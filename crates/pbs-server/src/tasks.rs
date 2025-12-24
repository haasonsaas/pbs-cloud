//! Lightweight task registry for PBS task APIs.

use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct TaskRegistry {
    node: String,
    tasks: Arc<RwLock<HashMap<String, TaskEntry>>>,
    order: Arc<RwLock<VecDeque<String>>>,
    max_tasks: usize,
    max_log_lines: usize,
}

pub struct TaskListFilter<'a> {
    pub running: Option<bool>,
    pub userfilter: Option<&'a str>,
    pub store: Option<&'a str>,
    pub errors: bool,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub typefilter: Option<&'a str>,
    pub statusfilter: Option<&'a [String]>,
}

pub struct TaskListRequest<'a> {
    pub start: usize,
    pub limit: usize,
    pub filter: TaskListFilter<'a>,
}

#[derive(Clone, Serialize, Deserialize)]
struct TaskEntry {
    upid: String,
    node: String,
    pid: i64,
    pstart: u64,
    starttime: i64,
    worker_type: String,
    worker_id: Option<String>,
    user: String,
    store: Option<String>,
    endtime: Option<i64>,
    status: Option<String>,
    exitstatus: Option<String>,
    log: Vec<String>,
    running: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TaskSnapshot {
    pub upid: String,
    pub node: String,
    pub pid: i64,
    pub pstart: u64,
    pub starttime: i64,
    pub worker_type: String,
    pub worker_id: Option<String>,
    pub user: String,
    pub store: Option<String>,
    pub endtime: Option<i64>,
    pub status: Option<String>,
    pub exitstatus: Option<String>,
    pub log: Vec<String>,
    pub running: bool,
}

impl From<TaskEntry> for TaskSnapshot {
    fn from(entry: TaskEntry) -> Self {
        Self {
            upid: entry.upid,
            node: entry.node,
            pid: entry.pid,
            pstart: entry.pstart,
            starttime: entry.starttime,
            worker_type: entry.worker_type,
            worker_id: entry.worker_id,
            user: entry.user,
            store: entry.store,
            endtime: entry.endtime,
            status: entry.status,
            exitstatus: entry.exitstatus,
            log: entry.log,
            running: entry.running,
        }
    }
}

impl From<TaskSnapshot> for TaskEntry {
    fn from(snapshot: TaskSnapshot) -> Self {
        Self {
            upid: snapshot.upid,
            node: snapshot.node,
            pid: snapshot.pid,
            pstart: snapshot.pstart,
            starttime: snapshot.starttime,
            worker_type: snapshot.worker_type,
            worker_id: snapshot.worker_id,
            user: snapshot.user,
            store: snapshot.store,
            endtime: snapshot.endtime,
            status: snapshot.status,
            exitstatus: snapshot.exitstatus,
            log: snapshot.log,
            running: snapshot.running,
        }
    }
}

impl TaskRegistry {
    pub fn new(node: impl Into<String>) -> Self {
        Self::with_limits(node, 1000, 1000)
    }

    pub fn with_limits(node: impl Into<String>, max_tasks: usize, max_log_lines: usize) -> Self {
        Self {
            node: node.into(),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            order: Arc::new(RwLock::new(VecDeque::new())),
            max_tasks: max_tasks.max(1),
            max_log_lines: max_log_lines.max(1),
        }
    }

    pub async fn create(
        &self,
        user: &str,
        worker_type: &str,
        worker_id: Option<&str>,
        store: Option<&str>,
    ) -> String {
        let now = Utc::now();
        let pid = std::process::id() as u64;
        let pstart = now.timestamp() as u64;
        let starttime = now.timestamp();
        let task_id: u64 = rand::thread_rng().gen();
        let upid = format!(
            "UPID:{}:{:08X}:{:08X}:{:08X}:{:08X}:{}:{}:{}:",
            self.node,
            pid,
            pstart,
            task_id,
            starttime as u64,
            worker_type,
            worker_id.unwrap_or(""),
            user
        );

        let entry = TaskEntry {
            upid: upid.clone(),
            node: self.node.clone(),
            pid: pid as i64,
            pstart,
            starttime,
            worker_type: worker_type.to_string(),
            worker_id: worker_id.map(|v| v.to_string()),
            user: user.to_string(),
            store: store.map(|v| v.to_string()),
            endtime: None,
            status: Some("running".to_string()),
            exitstatus: None,
            log: Vec::new(),
            running: true,
        };

        let mut tasks = self.tasks.write().await;
        let mut order = self.order.write().await;
        tasks.insert(upid.clone(), entry);
        order.push_back(upid.clone());

        while order.len() > self.max_tasks {
            if let Some(oldest) = order.pop_front() {
                if let Some(old) = tasks.get(&oldest) {
                    if old.running {
                        order.push_back(oldest);
                        break;
                    }
                }
                tasks.remove(&oldest);
            }
        }

        upid
    }

    pub async fn log(&self, upid: &str, message: &str) {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%:z");
        let line = format!("{}: {}", timestamp, message);
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(upid) {
            task.log.push(line);
            if task.log.len() > self.max_log_lines {
                let excess = task.log.len() - self.max_log_lines;
                task.log.drain(0..excess);
            }
        }
    }

    pub async fn finish(&self, upid: &str, exitstatus: &str) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(upid) {
            task.running = false;
            task.endtime = Some(Utc::now().timestamp());
            task.status = Some("stopped".to_string());
            task.exitstatus = Some(exitstatus.to_string());
        }
    }

    pub async fn abort(&self, upid: &str) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(upid) {
            task.running = false;
            task.endtime = Some(Utc::now().timestamp());
            task.status = Some("stopped".to_string());
            task.exitstatus = Some("ABORTED".to_string());
            task.log.push(format!(
                "{}: task aborted",
                Utc::now().format("%Y-%m-%dT%H:%M:%S%:z")
            ));
        }
    }

    pub async fn list(&self, req: TaskListRequest<'_>) -> (Vec<Value>, usize) {
        let tasks = self.tasks.read().await;
        let order = self.order.read().await;
        let mut entries = Vec::new();

        let TaskListRequest {
            start,
            limit,
            filter:
                TaskListFilter {
                    running,
                    userfilter,
                    store,
                    errors,
                    since,
                    until,
                    typefilter,
                    statusfilter,
                },
        } = req;

        for upid in order.iter() {
            let Some(task) = tasks.get(upid) else {
                continue;
            };
            if let Some(true) = running {
                if !task.running {
                    continue;
                }
            }
            if let Some(until) = until {
                if task.starttime > until {
                    continue;
                }
            }
            if let Some(since) = since {
                let endtime = task.endtime.unwrap_or(task.starttime);
                if endtime < since {
                    continue;
                }
            }
            if let Some(filter) = userfilter {
                if !task.user.starts_with(filter) && !filter.starts_with(&task.user) {
                    continue;
                }
            }
            if let Some(store_filter) = store {
                if task.store.as_deref() != Some(store_filter) {
                    continue;
                }
            }
            if let Some(typefilter) = typefilter {
                if !task.worker_type.contains(typefilter) {
                    continue;
                }
            }

            let task_state = if task.running {
                None
            } else {
                task.exitstatus.as_deref().map(|status| {
                    let status_upper = status.to_ascii_uppercase();
                    if status_upper.starts_with("OK") {
                        "ok"
                    } else if status_upper.starts_with("WARNINGS")
                        || status_upper.starts_with("WARNING")
                    {
                        "warning"
                    } else if status_upper.starts_with("ERROR")
                        || status_upper.starts_with("ABORTED")
                    {
                        "error"
                    } else {
                        "unknown"
                    }
                })
            };

            if errors {
                match task_state {
                    Some("warning") | Some("error") => {}
                    _ => continue,
                }
            }

            if let Some(filters) = statusfilter {
                let Some(state) = task_state else {
                    continue;
                };
                if !filters.iter().any(|entry| entry == state) {
                    continue;
                }
            }
            entries.push(task.clone());
        }

        let total = entries.len();
        let start_idx = start.min(entries.len());
        let end_idx = entries.len().min(start_idx.saturating_add(limit));

        let list = entries[start_idx..end_idx]
            .iter()
            .map(|task| {
                serde_json::json!({
                    "upid": task.upid,
                    "node": task.node,
                    "pid": task.pid,
                    "pstart": task.pstart,
                    "starttime": task.starttime,
                    "worker-type": task.worker_type,
                    "worker-id": task.worker_id,
                    "user": task.user,
                    "endtime": task.endtime,
                    "status": task.status,
                })
            })
            .collect();
        (list, total)
    }

    pub async fn log_entries(
        &self,
        upid: &str,
        start: usize,
        limit: usize,
    ) -> Option<(Vec<Value>, usize, bool)> {
        let tasks = self.tasks.read().await;
        let task = tasks.get(upid)?;
        let total = task.log.len();
        if total == 0 {
            return Some((Vec::new(), 0, task.running));
        }
        let start_idx = start.saturating_sub(1).min(total);
        let end_idx = total.min(start_idx.saturating_add(limit));
        let mut data = Vec::new();
        for (idx, line) in task.log[start_idx..end_idx].iter().enumerate() {
            data.push(serde_json::json!({
                "n": (start_idx + idx + 1) as u64,
                "t": line,
            }));
        }
        Some((data, total, task.running))
    }

    pub async fn status(&self, upid: &str) -> Option<(String, Option<String>)> {
        let tasks = self.tasks.read().await;
        let task = tasks.get(upid)?;
        let status = if task.running {
            "running".to_string()
        } else {
            "stopped".to_string()
        };
        Some((status, task.exitstatus.clone()))
    }

    pub async fn get(&self, upid: &str) -> Option<TaskSnapshot> {
        let tasks = self.tasks.read().await;
        tasks.get(upid).cloned().map(TaskSnapshot::from)
    }

    pub async fn running_count(&self) -> usize {
        let tasks = self.tasks.read().await;
        tasks.values().filter(|task| task.running).count()
    }

    pub async fn snapshot(&self) -> Vec<TaskSnapshot> {
        let tasks = self.tasks.read().await;
        let order = self.order.read().await;
        let mut snapshots = Vec::new();
        for upid in order.iter() {
            if let Some(task) = tasks.get(upid) {
                snapshots.push(TaskSnapshot::from(task.clone()));
            }
        }
        snapshots
    }

    pub async fn restore(&self, snapshots: Vec<TaskSnapshot>) {
        let mut tasks = self.tasks.write().await;
        let mut order = self.order.write().await;
        tasks.clear();
        order.clear();

        for mut snapshot in snapshots {
            if snapshot.log.len() > self.max_log_lines {
                let excess = snapshot.log.len() - self.max_log_lines;
                snapshot.log.drain(0..excess);
            }
            if snapshot.running {
                snapshot.running = false;
                snapshot.status = Some("stopped".to_string());
                snapshot.exitstatus = Some("ABORTED".to_string());
                snapshot.endtime = Some(Utc::now().timestamp());
                snapshot.log.push(format!(
                    "{}: task restored from persistence and marked stopped",
                    Utc::now().format("%Y-%m-%dT%H:%M:%S%:z")
                ));
            }
            order.push_back(snapshot.upid.clone());
            tasks.insert(snapshot.upid.clone(), TaskEntry::from(snapshot));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_task_log_capped() {
        let registry = TaskRegistry::new("node");
        let upid = registry
            .create("user@pam", "test", Some("worker"), Some("store"))
            .await;

        for idx in 0..1200usize {
            registry.log(&upid, &format!("line {}", idx)).await;
        }

        let snapshots = registry.snapshot().await;
        let task = snapshots
            .into_iter()
            .find(|task| task.upid == upid)
            .expect("task exists");
        assert_eq!(task.log.len(), 1000);
        assert!(task
            .log
            .first()
            .expect("log has entries")
            .ends_with("line 200"));
        assert!(task
            .log
            .last()
            .expect("log has entries")
            .ends_with("line 1199"));
    }
}
