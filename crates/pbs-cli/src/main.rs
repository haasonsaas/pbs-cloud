use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::{Client, Url};

#[derive(Parser)]
#[command(name = "pbs-cloud", version, about = "PBS Cloud CLI")]
struct Cli {
    /// API base URL (e.g. https://localhost:8007)
    #[arg(long, env = "PBS_API_URL", default_value = "https://localhost:8007")]
    url: String,
    /// API token (PBSAPIToken=...)
    #[arg(long, env = "PBS_API_TOKEN")]
    token: Option<String>,
    /// Allow invalid TLS certificates
    #[arg(long)]
    insecure: bool,
    /// Request timeout in seconds
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    /// Print raw response body
    #[arg(long)]
    raw: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Ping,
    Version,
    Status,
    DatastoreUsage,
    Nodes,
    NodeStatus,
    Permissions(PermissionsArgs),
    Datastores {
        #[command(subcommand)]
        command: DatastoreCommand,
    },
    Tasks {
        #[command(subcommand)]
        command: TasksCommand,
    },
    Verify {
        #[command(subcommand)]
        command: VerifyCommand,
    },
}

#[derive(Args)]
struct PermissionsArgs {
    /// ACL path to query
    #[arg(long, default_value = "/")]
    path: String,
    /// Auth ID to query (admin only for other users)
    #[arg(long)]
    auth_id: Option<String>,
}

#[derive(Subcommand)]
enum DatastoreCommand {
    List,
    Status(DatastoreStatusArgs),
    Snapshots(DatastoreSnapshotsArgs),
}

#[derive(Args)]
struct DatastoreStatusArgs {
    store: String,
}

#[derive(Args)]
struct DatastoreSnapshotsArgs {
    store: String,
    #[arg(long)]
    ns: Option<String>,
    #[arg(long, value_name = "TYPE")]
    backup_type: Option<String>,
    #[arg(long, value_name = "ID")]
    backup_id: Option<String>,
}

#[derive(Subcommand)]
enum TasksCommand {
    List(TaskListArgs),
    Status(TaskIdArgs),
    Log(TaskLogArgs),
}

#[derive(Args)]
struct TaskIdArgs {
    upid: String,
}

#[derive(Args)]
struct TaskLogArgs {
    upid: String,
    #[arg(long)]
    start: Option<usize>,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long)]
    download: bool,
    #[arg(long, alias = "test-status")]
    test_status: bool,
}

#[derive(Args)]
struct TaskListArgs {
    #[arg(long)]
    running: Option<bool>,
    #[arg(long)]
    errors: Option<bool>,
    #[arg(long)]
    start: Option<usize>,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long)]
    userfilter: Option<String>,
    #[arg(long)]
    store: Option<String>,
    #[arg(long)]
    since: Option<i64>,
    #[arg(long)]
    until: Option<i64>,
    #[arg(long)]
    typefilter: Option<String>,
    #[arg(long)]
    statusfilter: Option<Vec<String>>, // comma-separated or repeated
}

#[derive(Subcommand)]
enum VerifyCommand {
    List,
    Status(VerifyStatusArgs),
    History(VerifyHistoryArgs),
}

#[derive(Args)]
struct VerifyStatusArgs {
    id: String,
}

#[derive(Args)]
struct VerifyHistoryArgs {
    id: String,
    #[arg(long)]
    start: Option<usize>,
    #[arg(long)]
    limit: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = build_client(cli.insecure, cli.timeout)?;
    let base = cli.url.trim_end_matches('/');

    let token = cli.token.as_deref();

    match cli.command {
        Command::Ping => {
            get_and_print(
                &client,
                base,
                "/api2/json/ping",
                None,
                token,
                false,
                cli.raw,
            )
            .await?
        }
        Command::Version => {
            get_and_print(
                &client,
                base,
                "/api2/json/version",
                None,
                token,
                false,
                cli.raw,
            )
            .await?
        }
        Command::Status => {
            get_and_print(
                &client,
                base,
                "/api2/json/status",
                None,
                token,
                true,
                cli.raw,
            )
            .await?
        }
        Command::DatastoreUsage => {
            get_and_print(
                &client,
                base,
                "/api2/json/status/datastore-usage",
                None,
                token,
                true,
                cli.raw,
            )
            .await?
        }
        Command::Nodes => {
            get_and_print(
                &client,
                base,
                "/api2/json/nodes",
                None,
                token,
                true,
                cli.raw,
            )
            .await?
        }
        Command::NodeStatus => {
            get_and_print(
                &client,
                base,
                "/api2/json/nodes/localhost/status",
                None,
                token,
                true,
                cli.raw,
            )
            .await?
        }
        Command::Permissions(args) => {
            let mut params = Vec::new();
            params.push(("path", args.path));
            if let Some(auth_id) = args.auth_id {
                params.push(("auth-id", auth_id));
            }
            get_and_print(
                &client,
                base,
                "/api2/json/access/permissions",
                Some(params),
                token,
                true,
                cli.raw,
            )
            .await?
        }
        Command::Datastores { command } => match command {
            DatastoreCommand::List => {
                get_and_print(
                    &client,
                    base,
                    "/api2/json/admin/datastore",
                    None,
                    token,
                    true,
                    cli.raw,
                )
                .await?
            }
            DatastoreCommand::Status(args) => {
                let path = format!("/api2/json/admin/datastore/{}/status", args.store);
                get_and_print(&client, base, &path, None, token, true, cli.raw).await?
            }
            DatastoreCommand::Snapshots(args) => {
                let path = format!("/api2/json/admin/datastore/{}/snapshots", args.store);
                let mut params = Vec::new();
                if let Some(ns) = args.ns {
                    params.push(("ns", ns));
                }
                if let Some(bt) = args.backup_type {
                    params.push(("backup-type", bt));
                }
                if let Some(bi) = args.backup_id {
                    params.push(("backup-id", bi));
                }
                get_and_print(&client, base, &path, Some(params), token, true, cli.raw).await?
            }
        },
        Command::Tasks { command } => match command {
            TasksCommand::List(args) => {
                let mut params = Vec::new();
                if let Some(val) = args.running {
                    params.push(("running", val.to_string()));
                }
                if let Some(val) = args.errors {
                    params.push(("errors", val.to_string()));
                }
                if let Some(val) = args.start {
                    params.push(("start", val.to_string()));
                }
                if let Some(val) = args.limit {
                    params.push(("limit", val.to_string()));
                }
                if let Some(val) = args.userfilter {
                    params.push(("userfilter", val));
                }
                if let Some(val) = args.store {
                    params.push(("store", val));
                }
                if let Some(val) = args.since {
                    params.push(("since", val.to_string()));
                }
                if let Some(val) = args.until {
                    params.push(("until", val.to_string()));
                }
                if let Some(val) = args.typefilter {
                    params.push(("typefilter", val));
                }
                if let Some(values) = args.statusfilter {
                    let joined = values.join(",");
                    params.push(("statusfilter", joined));
                }

                get_and_print(
                    &client,
                    base,
                    "/api2/json/nodes/localhost/tasks",
                    Some(params),
                    token,
                    true,
                    cli.raw,
                )
                .await?
            }
            TasksCommand::Status(args) => {
                let path = format!("/api2/json/nodes/localhost/tasks/{}/status", args.upid);
                get_and_print(&client, base, &path, None, token, true, cli.raw).await?
            }
            TasksCommand::Log(args) => {
                let path = format!("/api2/json/nodes/localhost/tasks/{}/log", args.upid);
                let mut params = Vec::new();
                if let Some(val) = args.start {
                    params.push(("start", val.to_string()));
                }
                if let Some(val) = args.limit {
                    params.push(("limit", val.to_string()));
                }
                if args.download {
                    params.push(("download", "true".to_string()));
                }
                if args.test_status {
                    params.push(("test-status", "true".to_string()));
                }
                get_and_print(&client, base, &path, Some(params), token, true, cli.raw).await?
            }
        },
        Command::Verify { command } => match command {
            VerifyCommand::List => {
                get_and_print(
                    &client,
                    base,
                    "/api2/json/admin/verify",
                    None,
                    token,
                    true,
                    cli.raw,
                )
                .await?
            }
            VerifyCommand::Status(args) => {
                let path = format!("/api2/json/admin/verify/{}/status", args.id);
                get_and_print(&client, base, &path, None, token, true, cli.raw).await?
            }
            VerifyCommand::History(args) => {
                let path = format!("/api2/json/admin/verify/{}/history", args.id);
                let mut params = Vec::new();
                if let Some(val) = args.start {
                    params.push(("start", val.to_string()));
                }
                if let Some(val) = args.limit {
                    params.push(("limit", val.to_string()));
                }
                get_and_print(&client, base, &path, Some(params), token, true, cli.raw).await?
            }
        },
    }

    Ok(())
}

fn build_client(insecure: bool, timeout_secs: u64) -> Result<Client> {
    let timeout = Duration::from_secs(timeout_secs);
    let builder = Client::builder().timeout(timeout);
    if insecure {
        Ok(builder.danger_accept_invalid_certs(true).build()?)
    } else {
        Ok(builder.build()?)
    }
}

async fn get_and_print(
    client: &Client,
    base: &str,
    path: &str,
    params: Option<Vec<(&str, String)>>,
    token: Option<&str>,
    auth_required: bool,
    raw: bool,
) -> Result<()> {
    let mut url = Url::parse(&format!("{}{}", base, path))?;
    if let Some(params) = params {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, &value);
        }
    }

    let mut request = client.get(url);
    if auth_required {
        let token =
            token.ok_or_else(|| anyhow!("API token required (use --token or PBS_API_TOKEN)"))?;
        request = request.header("Authorization", format!("PBSAPIToken={}", token));
    }

    let response = request.send().await.context("request failed")?;
    let status = response.status();
    let body = response.text().await.context("failed to read body")?;
    if !status.is_success() {
        return Err(anyhow!("HTTP {}: {}", status, body));
    }

    if raw {
        println!("{}", body);
        return Ok(());
    }

    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        Err(_) => {
            println!("{}", body);
            Ok(())
        }
    }
}
