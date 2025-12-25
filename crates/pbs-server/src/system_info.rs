use std::collections::HashSet;
#[cfg(unix)]
use std::ffi::{CStr, CString};
use std::path::Path;

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Default)]
struct CpuSample {
    total: u64,
    idle: u64,
    iowait: u64,
}

#[derive(Debug, Default)]
pub struct CpuTracker {
    last: Option<CpuSample>,
}

impl CpuTracker {
    pub fn sample(&mut self) -> (f64, f64) {
        let Some(current) = read_cpu_sample() else {
            return (0.0, 0.0);
        };

        let (usage, wait) = if let Some(previous) = self.last {
            let total_delta = current.total.saturating_sub(previous.total);
            let idle_delta =
                (current.idle + current.iowait).saturating_sub(previous.idle + previous.iowait);
            let wait_delta = current.iowait.saturating_sub(previous.iowait);

            if total_delta > 0 {
                let usage = (total_delta.saturating_sub(idle_delta)) as f64 / total_delta as f64;
                let wait = wait_delta as f64 / total_delta as f64;
                (usage, wait)
            } else {
                (0.0, 0.0)
            }
        } else {
            (0.0, 0.0)
        };

        self.last = Some(current);
        (usage, wait)
    }
}

#[derive(Debug, Default)]
pub struct KernelInfo {
    pub sysname: String,
    pub release: String,
    pub version: String,
    pub machine: String,
}

#[derive(Debug, Default)]
pub struct CpuInfo {
    pub model: String,
    pub sockets: usize,
    pub cpus: usize,
}

#[derive(Debug, Default)]
pub struct MemoryInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
}

#[derive(Debug, Default)]
pub struct SwapInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
}

#[derive(Debug, Default)]
pub struct StorageInfo {
    pub total: u64,
    pub used: u64,
    pub avail: u64,
}

#[derive(Debug, Default)]
pub struct BootInfo {
    pub mode: String,
    pub secure_boot: bool,
}

#[derive(Debug, Default)]
pub struct SystemSnapshot {
    pub memory: MemoryInfo,
    pub swap: SwapInfo,
    pub root: StorageInfo,
    pub uptime: u64,
    pub loadavg: [f64; 3],
    pub cpu_usage: f64,
    pub cpu_wait: f64,
    pub cpuinfo: CpuInfo,
    pub kernel: KernelInfo,
    pub boot: BootInfo,
    pub fingerprint: String,
}

pub fn collect_system_snapshot(
    data_dir: Option<&Path>,
    tls_fingerprint: Option<&str>,
    cpu_tracker: &mut CpuTracker,
) -> SystemSnapshot {
    let memory = read_memory_info().unwrap_or_default();
    let swap = read_swap_info().unwrap_or_default();
    let root = data_dir.and_then(read_storage_info).unwrap_or_default();
    let uptime = read_uptime().unwrap_or(0);
    let loadavg = read_loadavg().unwrap_or([0.0, 0.0, 0.0]);
    let (cpu_usage, cpu_wait) = cpu_tracker.sample();
    let cpuinfo = read_cpu_info().unwrap_or_default();
    let kernel = read_kernel_info().unwrap_or_default();
    let boot = read_boot_info().unwrap_or_default();

    SystemSnapshot {
        memory,
        swap,
        root,
        uptime,
        loadavg,
        cpu_usage,
        cpu_wait,
        cpuinfo,
        kernel,
        boot,
        fingerprint: tls_fingerprint.unwrap_or("").to_string(),
    }
}

pub fn cert_fingerprint_sha256(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    format_fingerprint(&digest)
}

fn format_fingerprint(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    let mut out = String::with_capacity(hex.len() + hex.len() / 2);
    for (idx, ch) in hex.chars().enumerate() {
        if idx > 0 && idx % 2 == 0 {
            out.push(':');
        }
        out.push(ch);
    }
    out
}

fn read_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn read_cpu_sample() -> Option<CpuSample> {
    let contents = read_file(Path::new("/proc/stat"))?;
    let mut lines = contents.lines();
    let line = lines.next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let mut values = Vec::new();
    for part in parts {
        if let Ok(value) = part.parse::<u64>() {
            values.push(value);
        }
    }
    if values.len() < 4 {
        return None;
    }
    let idle = values.get(3).copied().unwrap_or(0);
    let iowait = values.get(4).copied().unwrap_or(0);
    let total = values.iter().sum();
    Some(CpuSample {
        total,
        idle,
        iowait,
    })
}

fn read_memory_info() -> Option<MemoryInfo> {
    let meminfo = parse_meminfo()?;
    let total = meminfo.get("MemTotal").copied().unwrap_or(0) * 1024;
    let free = meminfo
        .get("MemAvailable")
        .or_else(|| meminfo.get("MemFree"))
        .copied()
        .unwrap_or(0)
        * 1024;
    let used = total.saturating_sub(free);
    Some(MemoryInfo { total, used, free })
}

fn read_swap_info() -> Option<SwapInfo> {
    let meminfo = parse_meminfo()?;
    let total = meminfo.get("SwapTotal").copied().unwrap_or(0) * 1024;
    let free = meminfo.get("SwapFree").copied().unwrap_or(0) * 1024;
    let used = total.saturating_sub(free);
    Some(SwapInfo { total, used, free })
}

fn parse_meminfo() -> Option<std::collections::HashMap<String, u64>> {
    let contents = read_file(Path::new("/proc/meminfo"))?;
    let mut map = std::collections::HashMap::new();
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next()?.trim_end_matches(':').to_string();
        let value = parts.next().and_then(|v| v.parse::<u64>().ok());
        if let Some(value) = value {
            map.insert(key, value);
        }
    }
    Some(map)
}

fn read_loadavg() -> Option<[f64; 3]> {
    let contents = read_file(Path::new("/proc/loadavg"))?;
    let mut parts = contents.split_whitespace();
    let a = parts.next()?.parse::<f64>().ok()?;
    let b = parts.next()?.parse::<f64>().ok()?;
    let c = parts.next()?.parse::<f64>().ok()?;
    Some([a, b, c])
}

fn read_uptime() -> Option<u64> {
    let contents = read_file(Path::new("/proc/uptime"))?;
    let mut parts = contents.split_whitespace();
    let uptime = parts.next()?.parse::<f64>().ok()?;
    Some(uptime as u64)
}

fn read_cpu_info() -> Option<CpuInfo> {
    let contents = read_file(Path::new("/proc/cpuinfo"))?;
    let mut model = String::new();
    let mut cpus = 0usize;
    let mut sockets = HashSet::new();

    for line in contents.lines() {
        let mut parts = line.splitn(2, ':');
        let key = parts.next()?.trim();
        let value = parts.next().unwrap_or("").trim();
        match key {
            "processor" => cpus += 1,
            "model name" => {
                if model.is_empty() {
                    model = value.to_string();
                }
            }
            "physical id" => {
                if !value.is_empty() {
                    sockets.insert(value.to_string());
                }
            }
            _ => {}
        }
    }

    let socket_count = if !sockets.is_empty() {
        sockets.len()
    } else if cpus > 0 {
        1
    } else {
        0
    };

    Some(CpuInfo {
        model,
        sockets: socket_count,
        cpus,
    })
}

fn read_kernel_info() -> Option<KernelInfo> {
    #[cfg(unix)]
    {
        let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
        let result = unsafe { libc::uname(&mut uts) };
        if result == 0 {
            let sysname = unsafe { CStr::from_ptr(uts.sysname.as_ptr()) }
                .to_string_lossy()
                .to_string();
            let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }
                .to_string_lossy()
                .to_string();
            let version = unsafe { CStr::from_ptr(uts.version.as_ptr()) }
                .to_string_lossy()
                .to_string();
            let machine = unsafe { CStr::from_ptr(uts.machine.as_ptr()) }
                .to_string_lossy()
                .to_string();
            return Some(KernelInfo {
                sysname,
                release,
                version,
                machine,
            });
        }
    }

    None
}

fn read_boot_info() -> Option<BootInfo> {
    let efi_path = Path::new("/sys/firmware/efi");
    if !efi_path.exists() {
        return Some(BootInfo {
            mode: "legacy-bios".to_string(),
            secure_boot: false,
        });
    }

    let secure_boot = read_secure_boot().unwrap_or(false);
    Some(BootInfo {
        mode: "efi".to_string(),
        secure_boot,
    })
}

fn read_secure_boot() -> Option<bool> {
    let vars_path = Path::new("/sys/firmware/efi/efivars");
    if !vars_path.exists() {
        return None;
    }

    let entries = std::fs::read_dir(vars_path).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("SecureBoot-") {
            continue;
        }
        let data = std::fs::read(entry.path()).ok()?;
        if data.len() < 5 {
            continue;
        }
        let enabled = data[4] == 1;
        return Some(enabled);
    }

    None
}

fn read_storage_info(path: &Path) -> Option<StorageInfo> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut vfs = unsafe { std::mem::zeroed::<libc::statvfs>() };
        let result = unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) };
        if result != 0 {
            return None;
        }
        let block_size = vfs.f_frsize as u64;
        let total = vfs.f_blocks as u64 * block_size;
        let free = vfs.f_bfree as u64 * block_size;
        let avail = vfs.f_bavail as u64 * block_size;
        let used = total.saturating_sub(free);
        return Some(StorageInfo { total, used, avail });
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}
