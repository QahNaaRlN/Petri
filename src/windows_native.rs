//! Own native Windows candidate: LPAC, capability ACLs and a mandatory Job.
//! No VM, WSL, external sandbox SDK, elevation or unrestricted fallback.
//! Compiling this module is not Windows qualification; see the opt-in native tests.
#[cfg(windows)]
use anyhow::Context;
use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLimits {
    pub memory_bytes: u64,
    pub max_processes: u32,
    pub cpu_time_ms: u64,
    pub wall_time_ms: u64,
    pub stop_timeout_ms: u64,
    pub output_bytes: u64,
}
impl Default for NativeLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 512 * 1024 * 1024,
            max_processes: 8,
            cpu_time_ms: 10_000,
            wall_time_ms: 30_000,
            stop_timeout_ms: 3_000,
            output_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRequest {
    pub lab_id: String,
    pub execution_id: String,
    pub executable: PathBuf,
    /// Arguments excluding argv[0]. The executable is always explicit.
    pub argv: Vec<String>,
    pub workspace: PathBuf,
    pub temp: PathBuf,
    pub profile: PathBuf,
    pub toolchain: PathBuf,
    pub control_dir: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub limits: NativeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Exited,
    UserStop,
    WallTime,
    CpuTime,
    MemoryLimit,
    ProcessLimit,
    OutputLimit,
    WorkspaceLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeEvent {
    LaunchReady {
        pid: u32,
        job_name: String,
        lpac: bool,
    },
    Resumed {
        pid: u32,
    },
    Output {
        stream: String,
        bytes: Vec<u8>,
    },
    TreeStopped {
        active_processes: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeReport {
    /// All DWORD bits are preserved, including exception/termination codes.
    pub exit_code: u32,
    pub pid: u32,
    pub stop_reason: StopReason,
    pub tree_stopped: bool,
    pub user_cpu_100ns: u64,
    pub peak_job_memory: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    /// OS-created private AppContainer profile; it is also disk-budget observed.
    pub managed_profile: PathBuf,
    /// Identity also scopes Windows' own per-AppContainer registry storage.
    pub app_container_sid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeProbe {
    pub supported: bool,
    pub reason: Option<String>,
    pub os_build: Option<u32>,
    pub architecture: String,
}

/// Standard Microsoft C-runtime quoting, used only for the registered CPython executable.
/// A Windows command line is not universally an argv array for arbitrary programs.
pub fn quote_argument(arg: &str) -> Result<String> {
    ensure!(!arg.contains('\0'), "InvalidInput: NUL in argument");
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in arg.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        if c == '\"' {
            out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
            out.push(c);
        } else {
            out.extend(std::iter::repeat_n('\\', slashes));
            out.push(c);
        }
        slashes = 0;
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('\"');
    Ok(out)
}

#[cfg(windows)]
fn validate_request(r: &NativeRequest) -> Result<()> {
    for id in [&r.lab_id, &r.execution_id] {
        ensure!(
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "InvalidInput: invalid lab/execution identity"
        );
    }
    ensure!(r.argv.len() <= 256, "InvalidInput: too many arguments");
    ensure!(
        r.limits.memory_bytes > 0
            && r.limits.memory_bytes <= usize::MAX as u64
            && r.limits.max_processes > 0
            && r.limits.max_processes <= 128,
        "UnsupportedPolicy: invalid memory/process budget"
    );
    ensure!(
        r.limits.cpu_time_ms > 0
            && r.limits.cpu_time_ms <= i64::MAX as u64 / 10_000
            && r.limits.wall_time_ms > 0
            && r.limits.wall_time_ms <= 3_600_000
            && r.limits.stop_timeout_ms > 0
            && r.limits.stop_timeout_ms <= 30_000
            && r.limits.output_bytes > 0
            && r.limits.output_bytes <= 64 * 1024 * 1024,
        "UnsupportedPolicy: invalid execution budget"
    );
    for p in [
        &r.executable,
        &r.workspace,
        &r.temp,
        &r.profile,
        &r.toolchain,
        &r.control_dir,
    ] {
        ensure!(p.is_absolute(), "InvalidInput: paths must be absolute");
        ensure!(
            !p.as_os_str().to_string_lossy().contains('\0'),
            "InvalidInput: NUL in path"
        );
        for c in p.components() {
            ensure!(
                !matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                ),
                "InvalidInput: non-canonical path component"
            );
        }
    }
    let exe = r
        .executable
        .canonicalize()
        .context("registered executable")?;
    let tool = r.toolchain.canonicalize().context("registered toolchain")?;
    ensure!(
        exe.starts_with(&tool) && exe != tool,
        "PolicyDenied: executable must be inside the registered copied toolchain"
    );
    ensure!(
        exe.is_file(),
        "InvalidInput: executable is not a regular file"
    );
    let dirs = [
        &r.workspace,
        &r.temp,
        &r.profile,
        &r.toolchain,
        &r.control_dir,
    ];
    for (i, a) in dirs.iter().enumerate() {
        for b in dirs.iter().skip(i + 1) {
            let ac = a.canonicalize()?;
            let bc = b.canonicalize()?;
            ensure!(
                !ac.starts_with(&bc) && !bc.starts_with(&ac),
                "PolicyDenied: runtime directories overlap"
            );
        }
    }
    let mut names = std::collections::BTreeSet::new();
    for (k, v) in &r.environment {
        ensure!(
            !k.is_empty() && !k.contains(['=', '\0']) && !v.contains('\0'),
            "InvalidInput: invalid environment entry"
        );
        ensure!(
            names.insert(k.to_ascii_uppercase()),
            "InvalidInput: duplicate case-insensitive environment name"
        );
    }
    for a in &r.argv {
        quote_argument(a)?;
    }
    Ok(())
}

pub fn probe() -> NativeProbe {
    #[cfg(windows)]
    {
        win::probe()
    }
    #[cfg(not(windows))]
    {
        NativeProbe {
            supported: false,
            reason: Some(
                "UnsupportedPlatform: native Windows requires a qualified Windows host".into(),
            ),
            os_build: None,
            architecture: std::env::consts::ARCH.into(),
        }
    }
}

pub fn run(
    r: &NativeRequest,
    cancel: &AtomicBool,
    observe: &mut dyn FnMut(NativeEvent) -> Result<()>,
) -> Result<NativeReport> {
    #[cfg(windows)]
    {
        validate_request(r)?;
        win::run(r, cancel, observe)
    }
    #[cfg(not(windows))]
    {
        let _ = (r, cancel, observe);
        bail!("UnsupportedPlatform: native Windows execution is unavailable; no fallback")
    }
}

/// Effective explicit environment, for the controller's pinned manifest.
pub fn effective_environment(r: &NativeRequest) -> Result<BTreeMap<String, String>> {
    #[cfg(windows)]
    {
        win::environment_map(r)
    }
    #[cfg(not(windows))]
    {
        let _ = r;
        bail!("UnsupportedPlatform: Windows environment is unavailable")
    }
}

/// Remove only this owned laboratory's OS-managed profile, after confirmed stop.
pub fn delete_lab_profile(lab_id: &str) -> Result<()> {
    #[cfg(windows)]
    {
        win::delete_lab_profile(lab_id)
    }
    #[cfg(not(windows))]
    {
        let _ = lab_id;
        bail!("UnsupportedPlatform: Windows AppContainer profile deletion unavailable")
    }
}

/// Owner-only store root. Call before writing any metadata into this directory.
pub fn secure_private_dir(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        win::secure_private_dir(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            !path.exists() || !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
            "PolicyDenied: private directory is a link"
        );
        std::fs::create_dir_all(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        bail!("UnsupportedPlatform: private directory security unavailable")
    }
}

/// Create a new controller-owned file with a non-inherited private descriptor.
/// Existing objects are never adopted or repaired by this operation.
pub fn create_private_file(path: &Path) -> Result<std::fs::File> {
    #[cfg(windows)]
    {
        win::create_private_file(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        bail!("UnsupportedPlatform: private file creation unavailable")
    }
}

/// Revoke workload grants from an entire stopped, Petri-owned retained tree.
/// Caller must first prove the laboratory process tree has stopped.
pub fn secure_private_tree(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        win::secure_private_tree(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut pending = vec![(path.to_path_buf(), 0usize)];
        let mut count = 0;
        while let Some((p, depth)) = pending.pop() {
            count += 1;
            ensure!(
                count <= 100_000 && depth <= 64,
                "private tree exceeds bound"
            );
            let meta = std::fs::symlink_metadata(&p)?;
            ensure!(
                !meta.file_type().is_symlink() && (meta.is_dir() || meta.nlink() == 1),
                "PolicyDenied: linked private object"
            );
            std::fs::set_permissions(
                &p,
                std::fs::Permissions::from_mode(if meta.is_dir() { 0o700 } else { 0o600 }),
            )?;
            if meta.is_dir() {
                for entry in std::fs::read_dir(p)? {
                    pending.push((entry?.path(), depth + 1));
                }
            }
        }
        Ok(())
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        bail!("UnsupportedPlatform: private tree security unavailable")
    }
}

#[cfg(windows)]
mod win;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoting_preserves_empty_space_quote_and_backslash() {
        assert_eq!(quote_argument("").unwrap(), "\"\"");
        assert_eq!(quote_argument("a b").unwrap(), "\"a b\"");
        assert_eq!(quote_argument("x\"y").unwrap(), "\"x\\\"y\"");
        assert_eq!(quote_argument("x\\").unwrap(), "\"x\\\\\"");
        assert!(quote_argument("bad\0arg").is_err());
    }
    #[test]
    fn budgets_are_explicit_aggregate_candidate_values() {
        let l = NativeLimits::default();
        assert_eq!(l.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(l.max_processes, 8);
        assert_eq!(l.cpu_time_ms, 10_000);
        assert_eq!(l.wall_time_ms, 30_000);
    }
    #[test]
    fn non_windows_does_not_advertise_execution() {
        #[cfg(not(windows))]
        assert!(!probe().supported);
    }
}
