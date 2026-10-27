//! ADR-007/022: a failed isolation primitive is an error, never a host execution fallback.
//! Linux uses kernel namespaces, Landlock ABI >= 3 and seccomp, not an external runtime.
//! Limits are deliberately reported as per-process rlimits, not cgroup accounting.
use anyhow::{bail, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub rootfs: PathBuf,
    pub workspace: PathBuf,
    pub logs: PathBuf,
    pub command: Vec<String>,
    pub memory_bytes: u64,
    pub cpu_seconds: u64,
    pub max_processes: u64,
}

pub fn run(opts: &RuntimeOptions) -> Result<i32> {
    #[cfg(target_os = "linux")]
    {
        linux::run(opts)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = opts;
        bail!("NotImplemented: native execution on this OS requires the Phase 2 Linux VM backend")
    }
}

pub fn doctor() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        linux::doctor()
    }
    #[cfg(not(target_os = "linux"))]
    {
        serde_json::json!({"supported": false,"reason": "NotImplemented: Phase 2 VM backend", "os": std::env::consts::OS})
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use std::{
        ffi::CString,
        fs,
        io::Read,
        os::{
            fd::{FromRawFd, RawFd},
            unix::{ffi::OsStrExt, fs::FileTypeExt},
        },
        path::{Component, Path},
    };

    const MOUNT_ATTR_RDONLY: u64 = 1;
    const AT_RECURSIVE: u32 = 0x8000;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LL_EXECUTE: u64 = 1;
    const LL_READ: u64 = 1 << 2;
    const LL_READDIR: u64 = 1 << 3;
    const LL_ALL_V3: u64 = (1 << 15) - 1;

    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }
    // Kernel ABI is packed: the parent descriptor immediately follows the access mask.
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    fn cvt(ret: libc::c_int, what: &str) -> Result<()> {
        if ret < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| what.to_owned());
        }
        Ok(())
    }
    fn cpath(p: &Path) -> Result<CString> {
        Ok(CString::new(p.as_os_str().as_bytes())?)
    }
    fn mount(
        source: Option<&Path>,
        target: &Path,
        kind: Option<&str>,
        flags: libc::c_ulong,
        data: Option<&str>,
    ) -> Result<()> {
        let source = source.map(cpath).transpose()?;
        let target = cpath(target)?;
        let kind = kind.map(CString::new).transpose()?;
        let data = data.map(CString::new).transpose()?;
        unsafe {
            cvt(
                libc::mount(
                    source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                    target.as_ptr(),
                    kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                    flags,
                    data.as_ref()
                        .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
                ),
                "mount",
            )
        }
    }

    fn canonical_dir(p: &Path) -> Result<PathBuf> {
        let meta = fs::symlink_metadata(p)
            .with_context(|| format!("missing directory {}", p.display()))?;
        anyhow::ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "must be a real directory: {}",
            p.display()
        );
        Ok(fs::canonicalize(p)?)
    }
    fn validate(opts: &RuntimeOptions) -> Result<RuntimeOptions> {
        anyhow::ensure!(!opts.command.is_empty(), "command is empty");
        anyhow::ensure!(
            opts.memory_bytes >= 16 * 1024 * 1024 && opts.cpu_seconds > 0 && opts.max_processes > 0,
            "resource limits must be positive; memory >= 16 MiB"
        );
        for arg in &opts.command {
            CString::new(arg.as_bytes()).context("NUL in command")?;
        }
        let mut out = opts.clone();
        out.rootfs = canonical_dir(&opts.rootfs)?;
        out.workspace = canonical_dir(&opts.workspace)?;
        out.logs = canonical_dir(&opts.logs)?;
        for (a, b) in [
            (&out.rootfs, &out.workspace),
            (&out.rootfs, &out.logs),
            (&out.workspace, &out.logs),
        ] {
            anyhow::ensure!(
                !a.starts_with(b) && !b.starts_with(a),
                "rootfs, workspace and logs must be disjoint directories"
            );
        }
        for name in [
            "workspace",
            "logs",
            "tmp",
            "proc",
            "dev",
            "run",
            ".petri-oldroot",
        ] {
            canonical_dir(&out.rootfs.join(name))?;
        }
        // A pathname Unix socket crosses namespaces. Never expose preexisting host IPC.
        reject_special(&out.workspace)?;
        reject_special(&out.logs)?;
        reject_special(&out.rootfs)?;
        Ok(out)
    }
    fn reject_special(path: &Path) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let p = entry?.path();
            let meta = fs::symlink_metadata(&p)?;
            let ty = meta.file_type();
            anyhow::ensure!(
                !ty.is_socket() && !ty.is_fifo() && !ty.is_block_device() && !ty.is_char_device(),
                "host IPC/device cannot be exposed: {}",
                p.display()
            );
            if ty.is_dir() {
                reject_special(&p)?;
            }
        }
        Ok(())
    }

    /// Close inherited descriptors before PID namespace init can expose them
    /// through /proc/1/fd. Linux >= 6.2 is required, so close_range is mandatory.
    fn close_inherited(error_fd: RawFd) -> Result<()> {
        anyhow::ensure!(
            error_fd >= 3,
            "setup pipe must not occupy a standard descriptor"
        );
        if error_fd > 3 {
            anyhow::ensure!(
                unsafe { libc::syscall(libc::SYS_close_range, 3u32, (error_fd - 1) as u32, 0u32) }
                    == 0,
                "close inherited descriptors: {}",
                std::io::Error::last_os_error()
            );
        }
        anyhow::ensure!(
            unsafe { libc::syscall(libc::SYS_close_range, (error_fd + 1) as u32, u32::MAX, 0u32) }
                == 0,
            "close inherited descriptors: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }

    pub fn run(opts: &RuntimeOptions) -> Result<i32> {
        let opts = validate(opts)?;
        // A library caller must not fork this Rust setup code while another
        // thread may own allocator/runtime locks. The CLI uses a fresh reexec.
        anyhow::ensure!(fs::read_dir("/proc/self/task")?.count()==1,"SandboxUnavailable: runtime setup requires a single-threaded process; launch through the Petri CLI");
        let mut pipe = [0; 2];
        unsafe {
            cvt(
                libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC),
                "create isolation error pipe",
            )?;
        }
        // A caller may have closed stdio. Move the error endpoint out of 0..=2.
        if pipe[1] < 3 {
            let moved = unsafe { libc::fcntl(pipe[1], libc::F_DUPFD_CLOEXEC, 3) };
            if moved < 0 {
                unsafe {
                    libc::close(pipe[0]);
                    libc::close(pipe[1]);
                }
                bail!("duplicate setup pipe: {}", std::io::Error::last_os_error());
            }
            unsafe {
                libc::close(pipe[1]);
            }
            pipe[1] = moved;
        }
        // CLI calls this from a single-threaded process; no tokio/background threads.
        let supervisor_pid = unsafe { libc::getpid() };
        let child = unsafe { libc::fork() };
        if child < 0 {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            bail!("fork: {}", std::io::Error::last_os_error());
        }
        if child == 0 {
            unsafe {
                libc::close(pipe[0]);
            }
            if let Err(error) = close_inherited(pipe[1])
                .and_then(|_| namespace_worker(&opts, pipe[1], supervisor_pid))
            {
                let message = format!("SandboxUnavailable: {error:#}");
                let bytes = message.as_bytes();
                unsafe {
                    libc::write(pipe[1], bytes.as_ptr().cast(), bytes.len().min(3500));
                    libc::_exit(125);
                }
            }
            unsafe {
                libc::_exit(125);
            }
        }
        unsafe {
            libc::close(pipe[1]);
        }
        let mut error = String::new();
        let mut reader = unsafe { fs::File::from_raw_fd(pipe[0]) };
        reader.read_to_string(&mut error)?;
        let status = wait(child)?;
        if !error.is_empty() {
            bail!("{error}");
        }
        Ok(status)
    }
    fn wait(child: i32) -> Result<i32> {
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(child, &mut status, 0) };
            if result >= 0 {
                break;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                bail!("waitpid: {}", std::io::Error::last_os_error());
            }
        }
        Ok(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            125
        })
    }
    fn user_namespace() -> Result<()> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        anyhow::ensure!(
            uid != 0,
            "Petri refuses host-root execution; use an unprivileged user"
        );
        unsafe {
            cvt(
                libc::unshare(libc::CLONE_NEWUSER),
                "unshare user namespace (host must permit unprivileged user namespaces)",
            )?;
        }
        fs::write("/proc/self/setgroups", "deny")?;
        fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))?;
        fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))?;
        Ok(())
    }
    fn namespace_worker(
        opts: &RuntimeOptions,
        error_fd: RawFd,
        expected_parent: i32,
    ) -> Result<()> {
        unsafe {
            cvt(
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL),
                "parent death signal",
            )?;
        }
        anyhow::ensure!(
            unsafe { libc::getppid() } == expected_parent,
            "supervisor exited during startup"
        );
        user_namespace()?;
        unsafe {
            cvt(
                libc::unshare(
                    libc::CLONE_NEWNS
                        | libc::CLONE_NEWNET
                        | libc::CLONE_NEWPID
                        | libc::CLONE_NEWIPC
                        | libc::CLONE_NEWUTS
                        | libc::CLONE_NEWCGROUP,
                ),
                "unshare isolation namespaces",
            )?;
        }
        // PID 1 sees an out-of-namespace parent as PID 0, so getppid cannot
        // detect the registration race. An inherited pidfd pins parent identity.
        let parent_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) } as i32;
        cvt(parent_fd, "open namespace worker pidfd")?;
        let init = unsafe { libc::fork() };
        if init < 0 {
            unsafe {
                libc::close(parent_fd);
            }
            bail!("fork namespace init: {}", std::io::Error::last_os_error());
        }
        if init > 0 {
            unsafe {
                libc::close(parent_fd);
                libc::close(error_fd);
            }
            let status = wait(init)?;
            unsafe {
                libc::_exit(status);
            }
        }
        // This process is PID 1 only inside the new PID namespace.
        unsafe {
            cvt(
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL),
                "init parent death signal",
            )?;
        }
        let mut parent_status = libc::pollfd {
            fd: parent_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let alive = unsafe { libc::poll(&mut parent_status, 1, 0) };
        unsafe {
            libc::close(parent_fd);
        }
        anyhow::ensure!(alive == 0, "namespace worker exited during init startup");
        prepare_root(opts)?;
        // The payload shares this user namespace and UID with its privileged
        // reaper. Explicitly deny ptrace-style /proc/1/mem, fd and root access;
        // same-UID credentials must never become an alias to the init process.
        // A normal payload exec resets its own dumpability, not this parent's.
        unsafe {
            cvt(
                libc::prctl(libc::PR_SET_DUMPABLE, 0),
                "protect namespace init from payload inspection",
            )?;
        }
        let payload = unsafe { libc::fork() };
        if payload < 0 {
            bail!("fork payload: {}", std::io::Error::last_os_error());
        }
        if payload == 0 {
            if let Err(error) = execute(opts, error_fd) {
                let message = format!("SandboxUnavailable: {error:#}");
                unsafe {
                    libc::write(error_fd, message.as_ptr().cast(), message.len().min(3500));
                    libc::_exit(125);
                }
            }
            unsafe {
                libc::_exit(125);
            }
        }
        unsafe {
            libc::close(error_fd);
        }
        let status = wait(payload)?;
        // Namespace PID 1 owns cleanup: background processes cannot outlive a task.
        unsafe {
            libc::kill(-1, libc::SIGKILL);
        }
        loop {
            let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) };
            if result < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break;
            }
        }
        unsafe {
            libc::_exit(status);
        }
    }
    fn prepare_root(opts: &RuntimeOptions) -> Result<()> {
        mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )?;
        mount(
            Some(&opts.rootfs),
            &opts.rootfs,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )?;
        // Recursive read-only prevents writable nested mounts escaping rootfs policy.
        let root = cpath(&opts.rootfs)?;
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        let ret = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                root.as_ptr(),
                AT_RECURSIVE,
                &attr,
                std::mem::size_of::<MountAttr>(),
            )
        };
        anyhow::ensure!(
            ret == 0,
            "recursive read-only mount requires mount_setattr: {}",
            std::io::Error::last_os_error()
        );
        mount(
            Some(&opts.workspace),
            &opts.rootfs.join("workspace"),
            None,
            libc::MS_BIND,
            None,
        )?;
        mount(
            None,
            &opts.rootfs.join("workspace"),
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
        // ADR-012: blackbox is host-owned; an agent must not edit its audit trail.
        // /logs remains an empty read-only rootfs directory, not a host bind mount.
        let size = opts.memory_bytes.min(512 * 1024 * 1024);
        let tmp_opts = format!("size={size},mode=1777");
        mount(
            None,
            &opts.rootfs.join("tmp"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some(&tmp_opts),
        )?;
        mount(
            None,
            &opts.rootfs.join("run"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some("size=1m,mode=755"),
        )?;
        mount(
            None,
            &opts.rootfs.join("proc"),
            Some("proc"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY,
            Some("hidepid=2"),
        )?;
        let dev = opts.rootfs.join("dev");
        mount(
            None,
            &dev,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NOEXEC,
            Some("size=4m,mode=755"),
        )?;
        for name in ["null", "zero", "random", "urandom"] {
            fs::File::create(dev.join(name))?;
            mount(
                Some(&Path::new("/dev").join(name)),
                &dev.join(name),
                None,
                libc::MS_BIND,
                None,
            )?;
        }
        fs::create_dir(dev.join("shm"))?;
        mount(
            None,
            &dev.join("shm"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(&tmp_opts),
        )?;
        for (name, target) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ] {
            std::os::unix::fs::symlink(target, dev.join(name))?;
        }
        std::env::set_current_dir(&opts.rootfs)?;
        let dot = CString::new(".")?;
        let old = CString::new(".petri-oldroot")?;
        anyhow::ensure!(
            unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), old.as_ptr()) } == 0,
            "pivot_root: {}",
            std::io::Error::last_os_error()
        );
        std::env::set_current_dir("/")?;
        let old = CString::new("/.petri-oldroot")?;
        unsafe {
            cvt(
                libc::umount2(old.as_ptr(), libc::MNT_DETACH),
                "detach host root",
            )?;
        }
        Ok(())
    }
    fn limit(resource: libc::__rlimit_resource_t, value: u64) -> Result<()> {
        let lim = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        unsafe { cvt(libc::setrlimit(resource, &lim), "setrlimit") }
    }
    fn landlock() -> Result<()> {
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        anyhow::ensure!(
            abi >= 3,
            "Landlock ABI >= 3 required (Linux >= 6.2, enabled by host); detected {abi}"
        );
        let attr = RulesetAttr {
            handled_access_fs: LL_ALL_V3,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr,
                std::mem::size_of::<RulesetAttr>(),
                0,
            )
        } as i32;
        cvt(fd, "create Landlock ruleset")?;
        let result = (|| -> Result<()> {
            for (path, access) in [
                ("/", LL_EXECUTE | LL_READ | LL_READDIR),
                ("/workspace", LL_ALL_V3),
                ("/tmp", LL_ALL_V3),
                ("/dev", LL_ALL_V3 & !LL_EXECUTE),
            ] {
                let p = CString::new(path)?;
                let pathfd = unsafe { libc::open(p.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                cvt(pathfd, "open Landlock path")?;
                let beneath = PathBeneathAttr {
                    allowed_access: access,
                    parent_fd: pathfd,
                };
                let ret = unsafe { libc::syscall(libc::SYS_landlock_add_rule, fd, 1, &beneath, 0) };
                unsafe {
                    libc::close(pathfd);
                }
                anyhow::ensure!(
                    ret == 0,
                    "Landlock add rule: {}",
                    std::io::Error::last_os_error()
                );
            }
            anyhow::ensure!(
                unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd, 0) } == 0,
                "Landlock restrict: {}",
                std::io::Error::last_os_error()
            );
            Ok(())
        })();
        unsafe {
            libc::close(fd);
        }
        result
    }
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    fn drop_caps() -> Result<()> {
        // Lock out executable file capabilities and setuid capability restoration.
        unsafe {
            cvt(
                libc::prctl(libc::PR_SET_SECUREBITS, 1 | 2 | 4 | 8),
                "lock securebits",
            )?;
        }
        for cap in 0..64 {
            let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap) };
            if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
                bail!("drop capability {cap}: {}", std::io::Error::last_os_error());
            }
        }
        let header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        anyhow::ensure!(
            unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } == 0,
            "capset: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn execute(opts: &RuntimeOptions, error_fd: RawFd) -> Result<()> {
        limit(libc::RLIMIT_AS, opts.memory_bytes)?;
        limit(libc::RLIMIT_CPU, opts.cpu_seconds)?;
        limit(libc::RLIMIT_NPROC, opts.max_processes)?;
        limit(libc::RLIMIT_NOFILE, 256)?;
        limit(libc::RLIMIT_CORE, 0)?;
        unsafe {
            cvt(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
                "no_new_privileges",
            )?;
        }
        landlock()?;
        drop_caps()?;
        std::env::set_current_dir("/workspace")?;
        let env = [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/tmp",
            "LANG=C.UTF-8",
            "TERM=xterm-256color",
            "PETRI_SANDBOX=1",
        ];
        let env = env
            .into_iter()
            .map(CString::new)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut argv = opts
            .command
            .iter()
            .map(|s| CString::new(s.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let program = find_program(&opts.command[0])?;
        let mut argv_ptr = argv.iter_mut().map(|s| s.as_ptr()).collect::<Vec<_>>();
        argv_ptr.push(std::ptr::null());
        let mut env_ptr = env.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        env_ptr.push(std::ptr::null());
        // No inherited descriptors into host files/sockets survive exec. Keep only stdio
        // and the CLOEXEC setup error pipe; mount setup opens nothing persistent.
        close_inherited(error_fd)?;
        seccomp()?;
        unsafe {
            libc::execve(program.as_ptr(), argv_ptr.as_ptr(), env_ptr.as_ptr());
        }
        bail!(
            "exec {}: {}",
            opts.command[0],
            std::io::Error::last_os_error()
        )
    }
    fn find_program(command: &str) -> Result<CString> {
        if command.contains('/') {
            anyhow::ensure!(
                Path::new(command)
                    .components()
                    .all(|c| !matches!(c, Component::ParentDir)),
                "parent components forbidden in executable path"
            );
            return Ok(CString::new(command)?);
        }
        for dir in [
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ] {
            let path = Path::new(dir).join(command);
            let p = cpath(&path)?;
            if unsafe { libc::access(p.as_ptr(), libc::X_OK) } == 0 {
                return Ok(p);
            }
        }
        bail!("command not found inside stack: {command}")
    }
    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    fn seccomp_program() -> Result<Vec<libc::sock_filter>> {
        #[cfg(target_arch = "x86_64")]
        let arch = 0xc000003e;
        #[cfg(target_arch = "aarch64")]
        let arch = 0xc00000b7;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            bail!("seccomp architecture unsupported");
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
            let jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
            let ret = (libc::BPF_RET | libc::BPF_K) as u16;
            let mut code = vec![
                stmt(ld, 4),
                jump(jeq, arch, 1, 0),
                stmt(ret, libc::SECCOMP_RET_KILL_PROCESS),
                stmt(ld, 0),
            ];
            // clone3 stores flags behind a pointer: ENOSYS asks libc to fall back to
            // clone(), whose namespace flags can be inspected safely by classic BPF.
            code.extend([
                jump(jeq, libc::SYS_clone3 as u32, 0, 1),
                stmt(ret, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
            ]);
            code.extend([
                jump(jeq, libc::SYS_clone as u32, 0, 4),
                stmt(ld, 16),
                jump(
                    (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
                    0x7e020000,
                    0,
                    1,
                ),
                stmt(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
                stmt(ret, libc::SECCOMP_RET_ALLOW),
            ]);
            // Network namespaces do not isolate every socket family (notably
            // AF_VSOCK). Restrict domains as well as creating a disconnected netns.
            code.extend([
                jump(jeq, libc::SYS_socket as u32, 0, 6),
                stmt(ld, 16),
                jump(jeq, libc::AF_UNIX as u32, 3, 0),
                jump(jeq, libc::AF_INET as u32, 2, 0),
                jump(jeq, libc::AF_INET6 as u32, 1, 0),
                stmt(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
                stmt(ret, libc::SECCOMP_RET_ALLOW),
                jump(jeq, libc::SYS_socketpair as u32, 0, 4),
                stmt(ld, 16),
                jump(jeq, libc::AF_UNIX as u32, 1, 0),
                stmt(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
                stmt(ret, libc::SECCOMP_RET_ALLOW),
            ]);
            let mut allowed = vec![
                libc::SYS_read,
                libc::SYS_write,
                libc::SYS_readv,
                libc::SYS_writev,
                libc::SYS_pread64,
                libc::SYS_pwrite64,
                libc::SYS_close,
                libc::SYS_lseek,
                libc::SYS_fstat,
                libc::SYS_newfstatat,
                libc::SYS_statx,
                libc::SYS_fstatfs,
                libc::SYS_statfs,
                libc::SYS_mmap,
                libc::SYS_mprotect,
                libc::SYS_munmap,
                libc::SYS_mremap,
                libc::SYS_madvise,
                libc::SYS_brk,
                libc::SYS_msync,
                libc::SYS_rt_sigaction,
                libc::SYS_rt_sigprocmask,
                libc::SYS_rt_sigreturn,
                libc::SYS_sigaltstack,
                libc::SYS_rt_sigsuspend,
                libc::SYS_rt_sigtimedwait,
                libc::SYS_ioctl,
                libc::SYS_fcntl,
                libc::SYS_flock,
                libc::SYS_dup,
                libc::SYS_dup3,
                libc::SYS_pipe2,
                libc::SYS_openat,
                libc::SYS_getdents64,
                libc::SYS_readlinkat,
                libc::SYS_faccessat,
                libc::SYS_faccessat2,
                libc::SYS_mkdirat,
                libc::SYS_unlinkat,
                libc::SYS_renameat,
                libc::SYS_renameat2,
                libc::SYS_linkat,
                libc::SYS_symlinkat,
                libc::SYS_fchmod,
                libc::SYS_fchmodat,
                libc::SYS_fchown,
                libc::SYS_fchownat,
                libc::SYS_ftruncate,
                libc::SYS_truncate,
                libc::SYS_utimensat,
                libc::SYS_fsync,
                libc::SYS_fdatasync,
                libc::SYS_sync_file_range,
                libc::SYS_fallocate,
                libc::SYS_umask,
                libc::SYS_getcwd,
                libc::SYS_chdir,
                libc::SYS_fchdir,
                libc::SYS_execve,
                libc::SYS_wait4,
                libc::SYS_waitid,
                libc::SYS_exit,
                libc::SYS_exit_group,
                libc::SYS_getpid,
                libc::SYS_getppid,
                libc::SYS_gettid,
                libc::SYS_getuid,
                libc::SYS_geteuid,
                libc::SYS_getgid,
                libc::SYS_getegid,
                libc::SYS_getgroups,
                libc::SYS_set_tid_address,
                libc::SYS_set_robust_list,
                libc::SYS_get_robust_list,
                libc::SYS_futex,
                libc::SYS_rseq,
                libc::SYS_clock_gettime,
                libc::SYS_clock_getres,
                libc::SYS_clock_nanosleep,
                libc::SYS_nanosleep,
                libc::SYS_gettimeofday,
                libc::SYS_times,
                libc::SYS_getrandom,
                libc::SYS_uname,
                libc::SYS_sysinfo,
                libc::SYS_getrusage,
                libc::SYS_prlimit64,
                libc::SYS_getrlimit,
                libc::SYS_setrlimit,
                libc::SYS_sched_yield,
                libc::SYS_sched_getaffinity,
                libc::SYS_sched_setaffinity,
                libc::SYS_sched_getparam,
                libc::SYS_sched_getscheduler,
                libc::SYS_setpgid,
                libc::SYS_getpgid,
                libc::SYS_getsid,
                libc::SYS_setsid,
                libc::SYS_tgkill,
                libc::SYS_kill,
                libc::SYS_socket,
                libc::SYS_socketpair,
                libc::SYS_connect,
                libc::SYS_bind,
                libc::SYS_listen,
                libc::SYS_accept,
                libc::SYS_accept4,
                libc::SYS_sendto,
                libc::SYS_recvfrom,
                libc::SYS_sendmsg,
                libc::SYS_recvmsg,
                libc::SYS_sendmmsg,
                libc::SYS_recvmmsg,
                libc::SYS_shutdown,
                libc::SYS_getsockname,
                libc::SYS_getpeername,
                libc::SYS_setsockopt,
                libc::SYS_getsockopt,
                libc::SYS_epoll_create1,
                libc::SYS_epoll_ctl,
                libc::SYS_epoll_pwait,
                libc::SYS_ppoll,
                libc::SYS_pselect6,
                libc::SYS_eventfd2,
                libc::SYS_signalfd4,
                libc::SYS_timerfd_create,
                libc::SYS_timerfd_settime,
                libc::SYS_timerfd_gettime,
                libc::SYS_inotify_init1,
                libc::SYS_inotify_add_watch,
                libc::SYS_inotify_rm_watch,
                libc::SYS_copy_file_range,
                libc::SYS_sendfile,
                libc::SYS_getxattr,
                libc::SYS_lgetxattr,
                libc::SYS_fgetxattr,
                libc::SYS_listxattr,
                libc::SYS_llistxattr,
                libc::SYS_flistxattr,
                libc::SYS_setxattr,
                libc::SYS_lsetxattr,
                libc::SYS_fsetxattr,
                libc::SYS_removexattr,
                libc::SYS_lremovexattr,
                libc::SYS_fremovexattr,
            ];
            #[cfg(target_arch = "x86_64")]
            allowed.extend([
                libc::SYS_arch_prctl,
                libc::SYS_access,
                libc::SYS_open,
                libc::SYS_stat,
                libc::SYS_lstat,
                libc::SYS_readlink,
                libc::SYS_mkdir,
                libc::SYS_rmdir,
                libc::SYS_unlink,
                libc::SYS_rename,
                libc::SYS_link,
                libc::SYS_symlink,
                libc::SYS_chmod,
                libc::SYS_chown,
                libc::SYS_lchown,
                libc::SYS_pipe,
                libc::SYS_dup2,
                libc::SYS_poll,
                libc::SYS_select,
                libc::SYS_epoll_wait,
                libc::SYS_fork,
                libc::SYS_vfork,
                libc::SYS_time,
            ]);
            allowed.sort_unstable();
            allowed.dedup();
            for syscall in allowed {
                code.extend([
                    jump(jeq, syscall as u32, 0, 1),
                    stmt(ret, libc::SECCOMP_RET_ALLOW),
                ]);
            }
            code.push(stmt(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
            Ok(code)
        }
    }
    fn seccomp() -> Result<()> {
        let mut code = seccomp_program()?;
        let prog = libc::sock_fprog {
            len: code.len() as u16,
            filter: code.as_mut_ptr(),
        };
        unsafe {
            cvt(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog),
                "install seccomp allowlist",
            )
        }
    }
    /// Only raw syscalls run in the probe child. `doctor` is also called from
    /// the parallel Rust test harness, where allocating after fork can deadlock.
    fn namespace_probe() -> Result<()> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        anyhow::ensure!(
            uid != 0,
            "Petri refuses host-root execution; use an unprivileged user"
        );
        let uid_map = format!("0 {uid} 1\n");
        let gid_map = format!("0 {gid} 1\n");
        let mut pipe = [0; 2];
        unsafe {
            cvt(
                libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC),
                "probe pipe",
            )?;
        }
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                libc::close(pipe[0]);
                let mut error = 0i32;
                if libc::unshare(libc::CLONE_NEWUSER) < 0 {
                    error = *libc::__errno_location();
                }
                // Buffers and C paths are constructed before fork or literals.
                for (path, content) in [
                    (c"/proc/self/setgroups", b"deny".as_slice()),
                    (c"/proc/self/uid_map", uid_map.as_bytes()),
                    (c"/proc/self/gid_map", gid_map.as_bytes()),
                ] {
                    if error != 0 {
                        break;
                    }
                    let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                    if fd < 0 {
                        error = *libc::__errno_location();
                        break;
                    }
                    let written = libc::write(fd, content.as_ptr().cast(), content.len());
                    if written != content.len() as isize {
                        error = if written < 0 {
                            *libc::__errno_location()
                        } else {
                            libc::EIO
                        };
                    }
                    libc::close(fd);
                }
                if error == 0
                    && libc::unshare(
                        libc::CLONE_NEWNS
                            | libc::CLONE_NEWNET
                            | libc::CLONE_NEWPID
                            | libc::CLONE_NEWIPC
                            | libc::CLONE_NEWUTS
                            | libc::CLONE_NEWCGROUP,
                    ) < 0
                {
                    error = *libc::__errno_location();
                }
                libc::write(
                    pipe[1],
                    (&error as *const i32).cast(),
                    std::mem::size_of::<i32>(),
                );
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(pipe[1]);
        }
        if child < 0 {
            unsafe {
                libc::close(pipe[0]);
            }
            bail!("probe fork failed");
        }
        let mut bytes = [0u8; 4];
        let mut reader = unsafe { fs::File::from_raw_fd(pipe[0]) };
        let read = reader.read_exact(&mut bytes);
        let status = wait(child)?;
        read.context("namespace probe returned no result")?;
        anyhow::ensure!(status == 0, "namespace probe failed");
        let errno = i32::from_ne_bytes(bytes);
        anyhow::ensure!(
            errno == 0,
            "namespace probe: {}",
            std::io::Error::from_raw_os_error(errno)
        );
        Ok(())
    }

    pub fn doctor() -> serde_json::Value {
        let reason = namespace_probe()
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        let landlock_abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        let landlock_error = if landlock_abi < 0 {
            Some(std::io::Error::last_os_error().to_string())
        } else {
            None
        };
        let supported = reason.is_empty() && landlock_abi >= 3;
        serde_json::json!({"supported":supported,"os":"linux","namespace_probe":if reason.is_empty(){"available"}else{&reason},"landlock_abi":landlock_abi,"landlock_error":landlock_error,"required_landlock_abi":3,"network":"none only","resource_enforcement":"per-process RLIMIT_AS, RLIMIT_CPU, RLIMIT_NPROC; no cgroup aggregate guarantees","rootfs_probe":"performed at launch; doctor does not certify a stack","seccomp":"x86_64/aarch64 allowlist; installed at launch","mount_setattr_required":true})
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn rejects_empty_command_before_fork() {
            let opts = RuntimeOptions {
                rootfs: "/missing".into(),
                workspace: "/missing".into(),
                logs: "/missing".into(),
                command: vec![],
                memory_bytes: 32 * 1024 * 1024,
                cpu_seconds: 1,
                max_processes: 4,
            };
            assert!(run(&opts)
                .unwrap_err()
                .to_string()
                .contains("command is empty"));
        }
        #[test]
        fn rejects_host_ipc() {
            let t = tempfile::tempdir().unwrap();
            let fifo = cpath(&t.path().join("host.fifo")).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            assert!(reject_special(t.path())
                .unwrap_err()
                .to_string()
                .contains("host IPC"));
        }
        #[test]
        fn closes_inherited_descriptors_above_lowered_nofile_limit() {
            use std::os::fd::AsRawFd;
            let file = fs::File::open("/dev/null").unwrap();
            let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 300) };
            assert!(high >= 300);
            let mut pipe = [0; 2];
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                // Do not allocate/assert in a child of the parallel test runner.
                unsafe {
                    libc::close(pipe[0]);
                }
                let lim = libc::rlimit {
                    rlim_cur: 256,
                    rlim_max: 256,
                };
                let limited = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } == 0;
                let closed = close_inherited(pipe[1]).is_ok();
                let unavailable = unsafe { libc::fcntl(high, libc::F_GETFD) } < 0;
                let success = u8::from(limited && closed && unavailable);
                unsafe {
                    libc::write(pipe[1], (&success as *const u8).cast(), 1);
                    libc::_exit(0);
                }
            }
            unsafe {
                libc::close(pipe[1]);
                libc::close(high);
            }
            let mut read = unsafe { fs::File::from_raw_fd(pipe[0]) };
            let mut result = [0u8; 1];
            read.read_exact(&mut result).unwrap();
            assert_eq!(wait(child).unwrap(), 0);
            assert_eq!(
                result,
                [1],
                "high inherited descriptor must be closed even after RLIMIT_NOFILE decreases"
            );
        }
        #[test]
        fn rejects_symlink_mountpoints() {
            let t = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink("/", t.path().join("root")).unwrap();
            assert!(canonical_dir(&t.path().join("root")).is_err());
        }
        /// Evaluate the emitted classic BPF against synthetic seccomp_data;
        /// catches branch offsets and argument-domain bypasses without changing
        /// the test runner's irreversible seccomp state.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        fn filter_result(syscall: i64, arg0: u32, wrong_arch: bool) -> u32 {
            #[cfg(target_arch = "x86_64")]
            let arch = 0xc000003e;
            #[cfg(target_arch = "aarch64")]
            let arch = 0xc00000b7;
            let code = seccomp_program().unwrap();
            let mut accumulator = 0u32;
            let mut pc = 0usize;
            while pc < code.len() {
                let instruction = code[pc];
                if instruction.code == (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16 {
                    accumulator = match instruction.k {
                        0 => syscall as u32,
                        4 => {
                            if wrong_arch {
                                0
                            } else {
                                arch
                            }
                        }
                        16 => arg0,
                        _ => panic!("unknown load"),
                    };
                    pc += 1;
                } else if instruction.code == (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16 {
                    pc += 1 + if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    } as usize;
                } else if instruction.code == (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16
                {
                    pc += 1 + if accumulator & instruction.k != 0 {
                        instruction.jt
                    } else {
                        instruction.jf
                    } as usize;
                } else if instruction.code == (libc::BPF_RET | libc::BPF_K) as u16 {
                    return instruction.k;
                } else {
                    panic!("unknown BPF opcode");
                }
            }
            panic!("filter did not return")
        }
        #[test]
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        fn seccomp_blocks_namespace_and_non_namespaced_socket_bypasses() {
            let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
            assert_eq!(filter_result(libc::SYS_mount, 0, false), denied);
            assert_eq!(filter_result(libc::SYS_unshare, 0, false), denied);
            assert_eq!(filter_result(libc::SYS_bpf, 0, false), denied);
            assert_eq!(
                filter_result(libc::SYS_clone, libc::CLONE_NEWUSER as u32, false),
                denied
            );
            assert_eq!(
                filter_result(libc::SYS_clone, libc::SIGCHLD as u32, false),
                libc::SECCOMP_RET_ALLOW
            );
            assert_eq!(
                filter_result(libc::SYS_clone3, 0, false),
                libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
            );
            for domain in [libc::AF_VSOCK, libc::AF_PACKET, libc::AF_NETLINK] {
                assert_eq!(
                    filter_result(libc::SYS_socket, domain as u32, false),
                    denied
                );
                assert_eq!(
                    filter_result(libc::SYS_socketpair, domain as u32, false),
                    denied
                );
            }
            for domain in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6] {
                assert_eq!(
                    filter_result(libc::SYS_socket, domain as u32, false),
                    libc::SECCOMP_RET_ALLOW
                );
            }
            assert_eq!(
                filter_result(libc::SYS_socketpair, libc::AF_UNIX as u32, false),
                libc::SECCOMP_RET_ALLOW
            );
            assert_eq!(
                filter_result(libc::SYS_read, 0, false),
                libc::SECCOMP_RET_ALLOW
            );
            assert_eq!(
                filter_result(libc::SYS_read, 0, true),
                libc::SECCOMP_RET_KILL_PROCESS
            );
            assert_eq!(filter_result(0x40000000 | libc::SYS_read, 0, false), denied);
        }
        #[test]
        fn doctor_reports_limits_without_claiming_cgroups() {
            let report = doctor();
            assert!(report["resource_enforcement"]
                .as_str()
                .unwrap()
                .contains("per-process"));
        }
    }
}
