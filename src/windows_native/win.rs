//! Windows-only OS bindings. Every failure before resume rejects execution.
use super::*;
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    os::windows::ffi::{OsStrExt, OsStringExt},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Isolation::*, *},
    Storage::FileSystem::*,
    System::{JobObjects::*, Pipes::*, Threading::*, IO::*},
};

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
fn check(ok: i32, what: &str) -> Result<()> {
    if ok == 0 {
        bail!("{what}: {}", std::io::Error::last_os_error())
    }
    Ok(())
}
fn hresult(hr: i32, what: &str) -> Result<()> {
    ensure!(hr >= 0, "{what}: HRESULT 0x{:08x}", hr as u32);
    Ok(())
}

struct Handle(HANDLE);
impl Handle {
    fn new(h: HANDLE, what: &str) -> Result<Self> {
        ensure!(
            !h.is_null() && h != INVALID_HANDLE_VALUE,
            "{what}: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(h))
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Sid(PSID);
impl Drop for Sid {
    fn drop(&mut self) {
        unsafe {
            FreeSid(self.0);
        }
    }
}

#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(memory: *const c_void);
}
fn managed_profile(sid: PSID) -> Result<PathBuf> {
    let text = sid_string(sid)?;
    unsafe {
        let mut value = null_mut();
        hresult(
            GetAppContainerFolderPath(wide(text).as_ptr(), &mut value),
            "GetAppContainerFolderPath",
        )?;
        ensure!(
            !value.is_null(),
            "IsolationUnavailable: empty managed AppContainer profile"
        );
        let mut length = 0;
        while *value.add(length) != 0 {
            length += 1;
        }
        let path = PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(
            value, length,
        )));
        CoTaskMemFree(value.cast());
        let _handles = check_parents(&path)?;
        ensure!(path.is_dir(), "managed AppContainer profile missing");
        Ok(path)
    }
}

fn profile_name(lab_id: &str) -> Result<String> {
    ensure!(!lab_id.is_empty()&&lab_id.len()<=58&&lab_id.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b"-_.".contains(&b)),"InvalidInput: Windows lab identity must be lowercase ASCII and fit the 64-character AppContainer name");
    Ok(format!("petri.{lab_id}"))
}

pub(super) fn delete_lab_profile(lab_id: &str) -> Result<()> {
    let name = profile_name(lab_id)?;
    let hr = unsafe { DeleteAppContainerProfile(wide(name).as_ptr()) };
    // An absent profile is an idempotent cleanup result, not a host path delete.
    if hr as u32 == 0x80070002 || hr as u32 == 0x80070490 {
        return Ok(());
    }
    hresult(hr, "DeleteAppContainerProfile")
}

fn sid_string(sid: PSID) -> Result<String> {
    unsafe {
        let mut p = null_mut();
        check(
            ConvertSidToStringSidW(sid, &mut p),
            "ConvertSidToStringSidW",
        )?;
        let _m = Local(p.cast());
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        Ok(
            std::ffi::OsString::from_wide(std::slice::from_raw_parts(p, n))
                .to_string_lossy()
                .into_owned(),
        )
    }
}
fn current_user() -> Result<String> {
    unsafe {
        let mut h = null_mut();
        check(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h),
            "OpenProcessToken",
        )?;
        let h = Handle::new(h, "token")?;
        let mut bytes = 0;
        GetTokenInformation(h.0, TokenUser, null_mut(), 0, &mut bytes);
        ensure!(bytes > 0, "TokenUser size unavailable");
        let mut b = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        check(
            GetTokenInformation(h.0, TokenUser, b.as_mut_ptr().cast(), bytes, &mut bytes),
            "GetTokenInformation(TokenUser)",
        )?;
        sid_string((*(b.as_ptr().cast::<TOKEN_USER>())).User.Sid)
    }
}

/// Refuse reparse points and hard-linked files before any ACL mutation/open.
fn object_handle(path: &Path) -> Result<Handle> {
    unsafe {
        let h = Handle::new(
            CreateFileW(
                wide(path).as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            ),
            "open no-follow object",
        )?;
        let mut info: BY_HANDLE_FILE_INFORMATION = zeroed();
        check(
            GetFileInformationByHandle(h.0, &mut info),
            "GetFileInformationByHandle",
        )?;
        ensure!(
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "PolicyDenied: reparse point {}",
            path.display()
        );
        ensure!(
            info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 || info.nNumberOfLinks == 1,
            "PolicyDenied: hardlinked file {}",
            path.display()
        );
        Ok(h)
    }
}
fn check_parents(path: &Path) -> Result<Vec<Handle>> {
    let mut parents = Vec::new();
    for p in path.ancestors() {
        if p.as_os_str().is_empty() {
            continue;
        }
        parents.push(object_handle(p)?);
    }
    Ok(parents)
}
fn assert_owner(path: &Path, user: &str) -> Result<()> {
    unsafe {
        let mut owner = null_mut();
        let mut sd = null_mut();
        let code = GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        ensure!(code == 0, "read owner {}: Win32 {code}", path.display());
        let _sd = Local(sd);
        ensure!(
            sid_string(owner)? == user,
            "PolicyDenied: refusing ACL change of foreign-owned object {}",
            path.display()
        );
        Ok(())
    }
}
fn descriptor(sddl: &str) -> Result<Local> {
    unsafe {
        let mut sd = null_mut();
        check(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            ),
            "security descriptor",
        )?;
        Ok(Local(sd))
    }
}
fn owner_dacl(path: &Path, user: &str) -> Result<()> {
    assert_owner(path, user)?;
    let sd = descriptor(&format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})"))?;
    unsafe {
        check(
            SetFileSecurityW(
                wide(path).as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd.0,
            ),
            "set private owner DACL",
        )
    }
}
pub(super) fn secure_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        let parent = path.parent().context("private directory parent")?;
        let _parents = check_parents(parent)?;
        std::fs::create_dir(path).or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })?;
    }
    let _handles = check_parents(path)?;
    ensure!(path.is_dir(), "private storage must be a directory");
    owner_dacl(path, &current_user()?)
}

pub(super) fn secure_private_tree(root: &Path) -> Result<()> {
    use std::rc::Rc;
    let _root_parents = check_parents(root)?;
    let user = current_user()?;
    let mut pending = vec![(root.to_path_buf(), Vec::<Rc<Handle>>::new())];
    let mut count = 0;
    while let Some((p, mut parents)) = pending.pop() {
        count += 1;
        ensure!(
            count <= 100_000 && parents.len() <= 64,
            "PolicyDenied: private retained tree exceeds bound"
        );
        let handle = Rc::new(object_handle(&p)?);
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        unsafe {
            check(
                GetFileInformationByHandle(handle.0, &mut info),
                "private tree object identity",
            )?;
        }
        owner_dacl(&p, &user)?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            parents.push(handle);
            for e in std::fs::read_dir(&p)? {
                ensure!(
                    count + pending.len() < 100_000,
                    "PolicyDenied: private tree enumeration bound exceeded"
                );
                pending.push((e?.path(), parents.clone()));
            }
        }
    }
    Ok(())
}

fn grant(path: &Path, appsid: PSID, write: bool, user: &str) -> Result<()> {
    unsafe {
        let _h = object_handle(path)?;
        assert_owner(path, user)?;
        let mut old_acl = null_mut();
        let mut old_sd = null_mut();
        let code = GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut old_acl,
            null_mut(),
            &mut old_sd,
        );
        ensure!(
            code == 0 && !old_acl.is_null(),
            "PolicyDenied: cannot read non-null ACL"
        );
        let _old = Local(old_sd);
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: if write {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE
            } else {
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
            },
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: appsid.cast(),
            },
        };
        let mut acl = null_mut();
        let code = SetEntriesInAclW(1, &access, old_acl, &mut acl);
        ensure!(code == 0, "grant capability ACL: Win32 {code}");
        let _acl = Local(acl.cast());
        let code = SetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        );
        ensure!(code == 0, "set capability ACL: Win32 {code}");
        if write {
            let low = descriptor("S:(ML;OICI;NW;;;LW)")?;
            check(
                SetFileSecurityW(wide(path).as_ptr(), LABEL_SECURITY_INFORMATION, low.0),
                "set low integrity writable label",
            )?;
        }
        Ok(())
    }
}
fn grant_tree(root: &Path, sid: PSID, write: bool, user: &str) -> Result<()> {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut count = 0;
    while let Some((p, depth)) = stack.pop() {
        count += 1;
        ensure!(
            count <= 100_000 && depth <= 64,
            "PolicyDenied: tool/workspace tree exceeds preparation bound"
        );
        let meta = std::fs::symlink_metadata(&p)?;
        ensure!(
            !meta.file_type().is_symlink(),
            "PolicyDenied: link in runtime tree"
        );
        if write {
            owner_dacl(&p, user)?;
        }
        grant(&p, sid, write, user)?;
        if meta.is_dir() {
            for e in std::fs::read_dir(&p)? {
                ensure!(
                    count + stack.len() < 100_000,
                    "PolicyDenied: ACL tree enumeration bound exceeded"
                );
                stack.push((e?.path(), depth + 1));
            }
        }
    }
    Ok(())
}

#[repr(C)]
struct OsVersion {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
    service_pack_major: u16,
    service_pack_minor: u16,
    suite_mask: u16,
    product_type: u8,
    reserved: u8,
}
#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(v: *mut OsVersion) -> i32;
}
fn host_check() -> Result<u32> {
    unsafe {
        ensure!(
            cfg!(target_arch = "x86_64"),
            "UnsupportedPlatform: first native profile requires x64"
        );
        let mut os: OsVersion = zeroed();
        os.size = size_of::<OsVersion>() as u32;
        ensure!(
            RtlGetVersion(&mut os) >= 0,
            "UnsupportedPlatform: OS version probe failed"
        );
        ensure!(
            os.major == 10 && os.build == 26100 && os.product_type==1,
            "UnsupportedPlatform: first candidate requires Windows 11 24H2 client x64 (build 26100); other releases are not qualified"
        );
        let mut h = null_mut();
        check(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h),
            "OpenProcessToken",
        )?;
        let h = Handle::new(h, "controller token")?;
        let mut elevated = 0u32;
        let mut n = 0;
        check(
            GetTokenInformation(
                h.0,
                TokenElevation,
                (&mut elevated as *mut u32).cast(),
                4,
                &mut n,
            ),
            "TokenElevation",
        )?;
        ensure!(
            elevated == 0,
            "PolicyDenied: run the native candidate as a standard non-elevated user"
        );
        let mut elevation_type = 0u32;
        check(
            GetTokenInformation(
                h.0,
                TokenElevationType,
                (&mut elevation_type as *mut u32).cast(),
                4,
                &mut n,
            ),
            "TokenElevationType",
        )?;
        ensure!(
            elevation_type == TokenElevationTypeDefault as u32,
            "PolicyDenied: filtered administrator accounts are outside the standard-user candidate"
        );
        let mut admin = vec![0usize; 16];
        let mut size = (admin.len() * size_of::<usize>()) as u32;
        check(
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                null_mut(),
                admin.as_mut_ptr().cast(),
                &mut size,
            ),
            "administrator SID probe",
        )?;
        let mut member = 0;
        check(
            CheckTokenMembership(null_mut(), admin.as_mut_ptr().cast(), &mut member),
            "administrator membership probe",
        )?;
        ensure!(
            member == 0,
            "PolicyDenied: administrator group is outside the standard-user candidate"
        );
        Ok(os.build)
    }
}
pub(super) fn probe() -> NativeProbe {
    match host_check(){Ok(build)=>NativeProbe{supported:true,reason:Some("Host version/account prerequisites only; effective LPAC and limits are verified before resume; native qualification remains separate".into()),os_build:Some(build),architecture:std::env::consts::ARCH.into()},Err(e)=>NativeProbe{supported:false,reason:Some(e.to_string()),os_build:None,architecture:std::env::consts::ARCH.into()}}
}

struct Attributes {
    buffer: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn new() -> Result<Self> {
        unsafe {
            let mut n = 0;
            InitializeProcThreadAttributeList(null_mut(), 4, 0, &mut n);
            ensure!(n > 0, "attribute list size probe failed");
            let mut b = vec![0usize; n.div_ceil(size_of::<usize>())];
            let p = b.as_mut_ptr().cast();
            check(
                InitializeProcThreadAttributeList(p, 4, 0, &mut n),
                "InitializeProcThreadAttributeList",
            )?;
            Ok(Self { buffer: b, list: p })
        }
    }
    fn add<T>(&mut self, kind: u32, value: &T) -> Result<()> {
        unsafe {
            check(
                UpdateProcThreadAttribute(
                    self.list,
                    0,
                    kind as usize,
                    (value as *const T).cast(),
                    size_of::<T>(),
                    null_mut(),
                    null(),
                ),
                "UpdateProcThreadAttribute",
            )
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
        let _ = &self.buffer;
    }
}
fn pipe() -> Result<(Handle, Handle)> {
    unsafe {
        let mut r = null_mut();
        let mut w = null_mut();
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        check(CreatePipe(&mut r, &mut w, &sa, 0), "CreatePipe")?;
        Ok((Handle::new(r, "pipe read")?, Handle::new(w, "pipe write")?))
    }
}
fn no_inherit(h: &Handle) -> Result<()> {
    unsafe {
        check(
            SetHandleInformation(h.0, HANDLE_FLAG_INHERIT, 0),
            "clear handle inheritance",
        )
    }
}
fn token_is_lpac(process: HANDLE, sid: PSID) -> Result<()> {
    unsafe {
        let mut t = null_mut();
        check(
            OpenProcessToken(process, TOKEN_QUERY, &mut t),
            "child token",
        )?;
        let t = Handle::new(t, "child token")?;
        for class in [TokenIsAppContainer, TokenIsLessPrivilegedAppContainer] {
            let mut yes = 0u32;
            let mut n = 0;
            check(
                GetTokenInformation(t.0, class, (&mut yes as *mut u32).cast(), 4, &mut n),
                "verify LPAC token",
            )?;
            ensure!(yes == 1, "IsolationUnavailable: child token is not LPAC");
        }
        let mut n = 0;
        GetTokenInformation(t.0, TokenAppContainerSid, null_mut(), 0, &mut n);
        ensure!(n > 0, "child AppContainer SID size probe failed");
        let mut b = vec![0usize; (n as usize).div_ceil(size_of::<usize>())];
        check(
            GetTokenInformation(t.0, TokenAppContainerSid, b.as_mut_ptr().cast(), n, &mut n),
            "verify child AppContainer SID",
        )?;
        let info = &*(b.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>());
        ensure!(
            EqualSid(info.TokenAppContainer, sid) != 0,
            "IsolationUnavailable: unexpected child AppContainer identity"
        );
        let mut n = 0;
        GetTokenInformation(t.0, TokenCapabilities, null_mut(), 0, &mut n);
        ensure!(n > 0, "child capabilities size probe failed");
        let mut b = vec![0usize; (n as usize).div_ceil(size_of::<usize>())];
        check(
            GetTokenInformation(t.0, TokenCapabilities, b.as_mut_ptr().cast(), n, &mut n),
            "verify zero network capabilities",
        )?;
        ensure!(
            (*(b.as_ptr().cast::<TOKEN_GROUPS>())).GroupCount == 0,
            "IsolationUnavailable: unexpected child capabilities"
        );
        Ok(())
    }
}

struct ProcessGuard {
    process: Handle,
    thread: Handle,
    job: Handle,
    stop_timeout: Duration,
}

struct WatchdogGuard<'scope> {
    done: Arc<AtomicBool>,
    worker: Option<std::thread::ScopedJoinHandle<'scope, ()>>,
}
impl Drop for WatchdogGuard<'_> {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl ProcessGuard {
    fn accounting(&self) -> Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION> {
        unsafe {
            let mut a = zeroed();
            check(
                QueryInformationJobObject(
                    self.job.0,
                    JobObjectBasicAccountingInformation,
                    (&mut a as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                ),
                "query job accounting",
            )?;
            Ok(a)
        }
    }
    fn stop(&self) -> Result<()> {
        unsafe {
            check(
                TerminateJobObject(self.job.0, 0xc000013a),
                "TerminateJobObject",
            )?;
        }
        let end = Instant::now() + self.stop_timeout;
        loop {
            if self.accounting()?.ActiveProcesses == 0 {
                return Ok(());
            }
            ensure!(
                Instant::now() < end,
                "StopUnconfirmed: job did not reach zero active processes"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = TerminateJobObject(self.job.0, 0xc000013a);
            let _ = TerminateProcess(self.process.0, 0xc000013a);
        }
        let _ = &self.thread;
    }
}

pub(super) fn environment_map(r: &NativeRequest) -> Result<BTreeMap<String, String>> {
    let system = std::env::var_os("SYSTEMROOT").context("SYSTEMROOT unavailable")?;
    let mut env = BTreeMap::new();
    env.insert(
        "SYSTEMROOT".to_string(),
        system.to_string_lossy().into_owned(),
    );
    env.insert("WINDIR".to_string(), system.to_string_lossy().into_owned());
    for (k, p) in [
        ("HOME", &r.profile),
        ("USERPROFILE", &r.profile),
        ("LOCALAPPDATA", &r.profile),
        ("APPDATA", &r.profile),
        ("TEMP", &r.temp),
        ("TMP", &r.temp),
        ("PATH", &r.toolchain),
    ] {
        env.insert(k.into(), p.to_string_lossy().into_owned());
    }
    for (k, v) in &r.environment {
        let key = k.to_ascii_uppercase();
        ensure!(
            ![
                "SYSTEMROOT",
                "WINDIR",
                "HOME",
                "USERPROFILE",
                "LOCALAPPDATA",
                "APPDATA",
                "TEMP",
                "TMP",
                "PATH"
            ]
            .contains(&key.as_str()),
            "PolicyDenied: environment cannot replace protected native profile paths"
        );
        ensure!(
            ![
                "PYTHONHOME",
                "PYTHONPATH",
                "PYTHONSTARTUP",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "SSH_AUTH_SOCK"
            ]
            .contains(&key.as_str()),
            "PolicyDenied: inherited tool/network configuration"
        );
        env.insert(key, v.clone());
    }
    Ok(env)
}
fn environment(r: &NativeRequest) -> Result<Vec<u16>> {
    let env = environment_map(r)?;
    let mut bytes = Vec::new();
    for (k, v) in env {
        bytes.extend(format!("{k}={v}").encode_utf16());
        bytes.push(0);
    }
    bytes.push(0);
    ensure!(
        bytes.len() < 32767,
        "InvalidInput: environment exceeds Windows bound"
    );
    Ok(bytes)
}

fn drain(
    pipe: &Handle,
    stream: &str,
    remaining: &mut u64,
    count: &mut u64,
    observe: &mut dyn FnMut(NativeEvent) -> Result<()>,
) -> Result<bool> {
    unsafe {
        for _ in 0..16 {
            let mut available = 0;
            if PeekNamedPipe(
                pipe.0,
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            ) == 0
            {
                let e = GetLastError();
                if e == ERROR_BROKEN_PIPE {
                    return Ok(false);
                }
                bail!("PeekNamedPipe: Win32 {e}");
            }
            if available == 0 {
                return Ok(false);
            }
            if *remaining == 0 {
                return Ok(true);
            }
            let len = (available as usize).min(8192).min(*remaining as usize);
            let mut b = vec![0; len];
            let mut n = 0;
            check(
                ReadFile(pipe.0, b.as_mut_ptr(), len as u32, &mut n, null_mut()),
                "read captured output",
            )?;
            b.truncate(n as usize);
            *remaining -= n as u64;
            *count += n as u64;
            observe(NativeEvent::Output {
                stream: stream.into(),
                bytes: b,
            })?;
        }
        Ok(false)
    }
}

fn workspace_size(r: &NativeRequest, managed_profile: &Path) -> Result<u64> {
    use std::rc::Rc;
    let deadline = Instant::now() + Duration::from_millis(50);
    // Each descent retains every ancestor HANDLE without FILE_SHARE_DELETE.
    // read_dir therefore cannot follow a concurrently swapped ancestor. The
    // final component is opened OPEN_REPARSE_POINT and inspected via that handle.
    let mut pending = vec![
        (r.workspace.clone(), Vec::<Rc<Handle>>::new()),
        (r.temp.clone(), Vec::new()),
        (r.profile.clone(), Vec::new()),
        (managed_profile.to_path_buf(), Vec::new()),
    ];
    let mut bytes = 0u64;
    let mut count = 0;
    while let Some((p, mut parents)) = pending.pop() {
        count += 1;
        ensure!(
            count <= 20_000 && parents.len() <= 64 && Instant::now() < deadline,
            "WorkspaceLimit: soft disk scan bound exceeded"
        );
        let mut handle = match object_handle(&p) {
            Ok(h) => Rc::new(h),
            Err(e) => {
                if !p.exists() {
                    continue;
                }
                return Err(e);
            }
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        unsafe {
            check(
                GetFileInformationByHandle(handle.0, &mut info),
                "disk observer object identity",
            )?;
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            // Deny WRITE as well as DELETE sharing during traversal: a writer
            // could otherwise turn an empty directory into a junction IN PLACE.
            let pinned = Handle::new(
                unsafe {
                    CreateFileW(
                        wide(&p).as_ptr(),
                        FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ,
                        null(),
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                        null_mut(),
                    )
                },
                "pin live disk scan directory",
            )?;
            unsafe {
                check(
                    GetFileInformationByHandle(pinned.0, &mut info),
                    "verify pinned scan directory",
                )?;
            }
            ensure!(
                info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
                    && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "PolicyDenied: directory changed during disk scan"
            );
            handle = Rc::new(pinned);
            parents.push(handle);
            for e in std::fs::read_dir(&p)? {
                ensure!(
                    count + pending.len() < 20_000 && Instant::now() < deadline,
                    "WorkspaceLimit: live directory enumeration bound exceeded"
                );
                pending.push((e?.path(), parents.clone()));
            }
        } else {
            bytes = bytes
                .saturating_add(((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64);
        }
    }
    Ok(bytes)
}

fn limit_notifications(port: &Handle) -> Result<Option<StopReason>> {
    let mut reason = None;
    for _ in 0..64 {
        let mut message = 0;
        let mut key = 0;
        let mut overlapped = null_mut();
        let ok = unsafe {
            GetQueuedCompletionStatus(port.0, &mut message, &mut key, &mut overlapped, 0)
        };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            ensure!(
                error == WAIT_TIMEOUT,
                "job completion notification: Win32 {error}"
            );
            break;
        }
        reason = match message {
            1 => Some(StopReason::CpuTime),
            3 => Some(StopReason::ProcessLimit),
            9 | 10 => Some(StopReason::MemoryLimit),
            _ => reason,
        };
    }
    Ok(reason)
}

pub(super) fn run(
    r: &NativeRequest,
    cancel: &AtomicBool,
    observe: &mut dyn FnMut(NativeEvent) -> Result<()>,
) -> Result<NativeReport> {
    host_check()?;
    ensure!(
        !cancel.load(Ordering::Acquire),
        "Cancelled: stop requested before setup"
    );
    let _roots = [
        &r.workspace,
        &r.temp,
        &r.profile,
        &r.toolchain,
        &r.control_dir,
    ]
    .into_iter()
    .map(|p| check_parents(p))
    .collect::<Result<Vec<_>>>()?;
    ensure!(
        r.toolchain.file_name().is_some_and(|n| n == "files")
            && r.toolchain
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|n| n.to_string_lossy().starts_with("native-tool-")),
        "PolicyDenied: toolchain must be a registered copied native-tool tree"
    );
    let mut free = 0;
    unsafe {
        check(
            GetDiskFreeSpaceExW(
                wide(&r.workspace).as_ptr(),
                &mut free,
                null_mut(),
                null_mut(),
            ),
            "disk reserve",
        )?;
    }
    ensure!(
        free >= 2 * 1024 * 1024 * 1024,
        "BudgetExceeded: native candidate requires 2 GiB disk reserve"
    );
    let user = current_user()?;
    let name = profile_name(&r.lab_id)?;
    let mut sid = null_mut();
    let hr = unsafe {
        CreateAppContainerProfile(
            wide(&name).as_ptr(),
            wide(&name).as_ptr(),
            wide("Petri native laboratory").as_ptr(),
            null(),
            0,
            &mut sid,
        )
    };
    if hr < 0 {
        ensure!(
            hr as u32 == 0x800700b7,
            "CreateAppContainerProfile: HRESULT 0x{:08x}",
            hr as u32
        );
        hresult(
            unsafe { DeriveAppContainerSidFromAppContainerName(wide(&name).as_ptr(), &mut sid) },
            "derive owned AppContainer",
        )?;
    }
    let sid = Sid(sid);
    ensure!(
        !sid.0.is_null(),
        "IsolationUnavailable: empty AppContainer SID"
    );
    let managed_profile = managed_profile(sid.0)?;
    for p in [&r.workspace, &r.temp, &r.profile] {
        grant_tree(p, sid.0, true, &user)?;
    }
    {
        // Windows ACL updates are read/merge/write, not an atomic additive
        // operation. Serialize updates of this shared immutable tool tree so
        // concurrent laboratories cannot revoke each other's read grants.
        let lock_path = r
            .toolchain
            .parent()
            .context("registered toolchain parent")?
            .join(".petri-acl.lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        let _lock_identity = object_handle(&lock_path)?;
        assert_owner(&lock_path, &user)?;
        fs2::FileExt::lock_exclusive(&lock).context("serialize toolchain capability ACL grants")?;
        grant_tree(&r.toolchain, sid.0, false, &user)?;
        fs2::FileExt::unlock(&lock)?;
    }
    owner_dacl(&r.control_dir, &user)?;
    let job_name = format!("Local\\Petri-{}", uuid::Uuid::new_v4().simple());
    let sd = descriptor(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{user})"))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let job = Handle::new(
        unsafe { CreateJobObjectW(&sa, wide(&job_name).as_ptr()) },
        "CreateJobObjectW",
    )?;
    ensure!(
        unsafe { GetLastError() } != ERROR_ALREADY_EXISTS,
        "PolicyDenied: job identity collision"
    );
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_JOB_TIME;
    limits.BasicLimitInformation.ActiveProcessLimit = r.limits.max_processes;
    limits.BasicLimitInformation.PerJobUserTimeLimit = (r.limits.cpu_time_ms * 10_000) as i64;
    limits.JobMemoryLimit = r.limits.memory_bytes as usize;
    unsafe {
        check(
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ),
            "install aggregate job budgets",
        )?;
        let mut installed: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        check(
            QueryInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&mut installed as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                null_mut(),
            ),
            "verify installed job budgets",
        )?;
        ensure!(
            installed.BasicLimitInformation.LimitFlags & limits.BasicLimitInformation.LimitFlags
                == limits.BasicLimitInformation.LimitFlags
                && installed.BasicLimitInformation.ActiveProcessLimit
                    == limits.BasicLimitInformation.ActiveProcessLimit
                && installed.BasicLimitInformation.PerJobUserTimeLimit
                    == limits.BasicLimitInformation.PerJobUserTimeLimit
                && installed.JobMemoryLimit == limits.JobMemoryLimit,
            "IsolationUnavailable: installed aggregate job budgets differ from request"
        );
    }
    let completion = Handle::new(
        unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1) },
        "job completion port",
    )?;
    let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: std::ptr::dangling_mut::<c_void>(),
        CompletionPort: completion.0,
    };
    unsafe {
        check(
            SetInformationJobObject(
                job.0,
                JobObjectAssociateCompletionPortInformation,
                (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            ),
            "associate job limit notifications",
        )?;
    }
    let (stdin_read, stdin_write) = pipe()?;
    let (stdout_read, stdout_write) = pipe()?;
    let (stderr_read, stderr_write) = pipe()?;
    no_inherit(&stdin_write)?;
    no_inherit(&stdout_read)?;
    no_inherit(&stderr_read)?;
    let caps = SECURITY_CAPABILITIES {
        AppContainerSid: sid.0,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let optout = 1u32;
    let inherited = [stdin_read.0, stdout_write.0, stderr_write.0];
    let mitigation = 0x10000000u64;
    let mut attributes = Attributes::new()?;
    attributes.add(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps)?;
    attributes.add(
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        &optout,
    )?;
    attributes.add(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;
    attributes.add(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation)?;
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin_read.0;
    startup.StartupInfo.hStdOutput = stdout_write.0;
    startup.StartupInfo.hStdError = stderr_write.0;
    startup.lpAttributeList = attributes.list;
    let program = wide(&r.executable);
    let cwd = wide(&r.workspace);
    let mut command = wide(
        std::iter::once(r.executable.to_string_lossy().into_owned())
            .chain(r.argv.iter().cloned())
            .map(|a| quote_argument(&a))
            .collect::<Result<Vec<_>>>()?
            .join(" "),
    );
    ensure!(
        command.len() <= 32767,
        "InvalidInput: Windows command line too long"
    );
    let env = environment(r)?;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    unsafe {
        check(
            CreateProcessW(
                program.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_NO_WINDOW,
                env.as_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut pi,
            ),
            "create suspended LPAC process",
        )?;
    }
    let child = ProcessGuard {
        process: Handle::new(pi.hProcess, "child process")?,
        thread: Handle::new(pi.hThread, "child thread")?,
        job,
        stop_timeout: Duration::from_millis(r.limits.stop_timeout_ms),
    };
    // Any failure from this point executes the same confirmed tree cleanup,
    // including callback failure and a child that was never assigned/resumed.
    std::thread::scope(|scope| {
        let finished = Arc::new(AtomicBool::new(false));
        let resumed_ns = Arc::new(AtomicU64::new(0));
        let watchdog_cause = Arc::new(AtomicU8::new(0));
        let origin = Instant::now();
        let watched_job = child.job.0 as usize;
        let watched_done = Arc::clone(&finished);
        let watched_resume = Arc::clone(&resumed_ns);
        let watched_cause = Arc::clone(&watchdog_cause);
        let wall_ns = r.limits.wall_time_ms * 1_000_000;
        let worker = std::thread::Builder::new()
            .name("petri-native-watchdog".into())
            .spawn_scoped(scope, move || {
                while !watched_done.load(Ordering::Acquire) {
                    let resumed = watched_resume.load(Ordering::Acquire);
                    let cause = if cancel.load(Ordering::Acquire) {
                        2
                    } else if resumed != 0
                        && (origin.elapsed().as_nanos() as u64).saturating_sub(resumed - 1)
                            >= wall_ns
                    {
                        1
                    } else {
                        0
                    };
                    if cause != 0 {
                        // ProcessGuard owns the sole job HANDLE in this guardian. This
                        // thread is joined before the owner can close/reuse it. No
                        // handle is duplicated or inherited by the workload.
                        let terminated =
                            unsafe { TerminateJobObject(watched_job as HANDLE, 0xc000013a) };
                        watched_cause
                            .store(if terminated != 0 { cause } else { 3 }, Ordering::Release);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
            .context("create independent native watchdog before resume")?;
        let _watchdog = WatchdogGuard {
            done: finished,
            worker: Some(worker),
        };
        let result = (|| -> Result<NativeReport> {
            token_is_lpac(child.process.0, sid.0)?;
            unsafe {
                check(
                    AssignProcessToJobObject(child.job.0, child.process.0),
                    "assign mandatory Job",
                )?;
                let mut yes = 0;
                check(
                    IsProcessInJob(child.process.0, child.job.0, &mut yes),
                    "verify job membership",
                )?;
                ensure!(
                    yes != 0,
                    "IsolationUnavailable: child escaped mandatory job"
                );
            }
            drop(stdin_write);
            drop(stdin_read);
            drop(stdout_write);
            drop(stderr_write);
            observe(NativeEvent::LaunchReady {
                pid: pi.dwProcessId,
                job_name,
                lpac: true,
            })?;
            ensure!(
                !cancel.load(Ordering::Acquire),
                "Cancelled: stop before resume"
            );
            ensure!(
                unsafe { ResumeThread(child.thread.0) } != u32::MAX,
                "ResumeThread: {}",
                std::io::Error::last_os_error()
            );
            let resumed_at = Instant::now();
            resumed_ns.store((origin.elapsed().as_nanos() as u64) + 1, Ordering::Release);
            observe(NativeEvent::Resumed {
                pid: pi.dwProcessId,
            })?;
            let start = resumed_at;
            let mut last_scan = start;
            let mut reason = StopReason::Exited;
            let mut remaining = r.limits.output_bytes;
            let mut stdout_bytes = 0;
            let mut stderr_bytes = 0;
            loop {
                match watchdog_cause.load(Ordering::Acquire) {
                    1 => {
                        reason = StopReason::WallTime;
                        break;
                    }
                    2 => {
                        reason = StopReason::UserStop;
                        break;
                    }
                    3 => bail!("StopUnconfirmed: independent watchdog failed to terminate Job"),
                    _ => {}
                }
                if let Some(limit) = limit_notifications(&completion)? {
                    reason = limit;
                }
                if reason != StopReason::Exited {
                    break;
                }
                if cancel.load(Ordering::Acquire) {
                    reason = StopReason::UserStop;
                    break;
                }
                if start.elapsed() >= Duration::from_millis(r.limits.wall_time_ms) {
                    reason = StopReason::WallTime;
                    break;
                }
                if drain(
                    &stdout_read,
                    "stdout",
                    &mut remaining,
                    &mut stdout_bytes,
                    observe,
                )? || drain(
                    &stderr_read,
                    "stderr",
                    &mut remaining,
                    &mut stderr_bytes,
                    observe,
                )? {
                    reason = StopReason::OutputLimit;
                    break;
                }
                if last_scan.elapsed() >= Duration::from_millis(100) {
                    if workspace_size(r, &managed_profile)? > 256 * 1024 * 1024 {
                        reason = StopReason::WorkspaceLimit;
                        break;
                    }
                    last_scan = Instant::now();
                }
                let wait = unsafe { WaitForSingleObject(child.process.0, 10) };
                ensure!(
                    wait == WAIT_TIMEOUT || wait == WAIT_OBJECT_0,
                    "wait workload failed"
                );
                if wait == WAIT_OBJECT_0 {
                    break;
                }
            }
            child.stop()?;
            // ActiveProcesses is now observed as zero. Keep the watchdog joined
            // until scope exit, but do not reclassify this stopped workload if a
            // final output/journal callback subsequently blocks past its deadline.
            _watchdog.done.store(true, Ordering::Release);
            if reason == StopReason::Exited {
                if let Some(limit) = limit_notifications(&completion)? {
                    reason = limit;
                }
            }
            let stdout_overflow = drain(
                &stdout_read,
                "stdout",
                &mut remaining,
                &mut stdout_bytes,
                observe,
            )?;
            let stderr_overflow = drain(
                &stderr_read,
                "stderr",
                &mut remaining,
                &mut stderr_bytes,
                observe,
            )?;
            if stdout_overflow || stderr_overflow {
                reason = StopReason::OutputLimit;
            }
            let a = child.accounting()?;
            ensure!(
                a.ActiveProcesses == 0,
                "StopUnconfirmed: remaining descendants"
            );
            observe(NativeEvent::TreeStopped {
                active_processes: 0,
            })?;
            let mut code = 0;
            let mut final_limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            unsafe {
                check(
                    GetExitCodeProcess(child.process.0, &mut code),
                    "read DWORD exit code",
                )?;
                check(
                    QueryInformationJobObject(
                        child.job.0,
                        JobObjectExtendedLimitInformation,
                        (&mut final_limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                        null_mut(),
                    ),
                    "query job memory",
                )?;
            }
            if reason == StopReason::Exited
                && a.TotalUserTime >= limits.BasicLimitInformation.PerJobUserTimeLimit
            {
                reason = StopReason::CpuTime;
            }
            match watchdog_cause.load(Ordering::Acquire) {
                1 => reason = StopReason::WallTime,
                2 => reason = StopReason::UserStop,
                3 => bail!("StopUnconfirmed: independent watchdog termination failure"),
                _ => {}
            }
            Ok(NativeReport {
                exit_code: code,
                pid: pi.dwProcessId,
                stop_reason: reason,
                tree_stopped: true,
                user_cpu_100ns: a.TotalUserTime.max(0) as u64,
                peak_job_memory: final_limits.PeakJobMemoryUsed as u64,
                stdout_bytes,
                stderr_bytes,
                managed_profile: managed_profile.clone(),
                app_container_sid: sid_string(sid.0)?,
            })
        })();
        match result {
            Ok(report) => Ok(report),
            Err(error) => {
                // Before assignment only TerminateProcess can terminate the suspended root.
                unsafe {
                    let _ = TerminateProcess(child.process.0, 0xc000013a);
                }
                let stop = child.stop();
                let root_wait = unsafe {
                    WaitForSingleObject(child.process.0, r.limits.stop_timeout_ms as u32)
                };
                if let Err(stop_error) = stop {
                    return Err(error.context(format!(
                        "StopUnconfirmed during error cleanup: {stop_error}"
                    )));
                }
                ensure!(
                    root_wait == WAIT_OBJECT_0,
                    "StopUnconfirmed: suspended root not reaped after setup failure: {error}"
                );
                _watchdog.done.store(true, Ordering::Release);
                let _ = observe(NativeEvent::TreeStopped {
                    active_processes: 0,
                });
                Err(error)
            }
        }
    })
}
