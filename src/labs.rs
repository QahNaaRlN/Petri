//! Host-owned lab lifecycle. ADR-012: no metadata or recorder files are writable by the sandbox.
use crate::{git, observer, policy::Config, stacks};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Store {
    pub home: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lab {
    pub id: String,
    pub task: String,
    pub source: PathBuf,
    pub base_commit: String,
    pub branch: String,
    pub stack: stacks::StackInfo,
    pub config: Config,
    pub status: String,
    pub created_at: u64,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub model: Option<String>,
    pub prompt_hash: String,
    pub stack_hash: String,
    pub recording: String,
}
impl Store {
    pub fn open(home: PathBuf) -> Result<Self> {
        for part in ["", "labs", "stacks", "locks"] {
            private_dir(&home.join(part))?;
        }
        Ok(Self { home })
    }
    pub fn lab_dir(&self, id: &str) -> Result<PathBuf> {
        validate_id(id, "lab-")?;
        Ok(self.home.join("labs").join(id))
    }
    pub fn lock(&self, id: &str) -> Result<File> {
        validate_id(id, "lab-")?;
        let file = private_file(&self.home.join("locks").join(id), false)?;
        file.try_lock_exclusive()
            .context("LabBusy: another operation or supervisor owns this laboratory")?;
        Ok(file)
    }
    pub fn load(&self, id: &str) -> Result<Lab> {
        let lab: Lab = serde_json::from_slice(
            &fs::read(self.lab_dir(id)?.join("meta.json")).context("laboratory not found")?,
        )?;
        if lab.id != id {
            bail!("invalid lab metadata identity")
        };
        Ok(lab)
    }
    pub fn save(&self, lab: &Lab) -> Result<()> {
        write_json(&self.lab_dir(&lab.id)?.join("meta.json"), lab)
    }
    pub fn list(&self) -> Result<Vec<Lab>> {
        let mut labs = Vec::new();
        for entry in fs::read_dir(self.home.join("labs"))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            // Corrupt metadata is an error, never silently reported as healthy.
            labs.push(self.load(&id)?);
        }
        labs.sort_by_key(|lab| lab.created_at);
        Ok(labs)
    }
    pub fn create(
        &self,
        source: &Path,
        task: String,
        stack_name: &str,
        config: Config,
    ) -> Result<Lab> {
        config.validate()?;
        let source = source.canonicalize()?;
        let stack = stacks::resolve(&self.home.join("stacks"), stack_name)?;
        let id = format!("lab-{}", Uuid::new_v4().simple());
        let dir = self.lab_dir(&id)?;
        private_dir(&dir)?;
        let result = (|| {
            private_dir(&dir.join("blackbox"))?;
            private_dir(&dir.join("checkpoints"))?;
            let branch = format!("petri/{id}");
            let base_commit = git::create_workspace(&source, &dir.join("workspace"), &branch)?;
            let lab = Lab {
                id,
                prompt_hash: blake3::hash(task.as_bytes()).to_hex().to_string(),
                task,
                source,
                base_commit,
                branch,
                stack_hash: stack.digest.clone(),
                stack,
                config,
                status: "Prepared".into(),
                created_at: now(),
                command: vec![],
                exit_code: None,
                model: None,
                recording: "pipe-output; no PTY or agent trajectory".into(),
            };
            self.save(&lab)?;
            observer::event(
                &dir.join("blackbox"),
                "lab_created",
                serde_json::json!({"lab_id":lab.id,"stack_hash":lab.stack_hash,"prompt_hash":lab.prompt_hash}),
            )?;
            Ok(lab)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(dir);
        }
        result
    }
    pub fn require_stopped(&self, lab: &Lab) -> Result<()> {
        if ["Running", "Starting"].contains(&lab.status.as_str()) {
            bail!("LabBusy: laboratory is running or needs recovery after supervisor failure; inspect supervisor.pid")
        }
        Ok(())
    }
    pub fn checkpoint(&self, id: &str, message: &str) -> Result<String> {
        let _guard = self.lock(id)?;
        let lab = self.load(id)?;
        self.require_stopped(&lab)?;
        let dir = self.lab_dir(id)?;
        let cp = format!("cp-{}", Uuid::new_v4().simple());
        let staging = dir.join("checkpoints").join(format!(".{cp}.tmp"));
        private_dir(&staging)?;
        let result = (|| {
            copy_tree(&dir.join("workspace"), &staging.join("workspace"))?;
            copy_tree(&dir.join("git"), &staging.join("git"))?;
            write_json(
                &staging.join("meta.json"),
                &serde_json::json!({"id":cp,"message":message,"created_at":now(),"lab":lab}),
            )?;
            fs::rename(&staging, dir.join("checkpoints").join(&cp))?;
            observer::event(
                &dir.join("blackbox"),
                "checkpoint_created",
                serde_json::json!({"checkpoint":cp}),
            )?;
            Ok(cp)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(staging);
        }
        result
    }
    pub fn restore(&self, id: &str, cp: &str) -> Result<()> {
        validate_id(cp, "cp-")?;
        let _guard = self.lock(id)?;
        let mut lab = self.load(id)?;
        self.require_stopped(&lab)?;
        let dir = self.lab_dir(id)?;
        let src = dir.join("checkpoints").join(cp);
        if !src.is_dir() {
            bail!("checkpoint not found")
        }
        let staging = dir.join("restore-staging");
        if staging.exists() {
            bail!("unfinished restore detected; recover restore-staging before retry")
        }
        private_dir(&staging)?;
        let prepared = (|| {
            copy_tree(&src.join("workspace"), &staging.join("workspace"))?;
            copy_tree(&src.join("git"), &staging.join("git"))?;
            Ok(())
        })();
        if let Err(e) = prepared {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
        // ADR-017: save old trees until both replacements succeed; recover on any rename error.
        fs::rename(dir.join("workspace"), dir.join("workspace.previous"))?;
        if let Err(e) = fs::rename(dir.join("git"), dir.join("git.previous")) {
            fs::rename(dir.join("workspace.previous"), dir.join("workspace"))?;
            return Err(e.into());
        }
        let swapped = (|| {
            fs::rename(staging.join("workspace"), dir.join("workspace"))?;
            fs::rename(staging.join("git"), dir.join("git"))?;
            Ok(())
        })();
        if let Err(e) = swapped {
            for part in ["workspace", "git"] {
                let target = dir.join(part);
                if target.exists() {
                    fs::remove_dir_all(&target)?
                }
                fs::rename(dir.join(format!("{part}.previous")), target)?
            }
            let _ = fs::remove_dir_all(staging);
            return Err(e);
        }
        fs::remove_dir_all(dir.join("workspace.previous"))?;
        fs::remove_dir_all(dir.join("git.previous"))?;
        fs::remove_dir_all(staging)?;
        lab.status = "Prepared".into();
        lab.exit_code = None;
        self.save(&lab)?;
        observer::event(
            &dir.join("blackbox"),
            "checkpoint_restored",
            serde_json::json!({"checkpoint":cp}),
        )
    }
    pub fn discard(&self, id: &str) -> Result<()> {
        let _guard = self.lock(id)?;
        let lab = self.load(id)?;
        self.require_stopped(&lab)?;
        fs::remove_dir_all(self.lab_dir(id)?)?;
        Ok(())
    }
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn validate_id(id: &str, prefix: &str) -> Result<()> {
    let rest = id
        .strip_prefix(prefix)
        .context("invalid identifier prefix")?;
    if rest.len() != 32 || !rest.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid identifier")
    };
    Ok(())
}
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("refusing symlink directory: {}", path.display())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub fn private_file(path: &Path, truncate: bool) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    Ok(opts.open(path)?)
}
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("{}.tmp", Uuid::new_v4().simple()));
    let mut file = private_file(&tmp, true)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}
/// Copy inert files without dereferencing links, preserving executable bits; never hardlink writable snapshots.
pub fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    copy_tree_inner(source, target, 0, &source.canonicalize()?)
}
fn copy_tree_inner(source: &Path, target: &Path, depth: usize, root: &Path) -> Result<()> {
    if depth > 128 {
        bail!("snapshot nesting limit exceeded")
    }
    private_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let src = entry.path();
        let dst = target.join(entry.file_name());
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_tree_inner(&src, &dst, depth + 1, root)?
        } else if ty.is_file() {
            fs::copy(&src, &dst)?;
        } else if ty.is_symlink() {
            let link = fs::read_link(&src)?;
            // Absolute links could expose host files when inspected outside the lab. Reject rather than follow.
            let mut remaining = depth;
            for component in link.components() {
                match component {
                    std::path::Component::Normal(_) => remaining += 1,
                    std::path::Component::CurDir => {}
                    std::path::Component::ParentDir => {
                        if remaining == 0 {
                            bail!("symlink escapes snapshot: {}", src.display())
                        }
                        remaining -= 1
                    }
                    _ => bail!("unsafe absolute symlink in snapshot: {}", src.display()),
                }
            }
            let resolved = src
                .canonicalize()
                .context("dangling or cyclic symlink in snapshot is unsupported")?;
            if !resolved.starts_with(root) {
                bail!("symlink chain escapes snapshot: {}", src.display())
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(link, dst)?;
            #[cfg(not(unix))]
            bail!("Unsupported: symlink snapshots on this platform");
        } else {
            bail!("unsupported special file in snapshot: {}", src.display())
        }
    }
    Ok(())
}
