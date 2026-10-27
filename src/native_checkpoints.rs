//! Stopped-only native workspace/Git snapshots. No process or credential state.
//! An interrupted multi-directory restore leaves a durable veto marker; it is
//! never silently treated as an atomic, successful restore on restart.
use crate::execution::{self, Store};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    lab_id: String,
    checkpoint_id: String,
    base_commit: String,
    environment_digest: String,
    message: String,
    tree_digest: String,
}

fn plain_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "ArtifactInvalid: snapshot directory is an alias"
    );
    #[cfg(windows)]
    {
        let _guard = crate::git::pin_windows_directory(path)?;
    }
    Ok(())
}

fn bounded_names(directory: &Path, nodes: &mut u64) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut aliases = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        ensure!(
            *nodes < 100_000,
            "ArtifactInvalid: checkpoint node bound exceeded"
        );
        *nodes += 1;
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("ArtifactInvalid: non-Unicode snapshot name"))?;
        crate::git::validate_windows_relative_path(&name)?;
        ensure!(
            aliases.insert(name.to_ascii_lowercase()),
            "ArtifactInvalid: case-colliding checkpoint paths"
        );
        // Store bounded leaf names, not a full path/DirEntry for every object.
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    files: &mut u64,
    total: &mut u64,
    depth: usize,
) -> Result<()> {
    ensure!(
        depth <= 128,
        "ArtifactInvalid: snapshot nesting exceeds bound"
    );
    plain_directory(source)?;
    #[cfg(windows)]
    let _source_guard = crate::git::pin_windows_directory(source)?;
    execution::create_private_dir(destination)?;
    for name in bounded_names(source, files)? {
        let source_path = source.join(&name);
        let target = destination.join(&name);
        let kind = fs::symlink_metadata(&source_path)?;
        ensure!(
            !kind.file_type().is_symlink(),
            "ArtifactInvalid: snapshot links are unsupported"
        );
        if kind.is_dir() {
            copy_tree(&source_path, &target, files, total, depth + 1)?;
        } else {
            let mut input = crate::git::open_regular_no_links(&source_path)?;
            let length = input.metadata()?.len();
            *total = total
                .checked_add(length)
                .context("snapshot size overflow")?;
            ensure!(
                *files <= 100_000 && *total <= 512 * 1024 * 1024 && length <= 64 * 1024 * 1024,
                "ArtifactInvalid: native checkpoint exceeds file/size bounds"
            );
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            ensure!(
                std::io::copy(
                    &mut std::io::Read::by_ref(&mut input).take(length + 1),
                    &mut output
                )? == length,
                "ArtifactInvalid: snapshot file changed during collection"
            );
            #[cfg(unix)]
            {
                fs::set_permissions(&target, kind.permissions())?;
            }
            output.sync_all()?;
        }
    }
    sync_directory(destination)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    // Windows file contents are flushed. No cross-filesystem/power-loss atomic
    // transaction or directory-flush guarantee is claimed for these renames.
    Ok(())
}

fn tree_digest(root: &Path) -> Result<String> {
    fn walk(
        root: &Path,
        relative: &Path,
        digest: &mut Sha256,
        count: &mut u64,
        bytes: &mut u64,
    ) -> Result<()> {
        let directory = root.join(relative);
        plain_directory(&directory)?;
        #[cfg(windows)]
        let _guard = crate::git::pin_windows_directory(&directory)?;
        for name in bounded_names(&directory, count)? {
            let path = relative.join(name);
            ensure!(
                path.components().count() <= 128,
                "snapshot nesting exceeds bound"
            );
            let text = path.to_string_lossy().replace('\\', "/");
            let full_path = root.join(&path);
            let metadata = fs::symlink_metadata(&full_path)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "ArtifactInvalid: snapshot link denied"
            );
            digest.update((text.len() as u64).to_be_bytes());
            digest.update(text.as_bytes());
            if metadata.is_dir() {
                digest.update(b"directory\0");
                walk(root, &path, digest, count, bytes)?;
            } else {
                let mut input = crate::git::open_regular_no_links(&full_path)?;
                let length = input.metadata()?.len();
                *bytes = bytes
                    .checked_add(length)
                    .context("snapshot size overflow")?;
                ensure!(
                    *count <= 100_000 && *bytes <= 512 * 1024 * 1024 && length <= 64 * 1024 * 1024,
                    "ArtifactInvalid: snapshot size bound exceeded"
                );
                digest.update(b"file\0");
                digest.update(length.to_be_bytes());
                let mut hasher = Sha256::new();
                let actual = std::io::copy(
                    &mut std::io::Read::by_ref(&mut input).take(length + 1),
                    &mut hasher,
                )?;
                ensure!(actual == length, "ArtifactInvalid: checkpoint file changed");
                digest.update(hasher.finalize());
            }
        }
        Ok(())
    }
    let mut digest = Sha256::new();
    digest.update(b"petri.native-checkpoint/v1\0");
    walk(root, Path::new(""), &mut digest, &mut 0, &mut 0)?;
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

/// Digest the exact bounded native file tree without following aliases. The
/// caller must hold the stopped-lab lock or own pre-resume guardian execution.
pub fn snapshot_digest(root: &Path) -> Result<String> {
    tree_digest(root)
}

fn audit(directory: &Path, lab: &str, kind: &str, checkpoint: &str) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let path = directory.join("checkpoint-events.jsonl");
    if path.exists() {
        let _ = crate::git::open_regular_no_links(&path)?;
    }
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ);
    }
    let mut file = options.open(path)?;
    let length = file.metadata()?.len();
    let line = serde_json::to_vec(
        &serde_json::json!({"format":"petri.checkpoint-event/v1", "lab_id":lab,
        "kind":kind,"checkpoint_id":checkpoint,"offset":length,
        "timestamp_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().to_string()}),
    )?;
    ensure!(
        length + (line.len() as u64) < 16 * 1024 * 1024,
        "JournalFailure: checkpoint event journal is full"
    );
    file.write_all(&line)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .context("JournalFailure: durable checkpoint event")?;
    Ok(())
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    Ok(())
}

pub fn create(store: &Store, lab: &str, message: &str) -> Result<String> {
    ensure!(
        message.len() <= 4096,
        "InvalidInput: checkpoint message exceeds bound"
    );
    store.with_stopped_lab(lab, |directory, record| {
        let id = format!("checkpoint-{}", uuid::Uuid::new_v4().simple());
        audit(directory, lab, "checkpoint_intent", &id)?;
        let parent = directory.join("checkpoints");
        plain_directory(&parent)?;
        let staging = parent.join(format!(".staging-{id}"));
        execution::create_private_dir(&staging)?;
        let contents = staging.join("contents");
        execution::create_private_dir(&contents)?;
        let (mut files, mut total) = (0, 0);
        for part in ["workspace", "git"] {
            copy_tree(
                &directory.join(part),
                &contents.join(part),
                &mut files,
                &mut total,
                0,
            )?;
        }
        let manifest = Manifest {
            format: "petri.native-checkpoint/v1".into(),
            lab_id: lab.into(),
            checkpoint_id: id.clone(),
            base_commit: record.base_commit.clone(),
            environment_digest: record.environment.digest.clone(),
            message: message.into(),
            tree_digest: tree_digest(&contents)?,
        };
        write_new_json(&staging.join("manifest.json"), &manifest)?;
        fs::rename(&staging, parent.join(&id))?;
        sync_directory(&parent)?;
        audit(directory, lab, "checkpoint_created", &id)?;
        Ok(id)
    })
}

pub fn restore(store: &Store, lab: &str, checkpoint: &str) -> Result<()> {
    execution::validate_id(checkpoint, "checkpoint-")?;
    store.with_stopped_lab(lab, |directory, record| {
        let snapshot = directory.join("checkpoints").join(checkpoint);
        // Validate the old writable tree before touching it or its ACLs. The
        // stopped workload may have left hostile aliases in its output.
        tree_digest(&directory.join("workspace"))?;
        tree_digest(&directory.join("git"))?;
        plain_directory(&snapshot)?;
        let mut manifest_bytes = Vec::new();
        crate::git::open_regular_no_links(&snapshot.join("manifest.json"))?
            .take(64 * 1024 + 1)
            .read_to_end(&mut manifest_bytes)?;
        ensure!(
            manifest_bytes.len() <= 64 * 1024,
            "ArtifactInvalid: checkpoint manifest too large"
        );
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
        ensure!(
            manifest.format == "petri.native-checkpoint/v1"
                && manifest.lab_id == lab
                && manifest.checkpoint_id == checkpoint
                && manifest.base_commit == record.base_commit
                && manifest.environment_digest == record.environment.digest,
            "ArtifactInvalid: checkpoint identity or environment mismatch"
        );
        ensure!(
            tree_digest(&snapshot.join("contents"))? == manifest.tree_digest,
            "ArtifactInvalid: checkpoint digest mismatch"
        );
        let operation = uuid::Uuid::new_v4().simple().to_string();
        audit(directory, lab, "restore_requested", checkpoint)?;
        let staging = directory.join(format!(".restore-{operation}"));
        execution::create_private_dir(&staging)?;
        let (mut files, mut total) = (0, 0);
        for part in ["workspace", "git"] {
            copy_tree(
                &snapshot.join("contents").join(part),
                &staging.join(part),
                &mut files,
                &mut total,
                0,
            )?;
        }
        ensure!(
            tree_digest(&staging)? == manifest.tree_digest,
            "ArtifactInvalid: staged restore digest mismatch"
        );
        let previous = directory.join(format!(".previous-{operation}"));
        execution::create_private_dir(&previous)?;
        let marker = directory.join("restore-intent.json");
        write_new_json(
            &marker,
            &serde_json::json!({"format":"petri.native-restore/v1", "checkpoint":checkpoint,
            "staging":staging.file_name(), "previous":previous.file_name()}),
        )?;
        sync_directory(directory)?;
        let mut moved = Vec::<PathBuf>::new();
        let switch = (|| -> Result<()> {
            for part in ["workspace", "git"] {
                plain_directory(&directory.join(part))?;
                fs::rename(directory.join(part), previous.join(part))?;
                moved.push(PathBuf::from(part));
                fs::rename(staging.join(part), directory.join(part))?;
            }
            Ok(())
        })();
        if let Err(error) = switch {
            // Preserve all new/old data. Only remove the veto if ordinary-error
            // rollback succeeds completely; crashes require explicit inspection.
            for part in moved.iter().rev() {
                if directory.join(part).exists() {
                    fs::rename(directory.join(part), staging.join(part))
                        .context("RecoveryRequired: rollback of replacement failed")?;
                }
                fs::rename(previous.join(part), directory.join(part))
                    .context("RecoveryRequired: rollback of previous tree failed")?;
            }
            fs::remove_file(&marker)?;
            return Err(error);
        }
        sync_directory(directory)?;
        #[cfg(windows)]
        crate::windows_native::secure_private_tree(&previous)?;
        audit(directory, lab, "restore_completed", checkpoint)?;
        fs::remove_file(&marker)?;
        sync_directory(directory)?;
        // Previous trees are deliberately retained. Restore never rewinds
        // execution history, mandatory journals, environment or current policy.
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::EnvironmentRef;

    #[test]
    fn enumeration_bounds_empty_directories_and_refuses_case_aliases() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("first")).unwrap();
        fs::create_dir(temporary.path().join("second")).unwrap();
        assert!(bounded_names(temporary.path(), &mut 99_999)
            .unwrap_err()
            .to_string()
            .contains("node bound"));
        #[cfg(unix)]
        {
            fs::create_dir(temporary.path().join("FIRST")).unwrap();
            assert!(snapshot_digest(temporary.path())
                .unwrap_err()
                .to_string()
                .contains("case-colliding"));
        }
    }
    #[test]
    fn restores_files_and_git_without_rewinding_execution_history() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        let repository = git2::Repository::init(&source).unwrap();
        fs::write(source.join("fixture.py"), "print('before')\n").unwrap();
        let mut index = repository.index().unwrap();
        index.add_path(Path::new("fixture.py")).unwrap();
        let tree = repository.find_tree(index.write_tree().unwrap()).unwrap();
        let signature = git2::Signature::now("Petri fixture", "fixture@localhost").unwrap();
        repository
            .commit(Some("HEAD"), &signature, &signature, "baseline", &tree, &[])
            .unwrap();
        let store = Store::open(temporary.path().join("state")).unwrap();
        let lab = store
            .prepare(
                &source,
                "snapshot fixture",
                EnvironmentRef {
                    kind: "windows-native".into(),
                    id: "fixture".into(),
                    digest: format!("sha256:{}", "a".repeat(64)),
                },
            )
            .unwrap();
        let id = create(&store, &lab.lab_id, "before mutation").unwrap();
        let audit_path = store
            .lab_dir(&lab.lab_id)
            .unwrap()
            .join("checkpoint-events.jsonl");
        let before_audit = fs::read(&audit_path).unwrap();
        fs::write(
            store.workspace(&lab.lab_id).unwrap().join("fixture.py"),
            "print('after')\n",
        )
        .unwrap();
        assert!(!crate::git::diff(&store.workspace(&lab.lab_id).unwrap())
            .unwrap()
            .is_empty());
        restore(&store, &lab.lab_id, &id).unwrap();
        assert!(crate::git::diff(&store.workspace(&lab.lab_id).unwrap())
            .unwrap()
            .is_empty());
        assert_eq!(
            store.load_lab(&lab.lab_id).unwrap().execution_ids,
            lab.execution_ids
        );
        assert!(fs::read(&audit_path).unwrap().starts_with(&before_audit));
        let snapshot = store
            .lab_dir(&lab.lab_id)
            .unwrap()
            .join("checkpoints")
            .join(&id)
            .join("contents/workspace/fixture.py");
        fs::write(snapshot, "tamper").unwrap();
        assert!(restore(&store, &lab.lab_id, &id)
            .unwrap_err()
            .to_string()
            .contains("digest mismatch"));
    }
}
