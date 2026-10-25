//! Embedded Git without a system executable, hooks, helpers, or checkout filters.
//!
//! ADR-003: libgit2 provides mature local object/ref operations. Laboratory Git
//! metadata is an independent bare repository outside the mounted workspace;
//! worktrees are materialized from blobs, not shared with the source repository.
//! ADR-004: merge publishes a review branch and never edits main or the user's
//! working directory. The host must stop the lab before snapshotting its files.

use anyhow::{bail, ensure, Context, Result};
use git2::{DiffFormat, ObjectType, Oid, Repository, Signature};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    oid: Oid,
    mode: i32,
}

type Files = BTreeMap<String, Entry>;

fn forbidden(path: &str) -> bool {
    path.split('/').any(|part| {
        part.eq_ignore_ascii_case(".git")
            || part == ".ssh"
            || part == "docker.sock"
            || part == ".env"
            || part.starts_with(".env.")
    })
}

fn valid_relative(path: &str) -> Result<()> {
    ensure!(!path.is_empty() && !path.contains('\\'), "unsafe Git path");
    ensure!(
        Path::new(path).components().count() <= 128,
        "snapshot path exceeds maximum nesting depth"
    );
    ensure!(
        Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "unsafe Git path: {path}"
    );
    Ok(())
}

fn safe_link(path: &str, target: &Path) -> Result<()> {
    ensure!(!target.is_absolute(), "absolute symlink denied: {path}");
    let mut parts: Vec<_> = path.split('/').collect();
    parts.pop();
    for component in target.components() {
        match component {
            Component::Normal(p) => {
                let p = p.to_str().context("non-UTF8 symlink target")?;
                ensure!(!p.contains('\\'), "unsafe symlink target: {path}");
                parts.push(p);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ensure!(parts.pop().is_some(), "symlink escapes workspace: {path}");
            }
            _ => bail!("unsafe symlink target: {path}"),
        }
    }
    ensure!(
        !forbidden(&parts.join("/")),
        "symlink targets protected path: {path}"
    );
    Ok(())
}

/// Lexical `..` checks alone are insufficient: a preceding component may itself
/// be a symlink. Resolve the *snapshot graph*, without following host FS links.
fn validate_links(repo: &Repository, files: &Files) -> Result<()> {
    let mut links = BTreeMap::new();
    for (path, entry) in files {
        if entry.mode == 0o120000 {
            let blob = repo.find_blob(entry.oid)?;
            let target = std::str::from_utf8(blob.content()).context("non-UTF8 symlink target")?;
            safe_link(path, Path::new(target))?;
            links.insert(path.clone(), target.to_owned());
        }
    }
    for path in links.keys() {
        let mut pending: VecDeque<String> = path.split('/').map(str::to_owned).collect();
        let mut resolved = Vec::new();
        let mut expansions = 0;
        while let Some(part) = pending.pop_front() {
            match part.as_str() {
                "" | "." => continue,
                ".." => {
                    ensure!(
                        resolved.pop().is_some(),
                        "symlink chain escapes workspace: {path}"
                    );
                }
                _ => {
                    resolved.push(part);
                    let current = resolved.join("/");
                    ensure!(
                        !forbidden(&current),
                        "symlink chain targets protected path: {path}"
                    );
                    if let Some(target) = links.get(&current) {
                        expansions += 1;
                        ensure!(expansions <= 40, "symlink cycle or excessive chain: {path}");
                        resolved.pop();
                        for next in target.split('/').rev() {
                            pending.push_front(next.to_owned());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn flatten(repo: &Repository, tree: &git2::Tree<'_>, prefix: &str, out: &mut Files) -> Result<()> {
    for entry in tree {
        let name = entry
            .name()
            .context("non-UTF8 Git filenames are not supported")?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        valid_relative(&path)?;
        match entry.kind() {
            Some(ObjectType::Tree) => flatten(repo, &repo.find_tree(entry.id())?, &path, out)?,
            Some(ObjectType::Blob) => {
                ensure!(
                    matches!(entry.filemode(), 0o100644 | 0o100755 | 0o120000),
                    "unsupported file mode: {path}"
                );
                out.insert(
                    path,
                    Entry {
                        oid: entry.id(),
                        mode: entry.filemode(),
                    },
                );
                ensure!(out.len() <= 200_000, "snapshot exceeds 200000 files");
            }
            _ => bail!("submodules and non-blob Git entries are unsupported: {path}"),
        }
    }
    Ok(())
}

fn files_at(repo: &Repository, commit: Oid) -> Result<Files> {
    let tree = repo.find_commit(commit)?.tree()?;
    let mut out = Files::new();
    flatten(repo, &tree, "", &mut out)?;
    Ok(out)
}

fn build_tree(repo: &Repository, files: &Files) -> Result<Oid> {
    fn subtree(repo: &Repository, files: &Files, prefix: &str) -> Result<Oid> {
        let mut builder = repo.treebuilder(None)?;
        let mut dirs = BTreeSet::new();
        for (path, entry) in files {
            let Some(rest) = path.strip_prefix(prefix) else {
                continue;
            };
            if let Some((dir, _)) = rest.split_once('/') {
                dirs.insert(dir.to_owned());
            } else {
                builder.insert(rest, entry.oid, entry.mode)?;
            }
        }
        for dir in dirs {
            ensure!(
                builder.get(&dir)?.is_none(),
                "file/directory collision at {prefix}{dir}"
            );
            let id = subtree(repo, files, &format!("{prefix}{dir}/"))?;
            builder.insert(&dir, id, 0o040000)?;
        }
        Ok(builder.write()?)
    }
    subtree(repo, files, "")
}

fn lab_repo(workspace: &Path) -> Result<Repository> {
    let parent = workspace.parent().context("workspace has no parent")?;
    let repo = Repository::open_bare(parent.join("git"))
        .context("lab Git metadata is missing; source repositories must not be passed here")?;
    Ok(repo)
}

/// Resolve the source's current committed HEAD without running Git commands.
pub fn current_head(source: &Path) -> Result<String> {
    let repo = Repository::discover(source).context("source is not a Git repository")?;
    let oid = repo
        .head()
        .context("source must contain an initial commit")?
        .peel_to_commit()?
        .id();
    Ok(oid.to_string())
}

/// Export only committed, permitted files into a fully independent laboratory.
/// Source uncommitted/untracked files and source Git configuration are not copied.
pub fn create_workspace(source: &Path, destination: &Path, branch: &str) -> Result<String> {
    ensure!(
        branch.starts_with("petri/"),
        "lab branch must start with petri/"
    );
    ensure!(
        git2::Reference::is_valid_name(&format!("refs/heads/{branch}")),
        "invalid lab branch"
    );
    let src = Repository::discover(source).context("source is not a Git repository")?;
    let head = src
        .head()
        .context("source must contain an initial commit")?
        .peel_to_commit()?;
    let source_base = head.id();
    let files: Files = files_at(&src, source_base)?
        .into_iter()
        .filter(|(path, _)| !forbidden(path))
        .collect();
    validate_links(&src, &files)?;
    let parent = destination.parent().context("workspace has no parent")?;
    fs::create_dir_all(parent)?;
    let metadata = parent.join("git");
    ensure!(!destination.exists(), "workspace already exists");
    ensure!(!metadata.exists(), "lab Git metadata already exists");
    fs::create_dir(destination)?;
    let result = (|| -> Result<String> {
        let lab = Repository::init_bare(&metadata)?;
        let mut exported = Files::new();
        for (path, entry) in files {
            if forbidden(&path) {
                continue;
            }
            let blob = src.find_blob(entry.oid)?;
            let output = destination.join(&path);
            if let Some(dir) = output.parent() {
                fs::create_dir_all(dir)?;
            }
            if entry.mode == 0o120000 {
                let target = std::str::from_utf8(blob.content()).context("non-UTF8 symlink")?;
                safe_link(&path, Path::new(target))?;
                create_symlink(Path::new(target), &output)?;
            } else {
                fs::write(&output, blob.content())?;
                set_executable(&output, entry.mode == 0o100755)?;
            }
            let oid = lab.blob(blob.content())?;
            exported.insert(
                path,
                Entry {
                    oid,
                    mode: entry.mode,
                },
            );
        }
        let tree = lab.find_tree(build_tree(&lab, &exported)?)?;
        let sig = Signature::now("Petri", "petri@localhost")?;
        let reference = format!("refs/heads/{branch}");
        let initial = lab.commit(
            Some(&reference),
            &sig,
            &sig,
            "Petri isolated baseline",
            &tree,
            &[],
        )?;
        lab.set_head(&reference)?;
        fs::write(metadata.join("petri-source-head"), source_base.to_string())?;
        fs::write(metadata.join("petri-baseline"), initial.to_string())?;
        // The sibling metadata directory is deliberately absent from the sandbox.
        fs::write(destination.join(".git"), "gitdir: ../git\n")?;
        Ok(source_base.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
        let _ = fs::remove_dir_all(metadata);
    }
    result
}

#[cfg(unix)]
fn create_symlink(target: &Path, output: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, output)?;
    Ok(())
}
#[cfg(not(unix))]
fn create_symlink(_target: &Path, _output: &Path) -> Result<()> {
    bail!("symlink export is unsupported on this platform; no unsafe fallback")
}
#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
    )?;
    Ok(())
}
#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "not a regular file: {}",
        path.display()
    );
    // ADR-004: bounded host-side snapshots prevent an agent-created file from
    // exhausting the broker's memory. A caller can archive large data separately.
    const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
    ensure!(
        file.metadata()?.len() <= MAX_FILE_BYTES,
        "snapshot file exceeds 64 MiB: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE_BYTES,
        "snapshot file grew beyond 64 MiB"
    );
    Ok(bytes)
}

fn snapshot(repo: &Repository, workspace: &Path) -> Result<Files> {
    fn walk(repo: &Repository, root: &Path, relative: &Path, out: &mut Files) -> Result<()> {
        for entry in fs::read_dir(root.join(relative))? {
            let entry = entry?;
            let path = relative.join(entry.file_name());
            let name = path
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .context("non-UTF8 filenames are unsupported")
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            if name == ".git" {
                continue;
            }
            valid_relative(&name)?;
            ensure!(!forbidden(&name), "PolicyDenied: protected path {name}");
            let meta = fs::symlink_metadata(entry.path())?;
            if meta.is_dir() {
                walk(repo, root, &path, out)?;
            } else {
                let (bytes, mode) = if meta.file_type().is_symlink() {
                    let target = fs::read_link(entry.path())?;
                    safe_link(&name, &target)?;
                    (
                        target
                            .to_str()
                            .context("non-UTF8 symlink target")?
                            .as_bytes()
                            .to_vec(),
                        0o120000,
                    )
                } else {
                    ensure!(meta.is_file(), "special files are unsupported: {name}");
                    #[cfg(unix)]
                    let executable = {
                        use std::os::unix::fs::PermissionsExt;
                        meta.permissions().mode() & 0o111 != 0
                    };
                    #[cfg(not(unix))]
                    let executable = false;
                    (
                        read_regular(&entry.path())?,
                        if executable { 0o100755 } else { 0o100644 },
                    )
                };
                out.insert(
                    name,
                    Entry {
                        oid: repo.blob(&bytes)?,
                        mode,
                    },
                );
                ensure!(out.len() <= 200_000, "snapshot exceeds 200000 files");
            }
        }
        Ok(())
    }
    let mut files = Files::new();
    walk(repo, workspace, Path::new(""), &mut files)?;
    validate_links(repo, &files)?;
    Ok(files)
}

/// Show all additions, modifications and deletions against the immutable baseline,
/// including changes already committed in the laboratory.
/// The lab must be stopped before calling this operation.
pub fn diff(workspace: &Path) -> Result<String> {
    let repo = lab_repo(workspace)?;
    let baseline: Oid = fs::read_to_string(repo.path().join("petri-baseline"))?
        .trim()
        .parse()?;
    let old = repo.find_commit(baseline)?.tree()?;
    let new = repo.find_tree(build_tree(&repo, &snapshot(&repo, workspace)?)?)?;
    let diff = repo.diff_tree_to_tree(Some(&old), Some(&new), None)?;
    let mut output = String::new();
    diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
        if matches!(line.origin(), '+' | '-' | ' ') {
            output.push(line.origin());
        }
        output.push_str(&String::from_utf8_lossy(line.content()));
        true
    })?;
    Ok(output)
}

/// Commit a stopped lab's files to its own branch; never touches the source.
pub fn commit(workspace: &Path, message: &str) -> Result<String> {
    ensure!(!message.trim().is_empty(), "commit message is empty");
    let repo = lab_repo(workspace)?;
    let parent = repo.head()?.peel_to_commit()?;
    let tree = repo.find_tree(build_tree(&repo, &snapshot(&repo, workspace)?)?)?;
    let sig = Signature::now("Petri", "petri@localhost")?;
    let oid = repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &[&parent])?;
    Ok(oid.to_string())
}

/// Publish the stopped lab's changes as a review branch in the source repository.
/// The source HEAD and working files remain unchanged, including uncommitted files.
/// The caller must obtain explicit host-side approval before invoking this API.
pub fn merge(source: &Path, workspace: &Path, base: &str) -> Result<String> {
    let src = Repository::discover(source)?;
    let source_parent = src.head()?.peel_to_commit()?;
    ensure!(
        source_parent.id().to_string() == base,
        "source HEAD changed; refusing stale merge"
    );
    let lab = lab_repo(workspace)?;
    let recorded = fs::read_to_string(lab.path().join("petri-source-head"))?;
    ensure!(
        recorded.trim() == base,
        "source base does not match lab provenance"
    );
    let baseline_oid: Oid = fs::read_to_string(lab.path().join("petri-baseline"))?
        .trim()
        .parse()?;
    let baseline = files_at(&lab, baseline_oid)?;
    let current = snapshot(&lab, workspace)?;
    let mut merged = files_at(&src, source_parent.id())?;
    let names: BTreeSet<_> = baseline.keys().chain(current.keys()).cloned().collect();
    let mut changes = 0;
    for path in names {
        if baseline.get(&path) == current.get(&path) {
            continue;
        }
        ensure!(
            !forbidden(&path),
            "PolicyDenied: protected merge path {path}"
        );
        changes += 1;
        if let Some(entry) = current.get(&path) {
            let bytes = lab.find_blob(entry.oid)?;
            let oid = src.blob(bytes.content())?;
            merged.insert(
                path,
                Entry {
                    oid,
                    mode: entry.mode,
                },
            );
        } else {
            merged.remove(&path);
        }
    }
    ensure!(changes > 0, "lab has no changes to publish");
    let tree = src.find_tree(build_tree(&src, &merged)?)?;
    let sig = Signature::now("Petri", "petri@localhost")?;
    // UUID prevents overwriting a branch created by an earlier review operation.
    let branch = format!("petri/review-{}", uuid::Uuid::new_v4().simple());
    let reference = format!("refs/heads/{branch}");
    // Check again immediately before publication. We never update source HEAD.
    ensure!(
        src.head()?.peel_to_commit()?.id() == source_parent.id(),
        "source HEAD changed during publication"
    );
    src.commit(
        Some(&reference),
        &sig,
        &sig,
        &format!("Petri laboratory review\n\npetri-source: {base}\n"),
        &tree,
        &[&source_parent],
    )?;
    Ok(branch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn source(root: &Path) -> Repository {
        let repo = Repository::init(root).unwrap();
        fs::write(root.join("hello.txt"), "original\n").unwrap();
        fs::write(root.join(".env"), "TOKEN=secret\n").unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/.env"), "NESTED=secret\n").unwrap();
        fs::write(root.join("nested/file"), "nested\n").unwrap();
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .unwrap();
        let oid = index.write_tree().unwrap();
        let tree = repo.find_tree(oid).unwrap();
        let sig = Signature::now("Test", "test@example.invalid").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "initial", &tree, &[])
            .unwrap();
        drop(tree);
        repo
    }

    #[test]
    fn independent_export_excludes_secrets_and_untracked_files() {
        let tmp = TempDir::new().unwrap();
        let src = source(&tmp.path().join("source"));
        let source_root = src.workdir().unwrap();
        fs::write(source_root.join("untracked"), "not exported").unwrap();
        let workspace = tmp.path().join("lab/workspace");
        let base = create_workspace(source_root, &workspace, "petri/test").unwrap();
        assert_eq!(current_head(source_root).unwrap(), base);
        assert!(!workspace.join(".env").exists());
        assert!(!workspace.join("nested/.env").exists());
        assert!(!workspace.join("untracked").exists());
        assert_eq!(
            fs::read_to_string(workspace.join("hello.txt")).unwrap(),
            "original\n"
        );
        assert!(workspace.parent().unwrap().join("git/objects").is_dir());
        fs::write(workspace.join("hello.txt"), "changed\n").unwrap();
        fs::write(workspace.join("added"), "new\n").unwrap();
        let patch = diff(&workspace).unwrap();
        assert!(patch.contains("-original"));
        assert!(patch.contains("+changed"));
        assert!(patch.contains("+new"));
        commit(&workspace, "agent change").unwrap();
        assert_eq!(diff(&workspace).unwrap(), patch);
        assert_eq!(current_head(source_root).unwrap(), base);
        assert_eq!(
            fs::read_to_string(source_root.join("hello.txt")).unwrap(),
            "original\n"
        );
    }

    #[test]
    fn publication_preserves_main_secrets_and_dirty_worktree() {
        let tmp = TempDir::new().unwrap();
        let src = source(&tmp.path().join("source"));
        let root = src.workdir().unwrap();
        let workspace = tmp.path().join("lab/workspace");
        let base = create_workspace(root, &workspace, "petri/test").unwrap();
        fs::write(root.join("hello.txt"), "user dirty edit\n").unwrap();
        fs::remove_dir_all(workspace.join("nested")).unwrap();
        fs::write(workspace.join("hello.txt"), "agent change\n").unwrap();
        let branch = merge(root, &workspace, &base).unwrap();
        let review = src
            .find_branch(&branch, git2::BranchType::Local)
            .unwrap()
            .get()
            .peel_to_commit()
            .unwrap();
        let files = files_at(&src, review.id()).unwrap();
        assert!(files.contains_key(".env"));
        assert!(files.contains_key("nested/.env"));
        assert!(!files.contains_key("nested/file"));
        assert_eq!(current_head(root).unwrap(), base);
        assert_eq!(
            fs::read_to_string(root.join("hello.txt")).unwrap(),
            "user dirty edit\n"
        );
    }

    #[test]
    fn stale_publication_and_protected_files_are_denied() {
        let tmp = TempDir::new().unwrap();
        let src = source(&tmp.path().join("source"));
        let root = src.workdir().unwrap();
        let workspace = tmp.path().join("lab/workspace");
        let base = create_workspace(root, &workspace, "petri/test").unwrap();
        fs::write(workspace.join(".env"), "accidental token").unwrap();
        assert!(diff(&workspace)
            .unwrap_err()
            .to_string()
            .contains("PolicyDenied"));
        fs::remove_file(workspace.join(".env")).unwrap();
        let parent = src.head().unwrap().peel_to_commit().unwrap();
        let tree = parent.tree().unwrap();
        let sig = Signature::now("Test", "test@example.invalid").unwrap();
        src.commit(Some("HEAD"), &sig, &sig, "source moved", &tree, &[&parent])
            .unwrap();
        assert!(merge(root, &workspace, &base)
            .unwrap_err()
            .to_string()
            .contains("source HEAD changed"));
    }

    #[cfg(unix)]
    #[test]
    fn escaping_symlink_export_is_rejected_and_cleaned() {
        let tmp = TempDir::new().unwrap();
        let src = source(&tmp.path().join("source"));
        let root = src.workdir().unwrap();
        std::os::unix::fs::symlink("../../outside", root.join("bad")).unwrap();
        let mut index = src.index().unwrap();
        index.add_path(Path::new("bad")).unwrap();
        let tree = src.find_tree(index.write_tree().unwrap()).unwrap();
        let parent = src.head().unwrap().peel_to_commit().unwrap();
        let sig = Signature::now("Test", "test@example.invalid").unwrap();
        src.commit(Some("HEAD"), &sig, &sig, "bad symlink", &tree, &[&parent])
            .unwrap();
        let workspace = tmp.path().join("lab/workspace");
        assert!(create_workspace(root, &workspace, "petri/test").is_err());
        assert!(!workspace.exists());
        assert!(!workspace.parent().unwrap().join("git").exists());
    }

    #[test]
    fn protected_descendant_prevents_file_directory_collision() {
        let tmp = TempDir::new().unwrap();
        let src = source(&tmp.path().join("source"));
        let root = src.workdir().unwrap();
        let workspace = tmp.path().join("lab/workspace");
        let base = create_workspace(root, &workspace, "petri/test").unwrap();
        fs::remove_dir_all(workspace.join("nested")).unwrap();
        fs::write(workspace.join("nested"), "replacement file").unwrap();
        assert!(merge(root, &workspace, &base)
            .unwrap_err()
            .to_string()
            .contains("collision"));
    }

    #[test]
    fn malicious_git_pointer_cannot_redirect_host_operations() {
        let tmp = TempDir::new().unwrap();
        let src = source(&tmp.path().join("source"));
        let root = src.workdir().unwrap();
        let workspace = tmp.path().join("lab/workspace");
        let base = create_workspace(root, &workspace, "petri/test").unwrap();
        fs::write(
            workspace.join(".git"),
            format!("gitdir: {}\n", src.path().display()),
        )
        .unwrap();
        fs::write(workspace.join("hello.txt"), "agent changes\n").unwrap();
        commit(&workspace, "must remain in independent metadata").unwrap();
        assert_eq!(current_head(root).unwrap(), base);
        assert!(diff(&workspace).unwrap().contains("+agent changes"));
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_does_not_follow_absolute_or_protected_symlinks() {
        let tmp = TempDir::new().unwrap();
        let src = source(&tmp.path().join("source"));
        let root = src.workdir().unwrap();
        let workspace = tmp.path().join("lab/workspace");
        create_workspace(root, &workspace, "petri/test").unwrap();
        std::os::unix::fs::symlink(root.join(".env"), workspace.join("leak")).unwrap();
        assert!(diff(&workspace)
            .unwrap_err()
            .to_string()
            .contains("absolute symlink denied"));
        fs::remove_file(workspace.join("leak")).unwrap();
        std::os::unix::fs::symlink(".env", workspace.join("leak")).unwrap();
        assert!(diff(&workspace)
            .unwrap_err()
            .to_string()
            .contains("protected path"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_chain_cannot_hide_a_parent_escape() {
        let tmp = TempDir::new().unwrap();
        let src = source(&tmp.path().join("source"));
        let root = src.workdir().unwrap();
        let workspace = tmp.path().join("lab/workspace");
        create_workspace(root, &workspace, "petri/test").unwrap();
        fs::create_dir(workspace.join("links")).unwrap();
        std::os::unix::fs::symlink("..", workspace.join("links/up")).unwrap();
        // Lexically links/up/../outside stays below workspace. Expanding up
        // first reveals that the following .. escapes the workspace root.
        std::os::unix::fs::symlink("up/../outside", workspace.join("links/leak")).unwrap();
        assert!(diff(&workspace)
            .unwrap_err()
            .to_string()
            .contains("chain escapes workspace"));
    }
}
