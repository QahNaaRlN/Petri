//! Host lifecycle acceptance tests. These use real Git objects and verified stack
//! storage but never claim to exercise kernel isolation (see runtime tests).
use git2::{IndexAddOption, Repository, Signature};
use petri::{git, labs::Store, policy::Config, stacks};
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    store: Store,
    source: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        let repo = Repository::init(&source).unwrap();
        fs::write(source.join("hello.txt"), "original\n").unwrap();
        fs::write(source.join(".env"), "SECRET=must-not-export\n").unwrap();
        let mut index = repo.index().unwrap();
        index.add_all(["*"], IndexAddOption::DEFAULT, None).unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = Signature::now("Fixture", "fixture@example.invalid").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "source baseline", &tree, &[])
            .unwrap();
        fs::write(source.join("untracked.txt"), "user scratch file\n").unwrap();
        let store = Store::open(temp.path().join("state")).unwrap();
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(rootfs.join("etc/os-release"), "NAME=fixture\n").unwrap();
        stacks::import_rootfs(&store.home.join("stacks"), "fixture", &rootfs).unwrap();
        Self {
            _temp: temp,
            store,
            source,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Stack blobs are intentionally read-only. Remove via the store API so
        // TempDir can clean the fixture without changing product permissions.
        let _ = stacks::remove(&self.store.home.join("stacks"), "fixture");
    }
}

#[test]
fn checkpoint_restores_workspace_and_git_without_rewinding_audit() {
    let f = Fixture::new();
    let source_head = git::current_head(&f.source).unwrap();
    let lab = f
        .store
        .create(
            &f.source,
            "change hello".into(),
            "fixture",
            Config::default(),
        )
        .unwrap();
    let dir = f.store.lab_dir(&lab.id).unwrap();
    let workspace = dir.join("workspace");
    assert!(!workspace.join(".env").exists());
    assert!(!workspace.join("untracked.txt").exists());
    assert_eq!(f.store.list().unwrap().len(), 1);
    fs::write(workspace.join("hello.txt"), "first change\n").unwrap();
    let first_commit = git::commit(&workspace, "first change").unwrap();
    let cp = f.store.checkpoint(&lab.id, "preserve first state").unwrap();
    let audit_before = fs::read_to_string(dir.join("blackbox/events.jsonl")).unwrap();
    fs::write(workspace.join("hello.txt"), "second change\n").unwrap();
    fs::write(workspace.join("new-file"), "later\n").unwrap();
    git::commit(&workspace, "second change").unwrap();
    f.store.restore(&lab.id, &cp).unwrap();
    assert_eq!(
        fs::read_to_string(workspace.join("hello.txt")).unwrap(),
        "first change\n"
    );
    assert!(!workspace.join("new-file").exists());
    let metadata = Repository::open_bare(dir.join("git")).unwrap();
    assert_eq!(
        metadata
            .head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .id()
            .to_string(),
        first_commit
    );
    assert!(git::diff(&workspace).unwrap().contains("+first change"));
    let audit_after = fs::read_to_string(dir.join("blackbox/events.jsonl")).unwrap();
    assert!(audit_after.starts_with(&audit_before));
    assert!(audit_after.contains("checkpoint_restored"));
    assert_eq!(git::current_head(&f.source).unwrap(), source_head);
    f.store.discard(&lab.id).unwrap();
    assert!(f.store.list().unwrap().is_empty());
    assert!(!dir.exists());
}

#[test]
fn review_publication_preserves_dirty_source_and_main() {
    let f = Fixture::new();
    let lab = f
        .store
        .create(
            &f.source,
            "review branch".into(),
            "fixture",
            Config::default(),
        )
        .unwrap();
    let workspace = f.store.lab_dir(&lab.id).unwrap().join("workspace");
    fs::write(workspace.join("hello.txt"), "agent result\n").unwrap();
    fs::write(f.source.join("hello.txt"), "user edit in progress\n").unwrap();
    let branch = git::merge(&f.source, &workspace, &lab.base_commit).unwrap();
    let repo = Repository::open(&f.source).unwrap();
    let result = repo
        .find_branch(&branch, git2::BranchType::Local)
        .unwrap()
        .get()
        .peel_to_commit()
        .unwrap();
    let tree = result.tree().unwrap();
    let entry = tree.get_path(std::path::Path::new("hello.txt")).unwrap();
    assert_eq!(
        repo.find_blob(entry.id()).unwrap().content(),
        b"agent result\n"
    );
    assert!(tree.get_path(std::path::Path::new(".env")).is_ok());
    assert_eq!(git::current_head(&f.source).unwrap(), lab.base_commit);
    assert_eq!(
        fs::read_to_string(f.source.join("hello.txt")).unwrap(),
        "user edit in progress\n"
    );
    assert_eq!(
        fs::read_to_string(f.source.join("untracked.txt")).unwrap(),
        "user scratch file\n"
    );
}

#[test]
fn lifecycle_lock_and_running_status_prevent_live_snapshots() {
    let f = Fixture::new();
    let mut lab = f
        .store
        .create(&f.source, "locked".into(), "fixture", Config::default())
        .unwrap();
    {
        let _guard = f.store.lock(&lab.id).unwrap();
        assert!(f
            .store
            .checkpoint(&lab.id, "busy")
            .unwrap_err()
            .to_string()
            .contains("LabBusy"));
        assert!(f.store.discard(&lab.id).is_err());
    }
    lab.status = "Running".into();
    f.store.save(&lab).unwrap();
    assert!(f.store.checkpoint(&lab.id, "running").is_err());
    assert!(f.store.discard(&lab.id).is_err());
    assert!(f.store.restore(&lab.id, "../../outside").is_err());
    assert!(f.store.lab_dir("../../outside").is_err());
}

#[test]
fn cli_requires_explicit_publication_confirmation() {
    let f = Fixture::new();
    let lab = f
        .store
        .create(
            &f.source,
            "manual approval".into(),
            "fixture",
            Config::default(),
        )
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_petri"))
        .arg("--home")
        .arg(&f.store.home)
        .arg("merge")
        .arg(&lab.id)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("manual confirmation"));
    assert_eq!(git::current_head(&f.source).unwrap(), lab.base_commit);
}

#[cfg(target_os = "linux")]
#[test]
fn unavailable_or_incomplete_stack_never_falls_back_to_host_execution() {
    let f = Fixture::new();
    let lab = f
        .store
        .create(
            &f.source,
            "fail closed".into(),
            "fixture",
            Config::default(),
        )
        .unwrap();
    let marker = f.source.join("must-not-be-created");
    let script = format!("echo unsafe > {}", marker.display());
    // The stack contains no /bin/sh. Whether kernel setup succeeds or fails,
    // this command must never reach the host's interpreter.
    let output = Command::new(env!("CARGO_BIN_EXE_petri"))
        .arg("--home")
        .arg(&f.store.home)
        .arg("run")
        .arg(&lab.id)
        .arg("--")
        .args(["/bin/sh", "-c", &script])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!marker.exists());
    assert_eq!(f.store.load(&lab.id).unwrap().status, "Failed");
    let events = fs::read_to_string(
        f.store
            .lab_dir(&lab.id)
            .unwrap()
            .join("blackbox/events.jsonl"),
    )
    .unwrap();
    assert!(events.contains("run_finished"));
    assert_eq!(git::current_head(&f.source).unwrap(), lab.base_commit);
}

#[cfg(unix)]
#[test]
fn checkpoint_rejects_symlink_chains_that_escape_workspace() {
    let f = Fixture::new();
    let lab = f
        .store
        .create(
            &f.source,
            "malicious links".into(),
            "fixture",
            Config::default(),
        )
        .unwrap();
    let dir = f.store.lab_dir(&lab.id).unwrap();
    std::os::unix::fs::symlink("../blackbox", dir.join("workspace/outside")).unwrap();
    assert!(f.store.checkpoint(&lab.id, "reject escape").is_err());
    assert_eq!(fs::read_dir(dir.join("checkpoints")).unwrap().count(), 0);
    assert!(dir.join("blackbox/events.jsonl").is_file());
}
