//! Mandatory on a capable Linux runner; never auto-skipped as a passing isolation test.
//! PETRI_E2E_BUSYBOX=/bin/busybox cargo test --test runtime_linux -- --ignored --nocapture
#![cfg(target_os = "linux")]
use git2::{Repository, Signature};
use petri::{labs::Store, policy::Config, stacks};
use std::{fs, process::Command};

#[test]
#[ignore = "requires static BusyBox and host-enabled rootless namespaces with Landlock ABI >=3"]
fn real_isolation_preserves_host_and_blocks_rootfs_writes() {
    let busybox = std::env::var_os("PETRI_E2E_BUSYBOX")
        .expect("set PETRI_E2E_BUSYBOX to a static BusyBox executable");
    let temp = tempfile::tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    fs::create_dir_all(rootfs.join("bin")).unwrap();
    fs::copy(busybox, rootfs.join("bin/busybox")).unwrap();
    std::os::unix::fs::symlink("busybox", rootfs.join("bin/sh")).unwrap();
    let source = temp.path().join("source");
    let repo = Repository::init(&source).unwrap();
    fs::write(source.join("original"), b"host source\n").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("original")).unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let sig = Signature::now("E2E", "test@localhost").unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "initial", &tree, &[])
        .unwrap();
    let store = Store::open(temp.path().join("state")).unwrap();
    let stack = stacks::import_rootfs(&store.home.join("stacks"), "e2e", &rootfs).unwrap();
    let lab = store
        .create(&source, "isolation check".into(), "e2e", Config::default())
        .unwrap();
    let dir = store.lab_dir(&lab.id).unwrap();
    fs::write(dir.join("blackbox/audit-marker"), b"host-only").unwrap();
    fs::write(temp.path().join("host-marker"), b"untouched").unwrap();
    let script="set -eu; test -z \"${PETRI_TEST_SECRET+x}\"; test ! -e /logs/audit-marker; test ! -e /.petri-oldroot/etc/passwd; test ! -d /git; if (echo escaped > /petri-escape) 2>/dev/null; then exit 81; fi; if (echo escaped > /run/escape) 2>/dev/null; then exit 82; fi; if /bin/busybox wget -T 1 -O /tmp/network-output http://1.1.1.1 2>/dev/null; then exit 83; fi; echo safe > /workspace/result; test -e /proc/self/status; /bin/busybox rm /workspace/original";
    let output = Command::new(env!("CARGO_BIN_EXE_petri"))
        .arg("--home")
        .arg(&store.home)
        .arg("run")
        .arg(&lab.id)
        .arg("--")
        .args(["/bin/sh", "-c", script])
        .env("PETRI_TEST_SECRET", "must-not-leak")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sandbox failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(dir.join("workspace/result")).unwrap(), b"safe\n");
    assert_eq!(fs::read(source.join("original")).unwrap(), b"host source\n");
    assert_eq!(
        fs::read(temp.path().join("host-marker")).unwrap(),
        b"untouched"
    );
    assert_eq!(
        fs::read(dir.join("blackbox/audit-marker")).unwrap(),
        b"host-only"
    );
    assert!(!stack.rootfs.join("petri-escape").exists());
    assert!(!stack.rootfs.join("run/escape").exists());
    assert!(!fs::read_to_string(dir.join("blackbox/terminal.cast"))
        .unwrap()
        .contains("must-not-leak"));
}
