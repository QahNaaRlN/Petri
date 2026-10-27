//! Explicit Windows qualification only. Portable compilation is not isolation evidence.
//! Requires a standard non-admin Windows 11 24H2 x64 account and an externally
//! pinned portable CPython 3.12 directory/manifest. See qualify-windows.py --help.

#[cfg(not(target_os = "windows"))]
mod unsupported_host {
    use serde_json::Value;
    use std::process::{Command, Output};

    fn request(home: &std::path::Path, arguments: &[&str]) -> (Output, Value) {
        let output = Command::new(env!("CARGO_BIN_EXE_petri"))
            .arg("--home")
            .arg(home)
            .arg("windows")
            .args(arguments)
            .output()
            .unwrap();
        let response: Value = serde_json::from_slice(&output.stdout)
            .expect("stdout must contain exactly one JSON envelope, with no workload output");
        assert_eq!(response["protocol"], "petri.control/v1");
        assert!(response["request_id"].as_str().unwrap().starts_with("req-"));
        assert!(response["operation_id"]
            .as_str()
            .unwrap()
            .starts_with("op-"));
        (output, response)
    }

    #[test]
    fn native_doctor_reports_unsupported_without_creating_legacy_state() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("state");
        let (output, response) = request(&home, &["doctor", "--json", "--api-version", "1"]);
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(response["status"], "ok");
        assert_eq!(response["result"]["supported"], false);
        assert!(
            !home.exists(),
            "advisory probe must not open the legacy store"
        );
    }

    #[test]
    fn native_commands_and_unknown_protocol_fail_before_store_mutations() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("state");
        for arguments in [
            vec!["doctor", "--api-version", "2"],
            vec!["create", "--repo", "/not-used", "--tool", "not-used"],
        ] {
            let (output, response) = request(&home, &arguments);
            assert_eq!(output.status.code(), Some(3));
            assert_eq!(response["status"], "error");
            assert_eq!(response["error"]["code"], "Unsupported");
            assert!(
                !home.exists(),
                "refused Windows commands must leave stores untouched"
            );
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use git2::{IndexAddOption, Repository, Signature};
    use std::{fs, path::Path, process::Command};

    #[test]
    #[ignore = "real Windows isolation: set PETRI_WINDOWS_NATIVE_E2E=1, PETRI_WINDOWS_PYTHON_HOME and PETRI_WINDOWS_TOOLCHAIN_MANIFEST; run --ignored"]
    fn owned_offline_native_qualification() {
        assert_eq!(
            std::env::var("PETRI_WINDOWS_NATIVE_E2E").as_deref(),
            Ok("1"),
            "native qualification must be explicitly enabled; no skip-shaped PASS"
        );
        let python_home = std::env::var_os("PETRI_WINDOWS_PYTHON_HOME")
            .expect("provide the prepared portable CPython 3.12 directory");
        let manifest = std::env::var_os("PETRI_WINDOWS_TOOLCHAIN_MANIFEST")
            .expect("provide the external pinned all-files toolchain manifest");
        let fixture = tempfile::Builder::new()
            .prefix("petri-windows-qualification-")
            .tempdir()
            .unwrap()
            .keep();
        // Keep even on failure: unknown native executions must not be deleted
        // by a TempDir destructor, and qualification evidence must remain inspectable.
        eprintln!("Windows qualification evidence: {}", fixture.display());
        let source = fixture.join("source");
        let repo = Repository::init(&source).unwrap();
        fs::write(source.join("original.txt"), b"owned source baseline\n").unwrap();
        fs::write(
            source.join("native_fixture.py"),
            include_bytes!("fixtures/windows/native_fixture.py"),
        )
        .unwrap();
        let mut index = repo.index().unwrap();
        index.add_all(["*"], IndexAddOption::DEFAULT, None).unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let signature = Signature::now("Owned qualification", "fixture@localhost").unwrap();
        let baseline = repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "owned fixture",
                &tree,
                &[],
            )
            .unwrap();
        fs::write(source.join("untracked.txt"), b"owned untracked canary").unwrap();
        let output = Command::new(Path::new(&python_home).join("python.exe"))
            .args(["-I", "-S"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/qualify-windows.py"))
            .arg("--petri")
            .arg(env!("CARGO_BIN_EXE_petri"))
            .arg("--python-home")
            .arg(python_home)
            .arg("--toolchain-manifest")
            .arg(manifest)
            .arg("--source")
            .arg(&source)
            .arg("--output")
            .arg(fixture.join("qualification"))
            .output()
            .expect("start the qualification harness with the pinned host interpreter");
        assert!(
            output.status.success(),
            "qualification failed; evidence retained at {}\nstdout={}\nstderr={}",
            fixture.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            repo.head().unwrap().peel_to_commit().unwrap().id(),
            baseline
        );
        assert_eq!(
            fs::read(source.join("original.txt")).unwrap(),
            b"owned source baseline\n"
        );
        assert_eq!(
            fs::read(source.join("untracked.txt")).unwrap(),
            b"owned untracked canary"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.join("qualification/report.json")).unwrap())
                .unwrap();
        assert_eq!(report["assigned_suite"], "PASS");
        assert_eq!(report["full_specification"], "UNVERIFIED");
        assert_eq!(report["native_execution_observed"], true);
    }
}
