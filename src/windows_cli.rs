//! Explicit candidate CLI. Workload output never shares the machine-response stream.
use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Args)]
pub struct WindowsCli {
    #[arg(long, global = true, default_value_t = 1)]
    api_version: u16,
    /// Windows candidate commands always return JSON; accepted for explicit callers.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: WindowsAction,
}

#[derive(Subcommand)]
enum WindowsAction {
    /// Diagnostic capability probe, not a qualification certificate.
    Doctor,
    Tool {
        #[command(subcommand)]
        command: ToolAction,
    },
    /// Export committed HEAD into a separate native-v2 laboratory.
    Create {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        tool: String,
        #[arg(long, default_value = "offline Windows candidate")]
        task: String,
    },
    /// Run the registered CPython with -I -S and a script from the lab workspace.
    Run {
        id: String,
        #[arg(long)]
        script: PathBuf,
        #[arg(long)]
        operation_id: Option<String>,
        #[arg(long)]
        wallclock_ms: Option<u64>,
        #[arg(long)]
        detach: bool,
        #[arg(last = true)]
        args: Vec<String>,
    },
    Status {
        id: String,
        #[arg(long)]
        execution: Option<String>,
    },
    Stop {
        id: String,
        #[arg(long)]
        execution: String,
        #[arg(long)]
        operation_id: Option<String>,
    },
    Result {
        id: String,
        #[arg(long)]
        execution: String,
    },
    Checkpoint {
        id: String,
        #[arg(default_value = "")]
        message: String,
    },
    Restore {
        id: String,
        checkpoint: String,
    },
    Diff {
        id: String,
    },
    Commit {
        id: String,
        #[arg(short, long)]
        message: String,
    },
    #[command(hide = true)]
    Guardian {
        id: String,
        execution: String,
    },
}

#[derive(Subcommand)]
enum ToolAction {
    /// Copy and verify every file against an explicit offline distribution manifest.
    Import {
        source: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    List,
}

pub fn entry(home: PathBuf, cli: WindowsCli) -> i32 {
    let request_id = format!("req-{}", uuid::Uuid::new_v4().simple());
    let operation_id = match &cli.command {
        WindowsAction::Run { operation_id, .. } | WindowsAction::Stop { operation_id, .. } => {
            operation_id.clone()
        }
        _ => None,
    }
    .unwrap_or_else(|| format!("op-{}", uuid::Uuid::new_v4().simple()));
    let _explicit_json = cli.json;
    let response = if cli.api_version != 1 {
        Err(anyhow::anyhow!(
            "UnsupportedProtocol: expected --api-version 1"
        ))
    } else {
        dispatch(home, cli.command, &operation_id)
    };
    let (body, code) = match response {
        Ok((result, code)) => (
            json!({"protocol":"petri.control/v1","request_id":request_id,
                "operation_id":operation_id,"status":"ok","result":result,
                "warnings":["Experimental Windows offline candidate; no qualification is implied."]}),
            code,
        ),
        Err(error) => {
            let message = format!("{error:#}");
            let (error_code, exit_code) = classify_error(&message);
            (
                json!({"protocol":"petri.control/v1","request_id":request_id,
                "operation_id":operation_id,"status":"error",
                "error":{"code":error_code,"stage":"windows-candidate","native_code":null,
                    "message":message,"remediation":null},"warnings":[]}),
                exit_code,
            )
        }
    };
    println!("{body}");
    code
}

fn classify_error(message: &str) -> (&'static str, i32) {
    if message.contains("Unsupported") || message.contains("NotImplemented") {
        ("Unsupported", 3)
    } else if message.contains("LabBusy")
        || message.contains("IdempotencyConflict")
        || message.contains("StaleRevision")
    {
        ("Conflict", 5)
    } else if message.contains("PolicyDenied")
        || message.contains("Integrity")
        || message.contains("ArtifactInvalid")
    {
        ("PolicyDenied", 4)
    } else if message.contains("Journal") {
        ("JournalFailure", 10)
    } else if message.contains("InvalidRequest") || message.contains("InvalidInput") {
        ("InvalidRequest", 2)
    } else if message.contains("RecoveryRequired") {
        ("RecoveryRequired", 9)
    } else {
        ("SetupFailure", 6)
    }
}

#[cfg(not(target_os = "windows"))]
fn dispatch(_home: PathBuf, command: WindowsAction, _operation: &str) -> Result<(Value, i32)> {
    if matches!(command, WindowsAction::Doctor) {
        return Ok((
            json!({"supported":false,"backend":"windows-native",
            "profile":"windows-native-python312-lpac/v1","os":std::env::consts::OS,
            "reason":"Unsupported: native Windows execution requires a qualified Windows host"}),
            3,
        ));
    }
    bail!("Unsupported: the native Windows candidate only operates on Windows")
}

#[cfg(target_os = "windows")]
fn dispatch(home: PathBuf, command: WindowsAction, operation: &str) -> Result<(Value, i32)> {
    native::dispatch(home, command, operation)
}

#[cfg(target_os = "windows")]
mod native {
    use super::*;
    use anyhow::{ensure, Context};
    use fs2::FileExt;
    use petri::{
        execution::{
            self, CommandSpec, EnvironmentRef, ExecutionPolicy, ExecutionRecord, Outcome, Phase,
            ResourceBinding, StartRequest, StopProof, Store, TerminalResult,
        },
        native_tools::{NativeToolStore, NativeToolchain},
        windows_native::{self, NativeEvent, NativeLimits, NativeRequest, StopReason},
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        path::{Component, Path},
        process::{Command, Stdio},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    pub(super) fn dispatch(
        home: PathBuf,
        command: WindowsAction,
        operation: &str,
    ) -> Result<(Value, i32)> {
        if matches!(command, WindowsAction::Doctor) {
            let probe = windows_native::probe();
            let code = if probe.supported { 0 } else { 3 };
            let mut value = serde_json::to_value(probe)?;
            value["profile"] = json!("windows-native-python312-lpac/v1");
            value["qualification"] = json!("not-established-by-probe");
            return Ok((value, code));
        }
        let store = Store::open(home.clone())?;
        let tools = NativeToolStore::open(store.root.join("toolchains"))?;
        match command {
            WindowsAction::Doctor => unreachable!("probe handled above"),
            WindowsAction::Tool {
                command: ToolAction::Import { source, manifest },
            } => Ok((serde_json::to_value(tools.import(&source, &manifest)?)?, 0)),
            WindowsAction::Tool {
                command: ToolAction::List,
            } => Ok((serde_json::to_value(tools.list()?)?, 0)),
            WindowsAction::Create { repo, tool, task } => {
                let tool = tools.resolve(&tool)?;
                tools.verify(&tool)?;
                let lab = store.prepare(&repo, &task, environment_ref(&tool))?;
                let workspace = store.workspace(&lab.lab_id)?;
                Ok((
                    json!({"id":lab.lab_id,"lab_id":lab.lab_id,"workspace":workspace,"lab":lab}),
                    0,
                ))
            }
            WindowsAction::Run {
                id,
                script,
                wallclock_ms,
                detach,
                args,
                ..
            } => {
                ensure!(!detach, "Unsupported: detached Windows candidate needs a persistent controller; use foreground run");
                run(
                    &store,
                    &tools,
                    &home,
                    operation,
                    RunInput {
                        id: &id,
                        script: &script,
                        args,
                        wallclock_ms,
                    },
                )
            }
            WindowsAction::Status { id, execution } => {
                let lab = store.load_lab(&id)?;
                let selected = execution
                    .or_else(|| lab.active_execution.clone())
                    .or_else(|| lab.execution_ids.last().cloned());
                let record = selected
                    .map(|exec| store.load_execution(&id, &exec))
                    .transpose()?;
                Ok((json!({"lab":lab,"execution":record}), 0))
            }
            WindowsAction::Result { id, execution } => {
                let record = store.load_execution(&id, &execution)?;
                let code = result_code(&record);
                Ok((execution_payload(&store, &record)?, code))
            }
            WindowsAction::Checkpoint { id, message } => {
                let checkpoint = petri::native_checkpoints::create(&store, &id, &message)?;
                Ok((json!({"lab_id":id,"checkpoint_id":checkpoint}), 0))
            }
            WindowsAction::Restore { id, checkpoint } => {
                petri::native_checkpoints::restore(&store, &id, &checkpoint)?;
                Ok((
                    json!({"lab_id":id,"checkpoint_id":checkpoint,"restored":true}),
                    0,
                ))
            }
            WindowsAction::Diff { id } => {
                let diff = store
                    .with_stopped_lab(&id, |dir, _| petri::git::diff(&dir.join("workspace")))?;
                Ok((json!({"lab_id":id,"diff":diff}), 0))
            }
            WindowsAction::Commit { id, message } => {
                let commit = store.with_stopped_lab(&id, |dir, _| {
                    petri::git::commit(&dir.join("workspace"), &message)
                })?;
                Ok((json!({"lab_id":id,"commit":commit}), 0))
            }
            WindowsAction::Stop { id, execution, .. } => {
                let record = retry_busy(|| store.request_stop(&id, &execution, operation))?;
                let deadline = Instant::now()
                    + Duration::from_millis(record.request.policy.stop_timeout_ms + 1_000);
                loop {
                    let record = retry_busy(|| store.load_execution(&id, &execution))?;
                    if record
                        .result
                        .as_ref()
                        .is_some_and(|result| result.stop.confirmed)
                    {
                        return Ok((execution_payload(&store, &record)?, 0));
                    }
                    if record.phase == Phase::Terminal || Instant::now() >= deadline {
                        return Ok((execution_payload(&store, &record)?, 9));
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
            WindowsAction::Guardian { id, execution } => {
                guardian(&store, &tools, &id, &execution)?;
                Ok((json!({"guardian_completed":true}), 0))
            }
        }
    }

    fn environment_ref(tool: &NativeToolchain) -> EnvironmentRef {
        EnvironmentRef {
            kind: "windows-native".into(),
            id: tool.id.clone(),
            digest: tool.digest.clone(),
        }
    }

    fn retry_busy<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match operation() {
                Err(error)
                    if format!("{error:#}").contains("LabBusy") && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                result => return result,
            }
        }
    }

    fn bound_tool(store: &Store, tools: &NativeToolStore, id: &str) -> Result<NativeToolchain> {
        let lab = store.load_lab(id)?;
        let tool = tools.resolve(&lab.environment.id)?;
        tools.verify(&tool)?;
        ensure!(
            environment_ref(&tool) == lab.environment,
            "Integrity: registered environment differs from lab binding"
        );
        Ok(tool)
    }

    struct RunInput<'a> {
        id: &'a str,
        script: &'a Path,
        args: Vec<String>,
        wallclock_ms: Option<u64>,
    }

    fn run(
        store: &Store,
        tools: &NativeToolStore,
        home: &Path,
        operation: &str,
        input: RunInput<'_>,
    ) -> Result<(Value, i32)> {
        let RunInput {
            id,
            script,
            args,
            wallclock_ms,
        } = input;
        let probe = windows_native::probe();
        ensure!(
            probe.supported,
            "Unsupported: {}",
            probe
                .reason
                .unwrap_or_else(|| "native Windows profile unavailable".into())
        );
        let tool = bound_tool(store, tools, id)?;
        let workspace = store.workspace(id)?.canonicalize()?;
        ensure!(
            !script.as_os_str().is_empty()
                && script
                    .components()
                    .all(|part| matches!(part, Component::Normal(_))),
            "InvalidInput: --script must be a relative workspace path without traversal"
        );
        let absolute_script = workspace
            .join(script)
            .canonicalize()
            .context("resolve workspace Python script")?;
        ensure!(
            absolute_script.starts_with(&workspace) && absolute_script.is_file(),
            "PolicyDenied: script must be a regular file in the laboratory"
        );
        let script_name = path_string(&absolute_script)?;
        ensure!(
            absolute_script
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("py")),
            "UnsupportedProfile: first Windows candidate executes a Python .py script"
        );
        // The backend authors mandatory Windows environment entries. This map
        // contains approved extras only; host environment is never copied.
        let environment = BTreeMap::new();
        let mut argv = vec!["-I".into(), "-S".into(), script_name];
        argv.extend(args);
        let mut policy = ExecutionPolicy::default();
        if let Some(ms) = wallclock_ms {
            policy.wall_time_ms = ms;
        }
        ensure!(
            policy.wall_time_ms <= 3_600_000,
            "UnsupportedPolicy: Windows candidate wallclock limit is one hour"
        );
        let request = StartRequest {
            command: CommandSpec {
                executable: tool.executable.clone(),
                argv,
                cwd: workspace,
                environment,
            },
            policy,
            environment: environment_ref(&tool),
        };
        let begin = store.begin_execution(id, operation, &request)?;
        if !begin.created {
            let code = result_code(&begin.execution);
            let mut result = execution_payload(store, &begin.execution)?;
            result["idempotent_replay"] = json!(true);
            return Ok((result, code));
        }
        let execution = begin.execution.execution_id;
        let control = store.control_dir(id, &execution)?;
        let diagnostics = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(control.join("guardian.stderr"))?;
        let child = Command::new(std::env::current_exe()?)
            .arg("--home")
            .arg(home)
            .args(["windows", "guardian", id, &execution])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::from(diagnostics))
            .spawn();
        match child {
            Ok(mut child) => {
                // Sole controller lease: closing this private pipe requests a stop.
                // The handle stays owned until the guardian exits; it is never passed to the workload.
                let ownership = child.stdin.take().context("guardian ownership pipe")?;
                let waited = child.wait();
                drop(ownership);
                waited.context("wait for native guardian")?;
            }
            Err(error) => {
                store.finish_execution(id, &execution, TerminalResult {
                    outcome: Outcome::SetupFailed, windows_exit_code: None,
                    stop: StopProof { confirmed: true, active_processes: Some(0),
                        observation: "Controller could not create a guardian process; workload launch was never invoked.".into() },
                    user_cpu_100ns: 0, peak_job_memory: 0, stdout_bytes: 0, stderr_bytes: 0,
                    detail: Some(format!("guardian spawn failed: {error}")),
                })?;
            }
        }
        let mut record = store.load_execution(id, &execution)?;
        if record.phase != Phase::Terminal {
            store.recover_interrupted(id)?;
            record = store.load_execution(id, &execution)?;
        }
        let code = result_code(&record);
        Ok((execution_payload(store, &record)?, code))
    }

    fn path_string(path: &Path) -> Result<String> {
        path.to_str()
            .map(str::to_owned)
            .context("InvalidInput: native candidate requires Unicode paths")
    }

    fn execution_payload(store: &Store, record: &ExecutionRecord) -> Result<Value> {
        let control = store
            .lab_dir(&record.lab_id)?
            .join("blackbox")
            .join(&record.execution_id);
        let report_path = control.join("report.json");
        let report = if record.result.is_some() && report_path.exists() {
            Some(serde_json::from_slice::<Value>(&fs::read(&report_path)?)?)
        } else {
            None
        };
        let manifest_path = control.join("result.json");
        let manifest = if record.phase == Phase::Terminal && manifest_path.exists() {
            Some(serde_json::from_slice::<Value>(&fs::read(&manifest_path)?)?)
        } else {
            None
        };
        let manifest_digest = if manifest.is_some() {
            Some(hash_artifact(&manifest_path)?)
        } else {
            None
        };
        Ok(
            json!({"execution_id":record.execution_id,"execution":record,"report":report,
            "result_manifest":manifest,"result_manifest_integrity":manifest_digest,
            "artifacts":{"events":control.join("events.jsonl"),"stdout":control.join("stdout.bin"),
                "stderr":control.join("stderr.bin"),"guardian_stderr":control.join("guardian.stderr"),
                "effective_environment":control.join("environment.json"),"inputs":control.join("inputs.json"),
                "result_manifest":manifest_path}}),
        )
    }

    fn result_code(record: &ExecutionRecord) -> i32 {
        let Some(result) = &record.result else {
            return 9;
        };
        if result
            .detail
            .as_ref()
            .is_some_and(|detail| detail.contains("JournalFailure"))
        {
            return 10;
        }
        if !result.stop.confirmed {
            return 9;
        }
        match result.outcome {
            Outcome::Exited if result.windows_exit_code == Some(0) => 0,
            Outcome::Exited => 7,
            Outcome::SetupFailed => 6,
            Outcome::TimedOut | Outcome::BudgetExceeded => 8,
            Outcome::Cancelled | Outcome::Interrupted | Outcome::Unknown => 9,
        }
    }

    struct Journal {
        file: File,
        lab: String,
        execution: String,
        operation: String,
        sequence: u64,
        bytes: u64,
        started: Instant,
    }

    impl Journal {
        const LIMIT: u64 = 16 * 1024 * 1024;
        // Normal records cannot consume one stop proof and one terminal marker.
        const TERMINAL_RESERVE: u64 = 128 * 1024;

        fn create(path: &Path, lab: &str, execution: &str, operation: &str) -> Result<Self> {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .context("JournalFailure: create event journal")?;
            Ok(Self {
                file,
                lab: lab.into(),
                execution: execution.into(),
                operation: operation.into(),
                sequence: 0,
                bytes: 0,
                started: Instant::now(),
            })
        }

        fn append(&mut self, event: Value, terminal: bool) -> Result<()> {
            let sequence = self
                .sequence
                .checked_add(1)
                .context("JournalFailure: sequence exhausted")?;
            let timestamp_ms: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("JournalFailure: clock before Unix epoch")?
                .as_millis()
                .try_into()?;
            let elapsed_ms: u64 = self.started.elapsed().as_millis().try_into()?;
            let line = serde_json::to_vec(&json!({"protocol":"petri.event/v1","lab_id":self.lab,
                "execution_id":self.execution,"start_operation_id":self.operation,"sequence":sequence,
                "timestamp_ms":timestamp_ms,"elapsed_ms":elapsed_ms,"event":event}))?;
            let bytes = u64::try_from(line.len())?
                .checked_add(1)
                .context("JournalFailure: event size overflow")?;
            ensure!(bytes <= 64 * 1024, "JournalFailure: event exceeds 64 KiB");
            let next = self
                .bytes
                .checked_add(bytes)
                .context("JournalFailure: byte count overflow")?;
            let limit = if terminal {
                Self::LIMIT
            } else {
                Self::LIMIT - Self::TERMINAL_RESERVE
            };
            ensure!(
                next <= limit,
                "JournalFailure: 16 MiB execution journal limit reached; terminal space reserved"
            );
            self.file
                .write_all(&line)
                .and_then(|_| self.file.write_all(b"\n"))
                .and_then(|_| self.file.sync_all())
                .context("JournalFailure: durable native event")?;
            self.sequence = sequence;
            self.bytes = next;
            Ok(())
        }
    }

    fn hash_artifact(path: &Path) -> Result<Value> {
        let mut file = File::open(path)?;
        ensure!(
            file.metadata()?.is_file(),
            "ArtifactInvalid: digest source is not a regular file"
        );
        let mut hash = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
            size = size
                .checked_add(read as u64)
                .context("artifact size overflow")?;
        }
        Ok(json!({"sha256":format!("sha256:{}",hex::encode(hash.finalize())),"size":size}))
    }

    fn bounded_detail(mut detail: String) -> String {
        while detail.len() > 4096 {
            detail.pop();
        }
        detail
    }

    fn seal_result(
        store: &Store,
        record: &ExecutionRecord,
        tool: &NativeToolchain,
        environment_digest: &str,
        terminal: &TerminalResult,
        control: &Path,
    ) -> Result<()> {
        let lab = retry_busy(|| store.load_lab(&record.lab_id))?;
        let mut artifacts = serde_json::Map::new();
        for name in [
            "events.jsonl",
            "stdout.bin",
            "stderr.bin",
            "environment.json",
            "inputs.json",
            "report.json",
        ] {
            let path = control.join(name);
            if path.exists() {
                artifacts.insert(name.into(), hash_artifact(&path)?);
            }
        }
        let binary = std::env::current_exe()?;
        let input_snapshot: Value =
            serde_json::from_slice(&fs::read(control.join("inputs.json"))?)?;
        let manifest = json!({"format":"petri.native-result/v1","finalized":true,"signed":false,
            "lab_id":record.lab_id,"execution_id":record.execution_id,"start_operation_id":record.operation_id,
            "request_digest":record.request_digest,
            "source":{"base_commit":lab.base_commit,"isolated_baseline_digest":lab.baseline_digest},
            "input_snapshot":input_snapshot,
            "runtime":{"package_version":env!("CARGO_PKG_VERSION"),"binary":hash_artifact(&binary)?,
                "backend":"windows-native","profile":"windows-native-python312-lpac/v1","os":windows_native::probe()},
            "environment":{"reference":record.request.environment,"effective_digest":environment_digest,
                "toolchain_manifest":tool.manifest},
            "policy_digest":execution::record_digest("petri.execution-policy/v1",&record.request.policy)?,
            "command_digest":execution::record_digest("petri.command/v1",&record.request.command)?,
            "result":terminal,"artifacts":artifacts,
            "limitations":["Experimental offline CPython candidate; real Windows qualification is separate.",
                "SHA-256 inventory is local integrity metadata, not a digital signature or publisher authentication.",
                "No hard disk quota, full kernel audit, ConPTY, network allowlist or live provider in this profile.",
                "Captured pipe chunks do not establish a total stdout/stderr event order.",
                "Tree stop proof does not certify profile deletion or completed artifact retention cleanup.",
                "Full Windows servicing revision and independent OS qualification report are not collected here.",
                "guardian.stderr is an external diagnostic stream outside this finalized artifact inventory."]});
        let final_path = control.join("result.json");
        ensure!(
            !final_path.exists(),
            "StaleRevision: final result already published"
        );
        let staging_path =
            control.join(format!(".result-{}.staging", uuid::Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .context("JournalFailure: create final result manifest")?;
        file.write_all(&serde_json::to_vec_pretty(&manifest)?)
            .and_then(|_| file.sync_all())
            .context("JournalFailure: persist final result manifest")?;
        drop(file);
        fs::rename(staging_path, final_path)
            .context("JournalFailure: publish final result manifest")
    }

    fn guardian(store: &Store, tools: &NativeToolStore, id: &str, execution: &str) -> Result<()> {
        let control = store.control_dir(id, execution)?;
        let guard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(control.join("guardian.lock"))?;
        guard
            .try_lock_exclusive()
            .context("LabBusy: another guardian owns execution")?;
        let record = store.load_execution(id, execution)?;
        ensure!(
            record.phase == Phase::Preparing && record.result.is_none(),
            "StaleRevision: guardian requires a fresh preparing execution"
        );
        let tool = bound_tool(store, tools, id)?;
        ensure!(
            record.request.command.executable == tool.executable
                && record.request.environment == environment_ref(&tool),
            "Integrity: guardian command differs from verified registered toolchain"
        );
        let lab_dir = store.lab_dir(id)?;
        ensure!(
            record.request.command.argv.len() >= 3
                && record.request.command.argv[0] == "-I"
                && record.request.command.argv[1] == "-S",
            "UnsupportedProfile: guardian only accepts the isolated CPython script profile"
        );
        let script = PathBuf::from(&record.request.command.argv[2]);
        let workspace = store.workspace(id)?.canonicalize()?;
        ensure!(
            record.request.command.cwd == workspace
                && script.is_absolute()
                && script.canonicalize()?.starts_with(&workspace),
            "PolicyDenied: guardian script must remain in its lab workspace"
        );
        // The durable active-execution intent now excludes every stopped-only
        // host mutation; capture the actual input, including prior lab edits.
        let inputs = json!({"format":"petri.execution-inputs/v1",
            "workspace_digest":petri::native_checkpoints::snapshot_digest(&workspace)?,
            "git_digest":petri::native_checkpoints::snapshot_digest(&lab_dir.join("git"))?,
            "script":hash_artifact(&script)?});
        let mut input_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(control.join("inputs.json"))
            .context("JournalFailure: create execution input manifest")?;
        input_file
            .write_all(&serde_json::to_vec(&inputs)?)
            .and_then(|_| input_file.sync_all())
            .context("JournalFailure: persist execution input manifest")?;
        let policy = &record.request.policy;
        let request = NativeRequest {
            lab_id: id.into(),
            execution_id: execution.into(),
            executable: tool.executable.clone(),
            argv: record.request.command.argv.clone(),
            workspace: record.request.command.cwd.clone(),
            temp: lab_dir.join("temp").canonicalize()?,
            profile: lab_dir.join("profile").canonicalize()?,
            toolchain: tool.root.clone(),
            control_dir: control.canonicalize()?,
            environment: record.request.command.environment.clone(),
            limits: NativeLimits {
                memory_bytes: policy.memory_bytes,
                max_processes: policy.max_processes,
                cpu_time_ms: policy.cpu_time_ms,
                wall_time_ms: policy.wall_time_ms,
                stop_timeout_ms: policy.stop_timeout_ms,
                output_bytes: policy.output_bytes,
            },
        };
        let mut events = Journal::create(
            &control.join("events.jsonl"),
            id,
            execution,
            &record.operation_id,
        )?;
        let mut stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(control.join("stdout.bin"))?;
        let mut stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(control.join("stderr.bin"))?;
        let effective_environment = windows_native::effective_environment(&request)?;
        let environment_digest =
            execution::record_digest("petri.effective-environment/v1", &effective_environment)?;
        let mut environment_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(control.join("environment.json"))?;
        environment_file
            .write_all(&serde_json::to_vec(&json!({"digest":environment_digest,
            "environment":effective_environment}))?)
            .and_then(|_| environment_file.sync_all())
            .context("JournalFailure: effective environment manifest")?;
        events.append(json!({"kind":"preparing"}), false)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let input_cancel = cancel.clone();
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            loop {
                match std::io::stdin().read(&mut byte) {
                    Ok(0) | Err(_) => {
                        input_cancel.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(_) => {}
                }
            }
        });
        let finished = Arc::new(AtomicBool::new(false));
        let poll_finished = finished.clone();
        let poll_cancel = cancel.clone();
        let poll_store = store.clone();
        let poll_lab = id.to_string();
        let poll_execution = execution.to_string();
        let monitor_error = Arc::new(Mutex::new(None::<String>));
        let poll_error = monitor_error.clone();
        let monitor = thread::spawn(move || {
            while !poll_finished.load(Ordering::SeqCst) {
                match poll_store.stop_requested(&poll_lab, &poll_execution) {
                    Ok(true) => {
                        poll_cancel.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(false) => {}
                    Err(error) if format!("{error:#}").contains("LabBusy") => {}
                    Err(error) => {
                        if let Ok(mut slot) = poll_error.lock() {
                            *slot = Some(format!("{error:#}"));
                        }
                        poll_cancel.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        let mut stopped_observation = None;
        let mut resumed = false;
        let result = windows_native::run(&request, &cancel, &mut |event| {
            match event {
                NativeEvent::LaunchReady {
                    pid,
                    job_name,
                    lpac,
                } => {
                    events.append(
                        json!({"kind":"ready","pid":pid,"job_name":job_name,"lpac":lpac,
                        "effective_environment_digest":environment_digest}),
                        false,
                    )?;
                    store.record_ready(
                        id,
                        execution,
                        ResourceBinding {
                            pid,
                            job_name,
                            lpac,
                        },
                    )?;
                    if retry_busy(|| store.stop_requested(id, execution))? {
                        cancel.store(true, Ordering::SeqCst);
                        bail!("Cancelled: durable stop request observed before resume");
                    }
                }
                NativeEvent::Resumed { pid } => {
                    resumed = true;
                    events.append(json!({"kind":"running","pid":pid}), false)?;
                    store.record_running(id, execution)?;
                }
                NativeEvent::Output { stream, bytes } => {
                    match stream.as_str() {
                        "stdout" => stdout.write_all(&bytes),
                        "stderr" => stderr.write_all(&bytes),
                        _ => bail!("JournalFailure: unknown native output stream"),
                    }
                    .context("JournalFailure: native output capture")?;
                    events.append(
                        json!({"kind":"output","stream":stream,"bytes":bytes.len()}),
                        false,
                    )?;
                }
                NativeEvent::TreeStopped { active_processes } => {
                    events.append(
                        json!({"kind":"tree_stopped","active_processes":active_processes}),
                        true,
                    )?;
                    stopped_observation = Some(active_processes);
                }
            }
            Ok(())
        });
        finished.store(true, Ordering::SeqCst);
        monitor
            .join()
            .map_err(|_| anyhow::anyhow!("JournalFailure: stop monitor panicked"))?;
        stdout
            .sync_all()
            .and_then(|_| stderr.sync_all())
            .context("JournalFailure: flush output artifacts")?;
        let monitor_error = monitor_error
            .lock()
            .map_err(|_| anyhow::anyhow!("JournalFailure: monitor lock"))?
            .clone();
        let terminal = match result {
            Ok(report) => {
                let report_bytes = serde_json::to_vec_pretty(&report)?;
                let mut report_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(control.join("report.json"))?;
                report_file
                    .write_all(&report_bytes)
                    .and_then(|_| report_file.sync_all())
                    .context("JournalFailure: native report")?;
                let mut outcome = match report.stop_reason {
                    StopReason::Exited => Outcome::Exited,
                    StopReason::UserStop => Outcome::Cancelled,
                    StopReason::WallTime => Outcome::TimedOut,
                    _ => Outcome::BudgetExceeded,
                };
                if !report.tree_stopped {
                    outcome = Outcome::Unknown;
                } else if monitor_error.is_some() {
                    outcome = Outcome::Interrupted;
                }
                TerminalResult { outcome, windows_exit_code: Some(report.exit_code),
                    stop: StopProof { confirmed: report.tree_stopped, active_processes: report.tree_stopped.then_some(0),
                        observation: "Guardian queried its owned Job after termination and observed the reported active-process count.".into() },
                    user_cpu_100ns: report.user_cpu_100ns, peak_job_memory: report.peak_job_memory,
                    stdout_bytes: report.stdout_bytes, stderr_bytes: report.stderr_bytes,
                    detail: monitor_error.map(|error| bounded_detail(format!("Stop monitor failed: {error}"))) }
            }
            Err(error) => TerminalResult {
                outcome: if format!("{error:#}").contains("JournalFailure") {
                    Outcome::Unknown
                } else if stopped_observation == Some(0) {
                    if resumed {
                        Outcome::Interrupted
                    } else {
                        Outcome::SetupFailed
                    }
                } else {
                    Outcome::Unknown
                },
                windows_exit_code: None,
                stop: StopProof {
                    confirmed: stopped_observation == Some(0),
                    active_processes: stopped_observation,
                    observation: if stopped_observation == Some(0) {
                        "Guardian durably observed zero active Job processes during runtime error cleanup.".into()
                    } else {
                        "Native runtime returned an error without a durable terminal Job observation.".into()
                    },
                },
                user_cpu_100ns: 0,
                peak_job_memory: 0,
                stdout_bytes: stdout.metadata()?.len(),
                stderr_bytes: stderr.metadata()?.len(),
                detail: Some(bounded_detail(format!("{error:#}"))),
            },
        };
        events.append(json!({"kind":"terminal","outcome":terminal.outcome,"stop_confirmed":terminal.stop.confirmed,
            "result_manifest":"result.json"}), true)?;
        seal_result(
            store,
            &record,
            &tool,
            &environment_digest,
            &terminal,
            &control,
        )?;
        store.finish_execution(id, execution, terminal)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn journal_bounds_total_bytes_and_keeps_terminal_space() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("events.jsonl");
            let mut journal = Journal::create(&path, "lab-test", "exec-test", "op-test").unwrap();
            let payload = "x".repeat(60_000);
            loop {
                match journal.append(json!({"kind":"fixture","data":payload}), false) {
                    Ok(()) => {}
                    Err(error) => {
                        assert!(format!("{error:#}").contains("16 MiB"));
                        break;
                    }
                }
            }
            let previous = journal.sequence;
            journal
                .append(json!({"kind":"tree_stopped","active_processes":0}), true)
                .unwrap();
            journal
                .append(json!({"kind":"terminal","outcome":"Unknown"}), true)
                .unwrap();
            assert_eq!(journal.sequence, previous + 2);
            assert_eq!(fs::metadata(&path).unwrap().len(), journal.bytes);
            assert!(journal.bytes <= Journal::LIMIT);
            let text = fs::read_to_string(path).unwrap();
            for (index, line) in text.lines().enumerate() {
                let record: Value = serde_json::from_str(line).unwrap();
                assert_eq!(record["sequence"], (index as u64) + 1);
                assert_eq!(record["lab_id"], "lab-test");
                assert_eq!(record["start_operation_id"], "op-test");
            }
        }

        #[test]
        fn oversized_event_does_not_publish_partial_record() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("events.jsonl");
            let mut journal = Journal::create(&path, "lab-test", "exec-test", "op-test").unwrap();
            assert!(journal
                .append(json!({"data":"x".repeat(65_536)}), false)
                .is_err());
            assert_eq!(fs::metadata(&path).unwrap().len(), 0);
            assert_eq!(journal.sequence, 0);
        }
    }
}
