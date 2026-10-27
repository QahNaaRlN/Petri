//! Host-owned native execution records. The v2 store is deliberately outside
//! the legacy `labs/` namespace and never writes legacy `meta.json` records.
//! A durable intent is not proof of a process effect. Recovery never relaunches.
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const STORE_VERSION: u32 = 2;
const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Store {
    pub root: PathBuf,
    #[cfg(windows)]
    _directory_guards: std::sync::Arc<Vec<File>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRef {
    pub kind: String,
    pub id: String,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    pub memory_bytes: u64,
    pub max_processes: u32,
    pub cpu_time_ms: u64,
    pub wall_time_ms: u64,
    pub stop_timeout_ms: u64,
    pub output_bytes: u64,
}

impl Default for ExecutionPolicy {
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

impl ExecutionPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.memory_bytes >= 16 * 1024 * 1024
                && self.max_processes > 0
                && self.cpu_time_ms > 0
                && self.wall_time_ms > 0
                && self.stop_timeout_ms > 0
                && self.output_bytes > 0,
            "InvalidInput: mandatory budgets must be positive, memory >= 16 MiB"
        );
        ensure!(
            self.cpu_time_ms <= i64::MAX as u64 / 10_000
                && self.memory_bytes <= isize::MAX as u64
                && self.output_bytes <= 64 * 1024 * 1024
                && self.stop_timeout_ms <= 60_000
                && self.wall_time_ms <= 24 * 60 * 60 * 1000,
            "UnsupportedPolicy: budget exceeds bounded native candidate limits"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub command: CommandSpec,
    pub policy: ExecutionPolicy,
    pub environment: EnvironmentRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Created,
    Preparing,
    Ready,
    Running,
    Finalizing,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Exited,
    SetupFailed,
    TimedOut,
    Cancelled,
    BudgetExceeded,
    Interrupted,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopState {
    NotRequested,
    Requested,
    Confirmed,
    Unconfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanupState {
    Pending,
    Complete,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBinding {
    pub job_name: String,
    pub pid: u32,
    pub lpac: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopProof {
    pub confirmed: bool,
    pub active_processes: Option<u32>,
    /// A host observation description, never an inferred PID-file assertion.
    pub observation: String,
}

impl StopProof {
    pub fn unconfirmed(detail: &str) -> Self {
        Self {
            confirmed: false,
            active_processes: None,
            observation: detail.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.observation.trim().is_empty() && self.observation.len() <= 4096,
            "InvalidInput: stop proof requires a bounded observation"
        );
        ensure!(
            !self.confirmed || self.active_processes == Some(0),
            "InvalidInput: confirmed stop requires observed zero active processes"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalResult {
    pub outcome: Outcome,
    /// Preserves the entire Windows DWORD, including values > i32::MAX.
    pub windows_exit_code: Option<u32>,
    pub stop: StopProof,
    pub user_cpu_100ns: u64,
    pub peak_job_memory: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub schema_version: u32,
    pub execution_id: String,
    pub lab_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub request: StartRequest,
    pub phase: Phase,
    pub outcome: Option<Outcome>,
    pub stop_state: StopState,
    pub cleanup_state: CleanupState,
    pub binding: Option<ResourceBinding>,
    pub result: Option<TerminalResult>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub recovery_observations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabRecord {
    pub schema_version: u32,
    pub lab_id: String,
    pub metadata_revision: u64,
    pub source: PathBuf,
    pub base_commit: String,
    pub baseline_digest: String,
    pub branch: String,
    pub task_digest: String,
    pub environment: EnvironmentRef,
    pub active_execution: Option<String>,
    pub execution_ids: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationKind {
    Start,
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub schema_version: u32,
    pub operation_id: String,
    pub kind: OperationKind,
    pub request_digest: String,
    pub execution_id: String,
    pub input_revision: u64,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LabState {
    lab: LabRecord,
    executions: BTreeMap<String, ExecutionRecord>,
    operations: BTreeMap<String, OperationRecord>,
}

#[derive(Clone, Debug)]
pub struct BeginExecution {
    /// False means an existing intent; callers MUST NOT launch a process again.
    pub created: bool,
    pub execution: ExecutionRecord,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreMarker {
    format: String,
    version: u32,
}

pub fn new_operation_id() -> String {
    format!("op-{}", Uuid::new_v4().simple())
}

pub fn validate_id(value: &str, prefix: &str) -> Result<()> {
    let tail = value
        .strip_prefix(prefix)
        .context("InvalidInput: unexpected identity prefix")?;
    ensure!(
        tail.len() == 32
            && tail
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "InvalidInput: identity must have 32 lowercase hexadecimal characters"
    );
    Ok(())
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before Unix epoch")?
        .as_millis()
        .try_into()?)
}

/// Canonical JSON for this integer-only protocol. Object keys are sorted by
/// UTF-16 code units (JCS ordering); floating point inputs are rejected.
fn canonical(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<()> {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            output.push(b'{');
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            for (i, key) in keys.into_iter().enumerate() {
                if i != 0 {
                    output.push(b',');
                }
                output.extend(serde_json::to_vec(key)?);
                output.push(b':');
                canonical(&map[key], output)?;
            }
            output.push(b'}');
        }
        Value::Array(values) => {
            output.push(b'[');
            for (i, value) in values.iter().enumerate() {
                if i != 0 {
                    output.push(b',');
                }
                canonical(value, output)?;
            }
            output.push(b']');
        }
        Value::Number(number) => {
            ensure!(
                number.is_i64() || number.is_u64(),
                "InvalidInput: protocol numbers must be integers"
            );
            const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;
            ensure!(
                number.as_u64().is_some_and(|n| n <= MAX_SAFE_INTEGER)
                    || number
                        .as_i64()
                        .is_some_and(|n| n.unsigned_abs() <= MAX_SAFE_INTEGER),
                "InvalidInput: canonical protocol numbers exceed I-JSON safe integer range"
            );
            output.extend(number.to_string().as_bytes());
        }
        _ => output.extend(serde_json::to_vec(value)?),
    }
    Ok(())
}

pub fn record_digest<T: Serialize>(domain: &str, record: &T) -> Result<String> {
    ensure!(
        !domain.is_empty() && !domain.as_bytes().contains(&0),
        "invalid digest domain"
    );
    let mut bytes = Vec::new();
    canonical(&serde_json::to_value(record)?, &mut bytes)?;
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(bytes);
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

fn validate_environment(value: &EnvironmentRef) -> Result<()> {
    ensure!(
        value.kind == "windows-native" && !value.id.is_empty() && value.id.len() <= 128,
        "UnsupportedProfile: expected a tagged Windows native environment"
    );
    let digest = value.digest.strip_prefix("sha256:").unwrap_or("");
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "InvalidInput: environment requires an exact SHA-256 digest"
    );
    Ok(())
}

impl Store {
    pub fn open(home: PathBuf) -> Result<Self> {
        ensure!(
            home.is_absolute(),
            "InvalidInput: explicit home must be absolute"
        );
        if !home.exists() {
            create_private_dir(&home)?;
        }
        reject_alias_chain(&home)?;
        let root = home.join("native-v2");
        if !root.exists() {
            create_private_dir(&root)?;
        }
        reject_alias_chain(&root)?;
        // Compare source/store paths in one native spelling (C:\ versus the
        // canonical \\?\C:\ form must not conceal overlapping directories).
        let root = root.canonicalize()?;
        let marker = root.join("STORE.json");
        if marker.exists() {
            let value: StoreMarker = read_record(&marker)?;
            ensure!(
                value.format == "petri.native-store" && value.version == STORE_VERSION,
                "UnsupportedProfile: incompatible native store, no implicit migration"
            );
        } else {
            ensure!(
                fs::read_dir(&root)?.next().is_none(),
                "RecoveryRequired: unmarked native-v2 directory is not empty"
            );
            write_atomic(
                &marker,
                &StoreMarker {
                    format: "petri.native-store".into(),
                    version: STORE_VERSION,
                },
            )?;
        }
        for part in ["laboratories", "locks", "toolchains"] {
            create_private_dir(&root.join(part))?;
        }
        #[cfg(windows)]
        {
            let mut guards = Vec::new();
            let ancestors: Vec<_> = root.ancestors().collect();
            for ancestor in ancestors.into_iter().rev() {
                guards.push(crate::git::pin_windows_directory(ancestor)?);
            }
            Ok(Self {
                root,
                _directory_guards: std::sync::Arc::new(guards),
            })
        }
        #[cfg(not(windows))]
        Ok(Self { root })
    }

    pub fn lab_dir(&self, lab: &str) -> Result<PathBuf> {
        validate_id(lab, "lab-")?;
        Ok(self.root.join("laboratories").join(lab))
    }

    pub fn workspace(&self, lab: &str) -> Result<PathBuf> {
        Ok(self.lab_dir(lab)?.join("workspace"))
    }

    pub fn control_dir(&self, lab: &str, execution: &str) -> Result<PathBuf> {
        validate_id(execution, "exec-")?;
        let path = self.lab_dir(lab)?.join("blackbox").join(execution);
        ensure!(self.lab_dir(lab)?.is_dir(), "laboratory not found");
        create_private_dir(&path)?;
        Ok(path)
    }

    fn lock(&self, lab: &str) -> Result<File> {
        validate_id(lab, "lab-")?;
        let path = self.root.join("locks").join(lab);
        let file = open_private(&path, false, false)?;
        file.try_lock_exclusive()
            .context("LabBusy: native lab has a controller operation")?;
        Ok(file)
    }

    fn state(&self, lab: &str) -> Result<LabState> {
        let restore_pending =
            match fs::symlink_metadata(self.lab_dir(lab)?.join("restore-intent.json")) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
        ensure!(
            !restore_pending,
            "RecoveryRequired: interrupted checkpoint restore needs explicit reconciliation"
        );
        let state: LabState = read_record(&self.lab_dir(lab)?.join("state.json"))?;
        ensure!(
            state.lab.schema_version == STORE_VERSION && state.lab.lab_id == lab,
            "ArtifactInvalid: native lab metadata identity/version mismatch"
        );
        for (id, record) in &state.executions {
            validate_id(id, "exec-")?;
            ensure!(
                record.execution_id == *id
                    && record.lab_id == lab
                    && record.schema_version == STORE_VERSION,
                "ArtifactInvalid: execution identity/version mismatch"
            );
        }
        for (id, operation) in &state.operations {
            validate_id(id, "op-")?;
            ensure!(
                operation.schema_version == STORE_VERSION
                    && operation.operation_id == *id
                    && state.executions.contains_key(&operation.execution_id),
                "ArtifactInvalid: operation identity/version or execution link mismatch"
            );
        }
        Ok(state)
    }

    fn save(&self, state: &mut LabState) -> Result<()> {
        state.lab.metadata_revision = state
            .lab
            .metadata_revision
            .checked_add(1)
            .context("metadata revision exhausted")?;
        write_atomic(&self.lab_dir(&state.lab.lab_id)?.join("state.json"), state)
    }

    pub fn prepare(
        &self,
        source: &Path,
        task: &str,
        environment: EnvironmentRef,
    ) -> Result<LabRecord> {
        validate_environment(&environment)?;
        ensure!(task.len() <= 64 * 1024, "InvalidInput: task exceeds 64 KiB");
        reject_alias_chain(source)?;
        let source = source.canonicalize()?;
        // `Repository::discover` accepts a nested directory; containment must
        // be checked against the actual checkout, not that caller spelling.
        let repository = git2::Repository::discover(&source)?;
        let source = repository
            .workdir()
            .context("UnsupportedProfile: native candidate requires a non-bare source checkout")?
            .canonicalize()?;
        reject_alias_chain(&source)?;
        ensure!(
            !self.root.starts_with(&source) && !source.starts_with(&self.root),
            "PolicyDenied: native store and source must be disjoint"
        );
        let id = format!("lab-{}", Uuid::new_v4().simple());
        let dir = self.lab_dir(&id)?;
        create_private_dir(&dir)?;
        // Staging failures are retained for explicit inspection, never published
        // as a prepared record and never silently deleted during recovery.
        for part in ["blackbox", "temp", "profile", "checkpoints"] {
            create_private_dir(&dir.join(part))?;
        }
        let branch = format!("petri/{id}");
        let base_commit = crate::git::create_workspace(&source, &dir.join("workspace"), &branch)?;
        let baseline = git2::Repository::open_bare(dir.join("git"))?
            .head()?
            .peel_to_commit()?
            .tree_id()
            .to_string();
        let created_at_ms = now_ms()?;
        let record = LabRecord {
            schema_version: STORE_VERSION,
            lab_id: id,
            metadata_revision: 1,
            source,
            base_commit,
            baseline_digest: record_digest("petri.git-baseline/v1", &baseline)?,
            branch,
            task_digest: record_digest("petri.task/v1", &task)?,
            environment,
            active_execution: None,
            execution_ids: Vec::new(),
            created_at_ms,
        };
        write_atomic(
            &dir.join("state.json"),
            &LabState {
                lab: record.clone(),
                executions: BTreeMap::new(),
                operations: BTreeMap::new(),
            },
        )?;
        Ok(record)
    }

    pub fn load_lab(&self, id: &str) -> Result<LabRecord> {
        let _lock = self.lock(id)?;
        Ok(self.state(id)?.lab)
    }

    pub fn list_labs(&self) -> Result<Vec<LabRecord>> {
        let mut labs = Vec::new();
        for entry in fs::read_dir(self.root.join("laboratories"))? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_dir(),
                "ArtifactInvalid: unexpected native store entry"
            );
            let id = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid lab name"))?;
            labs.push(self.load_lab(&id)?);
        }
        labs.sort_by(|a, b| a.lab_id.cmp(&b.lab_id));
        Ok(labs)
    }

    pub fn load_execution(&self, lab: &str, execution: &str) -> Result<ExecutionRecord> {
        validate_id(execution, "exec-")?;
        let _lock = self.lock(lab)?;
        self.state(lab)?
            .executions
            .remove(execution)
            .context("execution not found")
    }

    pub fn require_stopped(&self, lab: &str) -> Result<()> {
        let _lock = self.lock(lab)?;
        ensure_stopped(&self.state(lab)?)
    }

    /// Holds the mutation lock throughout snapshot/restore/discard work. A
    /// separate `require_stopped` followed by an unlocked mutation is racy.
    pub fn with_stopped_lab<T>(
        &self,
        lab: &str,
        action: impl FnOnce(&Path, &LabRecord) -> Result<T>,
    ) -> Result<T> {
        let _lock = self.lock(lab)?;
        let state = self.state(lab)?;
        ensure_stopped(&state)?;
        action(&self.lab_dir(lab)?, &state.lab)
    }

    pub fn begin_execution(
        &self,
        lab: &str,
        operation: &str,
        request: &StartRequest,
    ) -> Result<BeginExecution> {
        validate_id(operation, "op-")?;
        request.policy.validate()?;
        validate_environment(&request.environment)?;
        validate_command(&request.command)?;
        let digest = record_digest("petri.start-request/v1", request)?;
        let _lock = self.lock(lab)?;
        let mut state = self.state(lab)?;
        if let Some(previous) = state.operations.get(operation) {
            ensure!(
                previous.kind == OperationKind::Start && previous.request_digest == digest,
                "IdempotencyConflict: operation ID already binds a different request"
            );
            let execution = state
                .executions
                .get(&previous.execution_id)
                .context("ArtifactInvalid: operation's execution missing")?
                .clone();
            return Ok(BeginExecution {
                created: false,
                execution,
            });
        }
        ensure_stopped(&state)?;
        ensure!(
            request.environment == state.lab.environment,
            "ArtifactInvalid: environment differs from lab"
        );
        let expected_workspace = self.workspace(lab)?.canonicalize()?;
        ensure!(
            request.command.cwd == expected_workspace,
            "PolicyDenied: first native profile cwd must be lab workspace"
        );
        let id = format!("exec-{}", Uuid::new_v4().simple());
        let time = now_ms()?;
        let record = ExecutionRecord {
            schema_version: STORE_VERSION,
            execution_id: id.clone(),
            lab_id: lab.into(),
            operation_id: operation.into(),
            request_digest: digest.clone(),
            request: request.clone(),
            phase: Phase::Preparing,
            outcome: None,
            stop_state: StopState::NotRequested,
            cleanup_state: CleanupState::Pending,
            binding: None,
            result: None,
            created_at_ms: time,
            updated_at_ms: time,
            recovery_observations: Vec::new(),
        };
        let operation = OperationRecord {
            schema_version: STORE_VERSION,
            operation_id: operation.into(),
            kind: OperationKind::Start,
            request_digest: digest,
            execution_id: id.clone(),
            input_revision: state.lab.metadata_revision,
            created_at_ms: time,
        };
        state
            .operations
            .insert(operation.operation_id.clone(), operation);
        state.executions.insert(id.clone(), record.clone());
        state.lab.execution_ids.push(id.clone());
        state.lab.active_execution = Some(id);
        self.save(&mut state)?;
        Ok(BeginExecution {
            created: true,
            execution: record,
        })
    }

    pub fn record_ready(
        &self,
        lab: &str,
        execution: &str,
        binding: ResourceBinding,
    ) -> Result<ExecutionRecord> {
        ensure!(
            binding.pid != 0
                && binding.lpac
                && !binding.job_name.is_empty()
                && binding.job_name.len() <= 512,
            "IsolationUnavailable: a native LPAC/job binding is required"
        );
        self.update(lab, execution, |record| {
            if record.phase == Phase::Ready && record.binding.as_ref() == Some(&binding) {
                return Ok(());
            }
            ensure!(
                record.phase == Phase::Preparing,
                "StaleRevision: execution is not preparing"
            );
            record.binding = Some(binding);
            record.phase = Phase::Ready;
            Ok(())
        })
    }

    pub fn record_running(&self, lab: &str, execution: &str) -> Result<ExecutionRecord> {
        self.update(lab, execution, |record| {
            if record.phase == Phase::Running {
                return Ok(());
            }
            ensure!(
                record.phase == Phase::Ready && record.binding.is_some(),
                "StaleRevision: execution was not ready"
            );
            record.phase = Phase::Running;
            Ok(())
        })
    }

    pub fn request_stop(
        &self,
        lab: &str,
        execution: &str,
        operation: &str,
    ) -> Result<ExecutionRecord> {
        validate_id(operation, "op-")?;
        validate_id(execution, "exec-")?;
        let digest = record_digest("petri.stop-request/v1", &(lab, execution))?;
        let _lock = self.lock(lab)?;
        let mut state = self.state(lab)?;
        if let Some(previous) = state.operations.get(operation) {
            ensure!(
                previous.kind == OperationKind::Stop && previous.request_digest == digest,
                "IdempotencyConflict: stop operation ID binds another request"
            );
            return state
                .executions
                .get(execution)
                .cloned()
                .context("execution not found");
        }
        let time = now_ms()?;
        let record = state
            .executions
            .get_mut(execution)
            .context("execution not found")?;
        if record.stop_state != StopState::Confirmed {
            record.stop_state = StopState::Requested;
            record.updated_at_ms = time;
        }
        let result = record.clone();
        state.operations.insert(
            operation.into(),
            OperationRecord {
                schema_version: STORE_VERSION,
                operation_id: operation.into(),
                kind: OperationKind::Stop,
                request_digest: digest,
                execution_id: execution.into(),
                input_revision: state.lab.metadata_revision,
                created_at_ms: time,
            },
        );
        self.save(&mut state)?;
        Ok(result)
    }

    pub fn stop_requested(&self, lab: &str, execution: &str) -> Result<bool> {
        Ok(self.load_execution(lab, execution)?.stop_state == StopState::Requested)
    }

    pub fn finish_execution(
        &self,
        lab: &str,
        execution: &str,
        result: TerminalResult,
    ) -> Result<ExecutionRecord> {
        result.stop.validate()?;
        ensure!(
            result.stop.confirmed
                || matches!(result.outcome, Outcome::Unknown | Outcome::Interrupted),
            "StopUnconfirmed: ordinary outcomes require a confirmed tree-stop proof; report Unknown instead"
        );
        ensure!(
            result.outcome != Outcome::Exited || result.windows_exit_code.is_some(),
            "InvalidInput: exited outcome must preserve the DWORD exit code"
        );
        ensure!(
            result.detail.as_ref().is_none_or(|s| s.len() <= 4096),
            "result detail exceeds bound"
        );
        let _lock = self.lock(lab)?;
        let mut state = self.state(lab)?;
        let record = state
            .executions
            .get_mut(execution)
            .context("execution not found")?;
        if let Some(previous) = &record.result {
            ensure!(
                previous == &result,
                "IdempotencyConflict: immutable execution result differs"
            );
            return Ok(record.clone());
        }
        ensure!(
            result.outcome != Outcome::Exited
                || (matches!(record.phase, Phase::Running | Phase::Finalizing)
                    && record.binding.is_some()),
            "StaleRevision: workload exit requires a recorded native binding and observed resume"
        );
        record.phase = Phase::Terminal;
        record.outcome = Some(result.outcome);
        record.stop_state = if result.stop.confirmed {
            StopState::Confirmed
        } else {
            StopState::Unconfirmed
        };
        // Zero job members proves tree stop, not removal of the native profile,
        // temporary ACL grants, or retained artifacts. Cleanup stays separate.
        record.cleanup_state = CleanupState::Pending;
        record.updated_at_ms = now_ms()?;
        let confirmed = result.stop.confirmed;
        record.result = Some(result);
        let receipt = record.clone();
        if confirmed && state.lab.active_execution.as_deref() == Some(execution) {
            state.lab.active_execution = None;
        }
        self.save(&mut state)?;
        Ok(receipt)
    }

    /// Explicit conservative reconciliation after controller loss. It records an
    /// observation without modifying or inventing any immutable terminal result.
    /// It is NOT a kill operation and cannot establish that an OS job stopped.
    pub fn recover_interrupted(&self, lab: &str) -> Result<Option<ExecutionRecord>> {
        let _lock = self.lock(lab)?;
        let mut state = self.state(lab)?;
        let Some(id) = state.lab.active_execution.clone() else {
            return Ok(None);
        };
        let record = state
            .executions
            .get_mut(&id)
            .context("ArtifactInvalid: active execution missing")?;
        if record.result.is_none() {
            record.phase = Phase::Terminal;
            record.outcome = Some(Outcome::Unknown);
            record.stop_state = StopState::Unconfirmed;
            record.cleanup_state = CleanupState::Pending;
            let observation = "Controller recovery: no durable terminal receipt; OS effect and descendant stop are unknown. No automatic rerun.";
            if record
                .recovery_observations
                .last()
                .is_none_or(|last| last != observation)
            {
                record.recovery_observations.push(observation.into());
            }
            record.updated_at_ms = now_ms()?;
        }
        let result = record.clone();
        self.save(&mut state)?;
        Ok(Some(result))
    }

    fn update(
        &self,
        lab: &str,
        execution: &str,
        change: impl FnOnce(&mut ExecutionRecord) -> Result<()>,
    ) -> Result<ExecutionRecord> {
        validate_id(execution, "exec-")?;
        let _lock = self.lock(lab)?;
        let mut state = self.state(lab)?;
        ensure!(
            state.lab.active_execution.as_deref() == Some(execution),
            "StaleRevision: execution is not active"
        );
        let record = state
            .executions
            .get_mut(execution)
            .context("execution not found")?;
        ensure!(
            record.result.is_none(),
            "StaleRevision: execution is sealed"
        );
        change(record)?;
        record.updated_at_ms = now_ms()?;
        let result = record.clone();
        self.save(&mut state)?;
        Ok(result)
    }
}

fn ensure_stopped(state: &LabState) -> Result<()> {
    ensure!(
        state.lab.active_execution.is_none(),
        "RecoveryRequired: active or unknown execution prevents mutation/relaunch"
    );
    for execution in state.executions.values() {
        ensure!(
            execution.phase == Phase::Terminal && execution.stop_state == StopState::Confirmed,
            "RecoveryRequired: execution has no confirmed tree-stop proof"
        );
    }
    Ok(())
}

fn validate_command(command: &CommandSpec) -> Result<()> {
    ensure!(
        command.executable.is_absolute() && command.cwd.is_absolute(),
        "InvalidInput: executable/cwd must be explicit absolute paths"
    );
    ensure!(
        command.argv.len() <= 256 && command.environment.len() <= 64,
        "InvalidInput: argument/environment count exceeds bound"
    );
    let mut bytes = 0usize;
    for text in command.argv.iter().chain(command.environment.values()) {
        ensure!(
            !text.contains('\0'),
            "InvalidInput: NUL in argument/environment"
        );
        bytes = bytes
            .checked_add(text.len())
            .context("request length overflow")?;
    }
    for key in command.environment.keys() {
        ensure!(
            !key.is_empty() && !key.contains(['=', '\0']) && key.len() <= 256,
            "InvalidInput: invalid environment key"
        );
        bytes += key.len();
    }
    ensure!(bytes <= 1024 * 1024, "InvalidInput: request exceeds 1 MiB");
    Ok(())
}

/// Does not change permissions outside Petri-owned leaf directories.
pub fn create_private_dir(path: &Path) -> Result<()> {
    reject_alias_chain(path)?;
    #[cfg(windows)]
    {
        crate::windows_native::secure_private_dir(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("UnsupportedPlatform: native store requires private directory support");
    reject_alias_chain(path)
}

fn reject_alias_chain(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "InvalidInput: storage path must be absolute"
    );
    let mut current = PathBuf::new();
    for component in path.components() {
        use std::path::Component;
        ensure!(
            !matches!(component, Component::ParentDir | Component::CurDir),
            "PolicyDenied: ambiguous storage path"
        );
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "PolicyDenied: symlink in storage path"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "PolicyDenied: reparse point in storage path"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn open_private(path: &Path, new: bool, read: bool) -> Result<File> {
    reject_alias_chain(path)?;
    let mut options = OpenOptions::new();
    options.read(read).write(!read);
    if new {
        options.create_new(true);
    } else if !read {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "PolicyDenied: metadata/lock is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(metadata.nlink() == 1, "PolicyDenied: hardlinked store file");
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "PolicyDenied: reparse store file"
        );
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "PolicyDenied: cannot inspect native store file identity: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            info.nNumberOfLinks == 1,
            "PolicyDenied: hardlinked native store file"
        );
    }
    Ok(file)
}

fn read_record<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let mut file = open_private(path, false, true)?;
    ensure!(
        file.metadata()?.len() <= MAX_RECORD_BYTES,
        "ArtifactInvalid: metadata exceeds limit"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "ArtifactInvalid: metadata grew beyond limit"
    );
    serde_json::from_slice(&bytes).context("ArtifactInvalid: invalid native store record")
}

fn write_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "JournalFailed: native metadata exceeds reserved record limit"
    );
    let parent = path.parent().context("store file has no parent")?;
    reject_alias_chain(parent)?;
    let temp = parent.join(format!(".petri-{}.tmp", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = open_private(&temp, true, false)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            #[link(name = "kernel32")]
            extern "system" {
                fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
            }
            let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            ensure!(
                unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } != 0,
                "JournalFailed: atomic replacement failed: {}",
                std::io::Error::last_os_error()
            );
        }
        #[cfg(not(windows))]
        {
            fs::rename(&temp, path)?;
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Repository, Signature};
    use tempfile::TempDir;

    fn fixture() -> (TempDir, Store, LabRecord, StartRequest) {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        let repo = Repository::init(&source).unwrap();
        fs::write(source.join("task.py"), "print('fixture')\n").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("task.py")).unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = Signature::now("fixture", "fixture@invalid.local").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "initial", &tree, &[])
            .unwrap();
        let store = Store::open(temp.path().join("private")).unwrap();
        let environment = EnvironmentRef {
            kind: "windows-native".into(),
            id: "fixture".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
        };
        let lab = store
            .prepare(&source, "task is not stored verbatim", environment.clone())
            .unwrap();
        let request = StartRequest {
            command: CommandSpec {
                executable: temp.path().join("python.exe"),
                argv: vec!["-I".into(), "-S".into(), "task.py".into()],
                cwd: store
                    .workspace(&lab.lab_id)
                    .unwrap()
                    .canonicalize()
                    .unwrap(),
                environment: BTreeMap::new(),
            },
            policy: ExecutionPolicy::default(),
            environment,
        };
        (temp, store, lab, request)
    }

    #[test]
    fn retry_returns_same_execution_and_conflicting_request_never_relaunches() {
        let (_temp, store, lab, mut request) = fixture();
        let op = new_operation_id();
        let first = store.begin_execution(&lab.lab_id, &op, &request).unwrap();
        let repeat = store.begin_execution(&lab.lab_id, &op, &request).unwrap();
        assert!(first.created);
        assert!(!repeat.created);
        assert_eq!(first.execution.execution_id, repeat.execution.execution_id);
        request.command.argv.push("other".into());
        assert!(store
            .begin_execution(&lab.lab_id, &op, &request)
            .unwrap_err()
            .to_string()
            .contains("IdempotencyConflict"));
        assert_eq!(store.load_lab(&lab.lab_id).unwrap().execution_ids.len(), 1);
    }

    #[test]
    fn interrupted_start_stays_unknown_and_blocks_mutation() {
        let (_temp, store, lab, request) = fixture();
        let begin = store
            .begin_execution(&lab.lab_id, &new_operation_id(), &request)
            .unwrap();
        let recovered = store.recover_interrupted(&lab.lab_id).unwrap().unwrap();
        assert_eq!(recovered.execution_id, begin.execution.execution_id);
        assert_eq!(recovered.outcome, Some(Outcome::Unknown));
        assert_eq!(recovered.stop_state, StopState::Unconfirmed);
        assert!(store.require_stopped(&lab.lab_id).is_err());
        assert!(store
            .begin_execution(&lab.lab_id, &new_operation_id(), &request)
            .is_err());
    }

    #[test]
    fn dword_result_preserved_and_not_replaced() {
        let (_temp, store, lab, request) = fixture();
        let start = store
            .begin_execution(&lab.lab_id, &new_operation_id(), &request)
            .unwrap();
        let id = &start.execution.execution_id;
        store
            .record_ready(
                &lab.lab_id,
                id,
                ResourceBinding {
                    job_name: "test-job".into(),
                    pid: 42,
                    lpac: true,
                },
            )
            .unwrap();
        store.record_running(&lab.lab_id, id).unwrap();
        let mut result = TerminalResult {
            outcome: Outcome::Exited,
            windows_exit_code: Some(0xc000_0005),
            stop: StopProof {
                confirmed: true,
                active_processes: Some(0),
                observation: "test oracle observed zero".into(),
            },
            user_cpu_100ns: 1,
            peak_job_memory: 1024,
            stdout_bytes: 0,
            stderr_bytes: 0,
            detail: None,
        };
        store
            .finish_execution(&lab.lab_id, id, result.clone())
            .unwrap();
        assert_eq!(
            store
                .load_execution(&lab.lab_id, id)
                .unwrap()
                .result
                .as_ref()
                .unwrap()
                .windows_exit_code,
            Some(0xc000_0005)
        );
        store
            .finish_execution(&lab.lab_id, id, result.clone())
            .unwrap();
        store.require_stopped(&lab.lab_id).unwrap();
        result.windows_exit_code = Some(0);
        assert!(store
            .finish_execution(&lab.lab_id, id, result)
            .unwrap_err()
            .to_string()
            .contains("IdempotencyConflict"));
    }

    #[test]
    fn legacy_namespace_and_metadata_are_never_written() {
        let (temp, store, lab, _) = fixture();
        assert!(!temp.path().join("private/labs").exists());
        assert!(!store
            .lab_dir(&lab.lab_id)
            .unwrap()
            .join("meta.json")
            .exists());
        let legacy = crate::labs::Store::open(temp.path().join("private")).unwrap();
        assert!(legacy.load(&lab.lab_id).is_err());
        assert!(store.load_lab(&lab.lab_id).is_ok());
    }

    #[test]
    fn stop_proof_cannot_confuse_root_exit_with_empty_job() {
        assert!(StopProof {
            confirmed: true,
            active_processes: Some(1),
            observation: "root exited".into()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn canonical_digest_orders_keys_and_rejects_unsafe_integers() {
        let a = serde_json::json!({"b": 2, "a": 1});
        let b = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(
            record_digest("test/v1", &a).unwrap(),
            record_digest("test/v1", &b).unwrap()
        );
        assert_ne!(
            record_digest("test/v1", &a).unwrap(),
            record_digest("test/v2", &a).unwrap()
        );
        assert!(record_digest("test/v1", &((1u64 << 53) - 1)).is_ok());
        assert!(record_digest("test/v1", &(1u64 << 53)).is_err());
        assert!(record_digest("test/v1", &i64::MIN).is_err());
        assert!(record_digest("test/v1", &1.5f64).is_err());
    }

    #[test]
    fn stopped_mutation_keeps_lock_for_entire_effect() {
        let (_temp, store, lab, request) = fixture();
        store
            .with_stopped_lab(&lab.lab_id, |_, _| {
                let error = store
                    .begin_execution(&lab.lab_id, &new_operation_id(), &request)
                    .unwrap_err();
                assert!(error.to_string().contains("LabBusy"));
                Ok(())
            })
            .unwrap();
        assert!(
            store
                .begin_execution(&lab.lab_id, &new_operation_id(), &request)
                .unwrap()
                .created
        );
    }

    #[test]
    fn unconfirmed_stop_cannot_seal_success_or_unlock_workspace() {
        let (_temp, store, lab, request) = fixture();
        let start = store
            .begin_execution(&lab.lab_id, &new_operation_id(), &request)
            .unwrap();
        let id = &start.execution.execution_id;
        let mut result = TerminalResult {
            outcome: Outcome::Exited,
            windows_exit_code: Some(0),
            stop: StopProof::unconfirmed("root process exit does not prove tree stop"),
            user_cpu_100ns: 0,
            peak_job_memory: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            detail: None,
        };
        assert!(store
            .finish_execution(&lab.lab_id, id, result.clone())
            .is_err());
        result.outcome = Outcome::Unknown;
        store.finish_execution(&lab.lab_id, id, result).unwrap();
        assert!(store.require_stopped(&lab.lab_id).is_err());
        assert!(store
            .begin_execution(&lab.lab_id, &new_operation_id(), &request)
            .is_err());
    }

    #[test]
    fn interrupted_restore_marker_blocks_even_a_fresh_start() {
        let (_temp, store, lab, request) = fixture();
        fs::write(
            store
                .lab_dir(&lab.lab_id)
                .unwrap()
                .join("restore-intent.json"),
            b"pending",
        )
        .unwrap();
        assert!(store
            .load_lab(&lab.lab_id)
            .unwrap_err()
            .to_string()
            .contains("RecoveryRequired"));
        assert!(store
            .begin_execution(&lab.lab_id, &new_operation_id(), &request)
            .is_err());
        assert!(store.with_stopped_lab(&lab.lab_id, |_, _| Ok(())).is_err());
    }

    #[test]
    fn nested_repository_argument_cannot_hide_store_inside_source_checkout() {
        let (temp, _store, lab, request) = fixture();
        let nested = lab.source.join("nested");
        fs::create_dir(&nested).unwrap();
        let unsafe_store = Store::open(lab.source.join("petri-data")).unwrap();
        let error = unsafe_store
            .prepare(&nested, "task", request.environment)
            .unwrap_err();
        assert!(error.to_string().contains("disjoint"));
        assert!(temp.path().join("source/task.py").exists());
    }

    #[test]
    fn exit_zero_cannot_invent_a_workload_that_was_never_resumed() {
        let (_temp, store, lab, request) = fixture();
        let start = store
            .begin_execution(&lab.lab_id, &new_operation_id(), &request)
            .unwrap();
        let error = store
            .finish_execution(
                &lab.lab_id,
                &start.execution.execution_id,
                TerminalResult {
                    outcome: Outcome::Exited,
                    windows_exit_code: Some(0),
                    stop: StopProof {
                        confirmed: true,
                        active_processes: Some(0),
                        observation: "no processes".into(),
                    },
                    user_cpu_100ns: 0,
                    peak_job_memory: 0,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    detail: None,
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("observed resume"));
    }
}
