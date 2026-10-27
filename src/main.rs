use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use petri::{
    git,
    labs::{self, Store},
    observer,
    policy::Config,
    runtime, stacks,
};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    time::Instant,
};

#[derive(Parser)]
#[command(
    name = "petri",
    version,
    about = "Isolated laboratories for coding agents. Unavailable security features fail closed."
)]
struct Cli {
    /// Private state directory (default: platform application data directory).
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Create an isolated snapshot of repository HEAD; provide an explicit command or --prepare.
    Create {
        task: String,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        stack: Option<String>,
        #[arg(long)]
        prepare: bool,
        #[arg(long, conflicts_with = "prepare")]
        detach: bool,
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Run an explicit agent/program in an existing laboratory, with network disabled.
    Run {
        id: String,
        #[arg(long)]
        detach: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    List {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        all: bool,
    },
    Diff {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Output recorded pipe output. Replay timing supported, PTY/interactive input is not recorded.
    Logs {
        id: String,
        #[arg(long)]
        replay: bool,
        #[arg(long)]
        follow: bool,
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
    /// Publish results to a review branch; never moves main or performs a network push.
    Merge {
        id: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        as_pr: bool,
    },
    Commit {
        id: String,
        #[arg(short, long)]
        message: String,
    },
    Discard {
        id: String,
    },
    /// Create an IDE symlink to a workspace, outside Git metadata.
    Link {
        id: String,
        #[arg(long, default_value = ".")]
        project: PathBuf,
    },
    Stack {
        #[command(subcommand)]
        command: StackAction,
    },
    Doctor,
    Vault {
        #[command(subcommand)]
        command: VaultAction,
    },
    Secret {
        #[command(subcommand)]
        command: SecretAction,
    },
    Compat {
        #[command(subcommand)]
        command: CompatAction,
    },
    Import {
        format: String,
    },
    Dashboard,
    #[command(hide = true)]
    Supervise {
        id: String,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    #[command(hide = true)]
    Sandbox {
        id: String,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}
#[derive(Subcommand)]
enum StackAction {
    List,
    ImportRootfs { name: String, path: PathBuf },
    ImportOci { name: String, path: PathBuf },
    Rm { name: String },
    Pull { name: String },
    Build { path: PathBuf },
}
#[derive(Subcommand)]
enum VaultAction {
    Status,
    Broker,
    Push,
    Sync {
        #[arg(long)]
        backend: String,
    },
}
#[derive(Subcommand)]
enum SecretAction {
    List,
    Add { name: String },
    Allow { name: String },
}
#[derive(Subcommand)]
enum CompatAction {
    Up,
    Docker {
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn main() {
    if let Err(e) = entry() {
        eprintln!("petri: {e:#}");
        std::process::exit(1)
    }
}
fn entry() -> Result<()> {
    let cli = Cli::parse();
    let home = cli
        .home
        .or_else(|| std::env::var_os("PETRI_HOME").map(PathBuf::from))
        .or_else(|| {
            directories::ProjectDirs::from("dev", "Petri", "petri")
                .map(|p| p.data_local_dir().to_path_buf())
        })
        .context("cannot determine application state directory; specify --home")?;
    let store = Store::open(home)?;
    match cli.command {
        Action::Create{task,repo,stack,prepare,detach,command}=>{
            if !prepare&&command.is_empty(){bail!("provide -- <program> [args] or --prepare; agent adapters are not bundled")}
            if prepare&&!command.is_empty(){bail!("--prepare cannot be combined with a command")}
            let config=Config::load(&repo.join("petri.yaml"))?;
            let stack=stack.or_else(||config.stack.clone()).context("specify --stack or set stack in petri.yaml; import a rootfs or OCI layout first")?;
            let lab=store.create(&repo,task,&stack,config)?;
            println!("{}",lab.id);
            if !prepare { execute(&store,&lab.id,command,detach)?; }
        }
        Action::Run{id,detach,command}=>execute(&store,&id,command,detach)?,
        Action::Supervise{id,command}=>supervise(&store,&id,command)?,
        Action::Sandbox{id,command}=>{
            let lab=store.load(&id)?;lab.config.validate()?;stacks::verify(&lab.stack)?;let dir=store.lab_dir(&id)?;
            let code=runtime::run(&runtime::RuntimeOptions{rootfs:lab.stack.rootfs,workspace:dir.join("workspace"),logs:dir.join("blackbox"),command,memory_bytes:lab.config.policy.memory_bytes,cpu_seconds:lab.config.policy.cpu_seconds,max_processes:lab.config.policy.max_processes})?;
            std::process::exit(code);
        }
        Action::List{json,all:_}=>{
            let labs=store.list()?;if json{println!("{}",serde_json::to_string_pretty(&labs)?)}else{for lab in labs{println!("{}\t{}\t{}\t{}",lab.id,lab.status,lab.stack.name,lab.task)}}
        }
        Action::Diff{id,json}=>{
            let _guard=store.lock(&id)?;let lab=store.load(&id)?;store.require_stopped(&lab)?;
            let diff=git::diff(&store.lab_dir(&id)?.join("workspace"))?;
            if json{println!("{}",serde_json::json!({"id":id,"diff":diff}))}else{print!("{diff}")}
        }
        Action::Logs{id,replay,follow}=>{
            if follow{bail!("Unsupported: logs --follow; foreground execution streams output live")}
            let dir=store.lab_dir(&id)?.join("blackbox");
            if replay{replay_recording(&dir)?}else{print!("{}",observer::replay(&dir)?)}
        }
        Action::Checkpoint{id,message}=>println!("{}",store.checkpoint(&id,&message)?),
        Action::Restore{id,checkpoint}=>store.restore(&id,&checkpoint)?,
        Action::Commit{id,message}=>{
            let _guard=store.lock(&id)?;let lab=store.load(&id)?;store.require_stopped(&lab)?;
            let message=format!("{message}\n\npetri-stack: {}\npetri-model: unspecified\npetri-prompt-hash: {}",lab.stack_hash,lab.prompt_hash);
            println!("{}",git::commit(&store.lab_dir(&id)?.join("workspace"),&message)?);
        }
        Action::Merge{id,yes,as_pr}=>{
            if as_pr{bail!("Unsupported: remote PR creation; publish local review branch then open a PR explicitly")}
            if !yes{bail!("manual confirmation required: review petri diff, then use petri merge <id> --yes")}
            let _guard=store.lock(&id)?;let lab=store.load(&id)?;store.require_stopped(&lab)?;
            let branch=git::merge(&lab.source,&store.lab_dir(&id)?.join("workspace"),&lab.base_commit)?;
            observer::event(&store.lab_dir(&id)?.join("blackbox"),"review_branch_published",serde_json::json!({"branch":branch}))?;
            println!("Published {branch}; source working tree and main were not changed.");
        }
        Action::Discard{id}=>store.discard(&id)?,
        Action::Link{id,project}=>{
            store.load(&id)?;let workspace=store.lab_dir(&id)?.join("workspace").canonicalize()?;
            let parent=project.join(".petri/labs");fs::create_dir_all(&parent)?;
            #[cfg(unix)] std::os::unix::fs::symlink(workspace,parent.join(id))?;
            #[cfg(not(unix))] {let _=workspace;let _=parent;bail!("Unsupported: IDE symlink on this platform");}
        }
        Action::Stack{command}=>{
            let dir=store.home.join("stacks");match command{
                StackAction::List=>println!("{}",serde_json::to_string_pretty(&stacks::list(&dir)?)?),
                StackAction::ImportRootfs{name,path}=>println!("{}",serde_json::to_string_pretty(&stacks::import_rootfs(&dir,&name,&path)?)?),
                StackAction::ImportOci{name,path}=>println!("{}",serde_json::to_string_pretty(&stacks::import_oci(&dir,&name,&path)?)?),
                StackAction::Rm{name}=>stacks::remove(&dir,&name)?,
                StackAction::Pull{name}=>bail!("Unsupported: registry pull for {name}; use verified offline OCI import"),
                StackAction::Build{path}=>bail!("Unsupported: stack build from {}; import a prepared rootfs or OCI layout",path.display()),
            }
        }
        Action::Doctor=>println!("{}",serde_json::to_string_pretty(&runtime::doctor())?),
        Action::Vault{command:VaultAction::Status}=>println!("{}",serde_json::json!({"available":false,"reason":"Unsupported: OS keychain, biometric authorization and scoped signing broker are not implemented; no secrets accepted"})),
        Action::Secret{..}|Action::Vault{..}=>bail!("Unsupported: Vault has no secure provider backend yet; no credential was accepted or issued"),
        Action::Compat{command:CompatAction::Up}=>petri::compat::serve(&store)?,
        Action::Compat{command:CompatAction::Docker{..}}=>bail!("Unsupported: Docker CLI shim; only read-only API endpoints are available via compat up"),
        Action::Import{format}=>bail!("Unsupported: {format} migration; export OCI separately and use stack import-oci"),
        Action::Dashboard=>bail!("Unsupported: dashboard; use petri list --json"),
    }
    Ok(())
}
fn execute(store: &Store, id: &str, command: Vec<String>, detach: bool) -> Result<()> {
    if detach {
        let lab = store.load(id)?;
        store.require_stopped(&lab)?;
        let log = labs::private_file(&store.lab_dir(id)?.join("supervisor.stderr"), true)?;
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--home")
            .arg(&store.home)
            .arg("supervise")
            .arg(id)
            .arg("--")
            .args(command)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()?;
        // Only the detached supervisor acquires the lock; the launcher must not race it.
        println!("Supervisor spawned: {}", child.id());
        let _ = &mut child;
        Ok(())
    } else {
        supervise(store, id, command)
    }
}
fn supervise(store: &Store, id: &str, command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        bail!("empty command")
    }
    let _guard = store.lock(id)?;
    let mut lab = store.load(id)?;
    store.require_stopped(&lab)?;
    lab.config.validate()?;
    let dir = store.lab_dir(id)?;
    let logs = dir.join("blackbox");
    lab.status = "Starting".into();
    lab.command = command.clone();
    lab.exit_code = None;
    store.save(&lab)?;
    use std::io::Write;
    let mut pid = labs::private_file(&dir.join("supervisor.pid"), true)?;
    writeln!(pid, "{}", std::process::id())?;
    observer::event(
        &logs,
        "run_starting",
        serde_json::json!({"argc":command.len(),"network":"none"}),
    )?;
    let result = (|| -> Result<i32> {
        let mut recording_offset = 0.0;
        let cast = logs.join("terminal.cast");
        if cast.exists() {
            if fs::metadata(&cast)?.len() > 64 * 1024 * 1024 {
                bail!("recording exceeds 64 MiB; archive it before another run")
            }
            for (i, line) in BufReader::new(fs::File::open(&cast)?).lines().enumerate() {
                if i > 0 {
                    let v: serde_json::Value = serde_json::from_str(&line?)?;
                    recording_offset = v[0].as_f64().context("invalid recording time")? + 0.001;
                }
            }
        }
        observer::record_output(&logs, "", recording_offset)?;
        let mut sandbox = Command::new(std::env::current_exe()?);
        sandbox
            .arg("--home")
            .arg(&store.home)
            .arg("sandbox")
            .arg(id)
            .arg("--")
            .args(&command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // ADR-016: close the supervisor->sandbox death-signal gap before exec.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let supervisor_pid = std::process::id() as i32;
            unsafe {
                sandbox.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != supervisor_pid {
                        return Err(std::io::Error::other("supervisor died during spawn"));
                    }
                    Ok(())
                });
            }
        }
        let mut child = sandbox.spawn()?;
        // This status indicates a supervised process, not a successful sandbox setup. Failures become Failed.
        lab.status = "Running".into();
        store.save(&lab)?;
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(64);
        fn read_output<R: std::io::Read + Send + 'static>(
            reader: R,
            tx: mpsc::SyncSender<Vec<u8>>,
        ) {
            std::thread::spawn(move || {
                let mut reader = reader;
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        read_output(child.stdout.take().context("stdout pipe")?, tx.clone());
        read_output(child.stderr.take().context("stderr pipe")?, tx.clone());
        drop(tx);
        let start = Instant::now();
        let mut recording_error = None;
        for bytes in rx {
            if let Err(e) = std::io::stdout().write_all(&bytes) {
                recording_error = Some(anyhow::Error::from(e));
                break;
            }
            let text = String::from_utf8_lossy(&bytes);
            if let Err(e) = observer::record_output(
                &logs,
                &text,
                recording_offset + start.elapsed().as_secs_f64(),
            ) {
                recording_error = Some(e);
                break;
            }
        }
        if let Some(e) = recording_error {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.context("recording failed; execution stopped"));
        }
        let status = child.wait()?;
        Ok(status.code().unwrap_or(128))
    })();
    lab.exit_code = Some(result.as_ref().copied().unwrap_or(1));
    lab.status = if lab.exit_code == Some(0) {
        "Exited"
    } else {
        "Failed"
    }
    .into();
    store.save(&lab)?;
    let _ = fs::remove_file(dir.join("supervisor.pid"));
    observer::event(
        &logs,
        "run_finished",
        serde_json::json!({"exit_code":lab.exit_code,"status":lab.status}),
    )?;
    let diff = git::diff(&dir.join("workspace"))?;
    let mut out = labs::private_file(&logs.join("fs.diff"), true)?;
    out.write_all(diff.as_bytes())?;
    let code = result?;
    if code != 0 {
        bail!("laboratory exited with status {code}; inspect petri logs {id}")
    }
    Ok(())
}
fn replay_recording(dir: &std::path::Path) -> Result<()> {
    let file = fs::File::open(dir.join("terminal.cast"))?;
    let mut previous = 0.0;
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let value: serde_json::Value = serde_json::from_str(&line?)?;
        if i == 0 {
            continue;
        }
        let t = value[0].as_f64().context("invalid cast timing")?;
        if !t.is_finite() || t < previous {
            bail!("invalid cast timing")
        }
        // Stay interruptible while respecting long pauses.
        let mut remaining = t - previous;
        while remaining > 0.0 {
            let chunk = remaining.min(0.25);
            std::thread::sleep(std::time::Duration::from_secs_f64(chunk));
            remaining -= chunk
        }
        if let Some(s) = value[2].as_str() {
            print!("{s}");
            std::io::stdout().flush()?
        }
        previous = t;
    }
    Ok(())
}
