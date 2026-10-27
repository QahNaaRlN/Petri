//! Host-only blackbox writers. ADR-012: the lab must never mount this directory
//! writable. File permissions are not an append-only boundary for a same-UID
//! attacker. These functions do not claim complete process/network observation.
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_REPLAY_BYTES: u64 = 64 * 1024 * 1024;

fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn log_file(dir: &Path, name: &str) -> Result<File> {
    fs::create_dir_all(dir)?;
    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("blackbox directory must be a real directory");
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let file = options.open(dir.join(name)).context("open blackbox file")?;
    if !file.metadata()?.is_file() {
        bail!("blackbox log must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if file.metadata()?.nlink() != 1 {
            bail!("blackbox file must not have hardlinks");
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        // Held until File is closed. Serialize the header and entire JSON line.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("lock blackbox file");
        }
    }
    Ok(file)
}

fn write_json_line(file: &mut File, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(())
}

pub fn event(dir: &Path, kind: &str, data: Value) -> Result<()> {
    if kind.is_empty()
        || kind.len() > 64
        || !kind.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        bail!("event kind must contain 1..64 ASCII letters, numbers or underscores");
    }
    let mut file = log_file(dir, "events.jsonl")?;
    write_json_line(
        &mut file,
        &json!({"timestamp":unix_timestamp()?,"kind":kind,"data":data}),
    )
}

/// Redacts only exact, explicitly supplied strings. It is not a secret detector
/// and cannot revoke credentials already disclosed to an agent (ADR-011).
pub fn redact(text: &str, secrets: &[String]) -> String {
    let mut candidates: Vec<&str> = secrets
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    candidates.sort_unstable_by_key(|s| std::cmp::Reverse(s.len()));
    candidates.dedup();
    // Match against the original input, avoiding replacements inside a previous
    // redaction marker and avoiding shorter values exposing a longer secret.
    let mut output = String::with_capacity(text.len());
    let mut offset = 0;
    while offset < text.len() {
        let remaining = &text[offset..];
        if let Some(secret) = candidates
            .iter()
            .find(|secret| remaining.starts_with(**secret))
        {
            output.push_str("***redacted***");
            offset += secret.len();
        } else {
            let next = remaining.chars().next().expect("nonempty input remainder");
            output.push(next);
            offset += next.len_utf8();
        }
    }
    output
}

/// Records captured pipe output in asciicast v2. This is not PTY emulation and
/// receives no secret values: callers must never pass raw credentials here.
pub fn record_output(dir: &Path, output: &str, elapsed: f64) -> Result<()> {
    if !elapsed.is_finite() || elapsed < 0.0 {
        bail!("recording time must be finite and non-negative");
    }
    let mut file = log_file(dir, "terminal.cast")?;
    if file.metadata()?.len().saturating_add(output.len() as u64) > MAX_REPLAY_BYTES {
        bail!("terminal recording exceeds 64 MiB; archive it before another run");
    }
    if file.metadata()?.len() == 0 {
        write_json_line(
            &mut file,
            &json!({"version":2,"width":80,"height":24,"timestamp":unix_timestamp()?,"title":"Petri captured output (pipe, not PTY)"}),
        )?;
    }
    if !output.is_empty() {
        write_json_line(&mut file, &json!([elapsed, "o", output]))?;
    }
    Ok(())
}

/// Concatenates output events. It deliberately does not sleep for recorded
/// delays; a caller wanting timed playback should consume the .cast file.
pub fn replay(dir: &Path) -> Result<String> {
    let path = dir.join("terminal.cast");
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("terminal recording must be a regular file");
    }
    if metadata.len() > MAX_REPLAY_BYTES {
        bail!("recording exceeds the 64 MiB in-memory replay limit; use an asciicast player");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut lines = BufReader::new(options.open(&path)?).lines();
    let header: Value = serde_json::from_str(&lines.next().context("empty recording")??)?;
    if header.get("version").and_then(Value::as_u64) != Some(2) {
        bail!("unsupported terminal recording version");
    }
    let mut output = String::new();
    for line in lines {
        let event: Value = serde_json::from_str(&line?)?;
        let array = event.as_array().context("invalid recording event")?;
        if array.len() != 3 || !array[0].is_number() {
            bail!("invalid recording event");
        }
        if array[1].as_str() == Some("o") {
            output.push_str(array[2].as_str().context("invalid recording output")?);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_redaction_handles_overlap_unicode_and_empty_values() {
        let secrets = [
            "token".into(),
            "token-long".into(),
            "".into(),
            "密钥".into(),
            "redacted".into(),
        ];
        assert_eq!(
            redact("token-long + token + 密钥", &secrets),
            "***redacted*** + ***redacted*** + ***redacted***"
        );
        assert_eq!(redact("plain", &secrets), "plain");
    }

    #[test]
    fn events_are_valid_separate_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        event(dir.path(), "lab_created", json!({"id":"lab-1"})).unwrap();
        event(dir.path(), "lab_stopped", json!({"exit_code":0})).unwrap();
        let text = fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        let values: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["kind"], "lab_created");
        assert!(values[0]["timestamp"].is_u64());
    }

    #[test]
    fn recording_round_trips_without_duplicate_headers() {
        let dir = tempfile::tempdir().unwrap();
        record_output(dir.path(), "hello\n", 0.1).unwrap();
        record_output(dir.path(), "world\n", 0.2).unwrap();
        assert_eq!(replay(dir.path()).unwrap(), "hello\nworld\n");
        let cast = fs::read_to_string(dir.path().join("terminal.cast")).unwrap();
        assert_eq!(cast.lines().count(), 3);
        assert!(record_output(dir.path(), "bad", f64::NAN).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn log_writes_reject_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("untouched");
        fs::write(&target, "original").unwrap();
        symlink(&target, dir.path().join("events.jsonl")).unwrap();
        assert!(event(dir.path(), "test", json!({})).is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "original");
    }
}
