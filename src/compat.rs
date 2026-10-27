//! A deliberately read-only Docker API subset, not a Docker/Compose runtime.
//! ADR-015: unsupported operations return 501; no mutation may report success.
#[cfg(unix)]
use crate::labs::Lab;
use crate::labs::Store;
#[cfg(unix)]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(unix)]
use serde_json::{json, Value};

#[cfg(unix)]
const API_VERSION: &str = "1.44";
#[cfg(unix)]
const HEADER_LIMIT: usize = 8192;

#[cfg(unix)]
struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

#[cfg(unix)]
impl Response {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: value.to_string().into_bytes(),
        }
    }

    fn error(status: u16, message: &str) -> Self {
        Self::json(status, json!({"message":message}))
    }
}

#[cfg(unix)]
fn unsupported() -> Response {
    Response::error(501, "NotImplemented: Petri provides read-only Docker discovery only; container mutations, images, networks, volumes, exec, builds and Compose are not supported")
}

#[cfg(unix)]
fn docker_state(lab: &Lab) -> &'static str {
    match lab.status.as_str() {
        "Running" => "running",
        "Exited" | "Stopped" | "Failed" => "exited",
        "Prepared" | "Starting" => "created",
        _ => "unknown",
    }
}

#[cfg(unix)]
fn labels(lab: &Lab) -> Value {
    json!({
        "org.petri.lab":lab.id,
        "org.petri.stack.digest":lab.stack_hash,
        "org.petri.status":lab.status,
        "org.petri.compat":"read-only"
    })
}

#[cfg(unix)]
fn summary(lab: &Lab) -> Value {
    json!({
        "Id":lab.id,
        "Names":[format!("/{}",lab.id)],
        "Image":lab.stack.name,
        "ImageID":lab.stack.digest,
        "Command":lab.command.join(" "),
        "Created":lab.created_at,
        "State":docker_state(lab),
        "Status":lab.status,
        "Labels":labels(lab),
        "Ports":[],
        "Mounts":[],
        "HostConfig":{"NetworkMode":"none"},
        "NetworkSettings":{"Networks":{}}
    })
}

#[cfg(unix)]
fn created_timestamp(timestamp: u64) -> Option<String> {
    let seconds: libc::time_t = timestamp.try_into().ok()?;
    let mut time = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::gmtime_r(&seconds, time.as_mut_ptr()) }.is_null() {
        return None;
    }
    let time = unsafe { time.assume_init() };
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.tm_year + 1900,
        time.tm_mon + 1,
        time.tm_mday,
        time.tm_hour,
        time.tm_min,
        time.tm_sec
    ))
}

#[cfg(unix)]
fn inspect(lab: &Lab) -> Value {
    json!({
        "Id":lab.id,
        "Name":format!("/{}",lab.id),
        "Created":created_timestamp(lab.created_at),
        "Image":lab.stack.digest,
        "Path":lab.command.first().cloned().unwrap_or_default(),
        "Args":lab.command.iter().skip(1).collect::<Vec<_>>(),
        "State":{
            "Status":docker_state(lab),
            "Running":lab.status=="Running",
            "Paused":false,
            "Restarting":false,
            "Dead":false,
            "ExitCode":lab.exit_code,
            "Error":"",
            "Pid":0
        },
        "Config":{
            "Image":lab.stack.name,
            "Cmd":lab.command,
            "Env":[],
            "Labels":labels(lab),
            "WorkingDir":"/workspace",
            "Tty":false
        },
        "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true},
        "NetworkSettings":{"Networks":{}},
        "Mounts":[]
    })
}

#[cfg(unix)]
fn dispatch(store: &Store, method: &str, target: &str) -> Response {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let path = path.strip_prefix("/v1.44").unwrap_or(path);
    if method == "HEAD" && path == "/_ping" {
        return Response {
            status: 200,
            content_type: "text/plain",
            body: Vec::new(),
        };
    }
    if method != "GET" {
        return unsupported();
    }
    match path {
        "/_ping" => Response {
            status: 200,
            content_type: "text/plain",
            body: b"OK".to_vec(),
        },
        "/version" => Response::json(
            200,
            json!({
                "Version":env!("CARGO_PKG_VERSION"),
                "ApiVersion":API_VERSION,
                "MinAPIVersion":API_VERSION,
                "Os":std::env::consts::OS,
                "Arch":std::env::consts::ARCH,
                "Experimental":false,
                "Components":[{"Name":"Petri read-only discovery","Version":env!("CARGO_PKG_VERSION"),"Details":{"Compatibility":"read-only subset; no Compose"}}]
            }),
        ),
        "/info" => match store.list() {
            Ok(labs) => Response::json(
                200,
                json!({
                    "ID":"petri",
                    "Name":"Petri (read-only discovery)",
                    "ServerVersion":env!("CARGO_PKG_VERSION"),
                    "OSType":std::env::consts::OS,
                    "Architecture":std::env::consts::ARCH,
                    "Containers":labs.len(),
                    "ContainersRunning":labs.iter().filter(|lab| lab.status=="Running").count(),
                    "ContainersPaused":0,
                    "ContainersStopped":labs.iter().filter(|lab| lab.status!="Running").count(),
                    "Images":0,
                    "Warnings":["Petri discovery API only; Docker mutations and Compose are unsupported", "Resource limits are per-process rlimits, not cgroup accounting"]
                }),
            ),
            Err(_) => Response::error(500, "failed to read laboratory metadata"),
        },
        "/containers/json" => {
            let mut all = false;
            for parameter in query.split('&').filter(|value| !value.is_empty()) {
                match parameter {
                    "all=1" | "all=true" => all = true,
                    "all=0" | "all=false" => all = false,
                    _ => return unsupported(),
                }
            }
            match store.list() {
                Ok(labs) => Response::json(
                    200,
                    Value::Array(
                        labs.iter()
                            .filter(|lab| all || lab.status == "Running")
                            .map(summary)
                            .collect(),
                    ),
                ),
                Err(_) => Response::error(500, "failed to read laboratory metadata"),
            }
        }
        _ => {
            if let Some(id) = path
                .strip_prefix("/containers/")
                .and_then(|remaining| remaining.strip_suffix("/json"))
            {
                let directory = match store.lab_dir(id) {
                    Ok(path) => path,
                    Err(_) => return Response::error(400, "invalid laboratory identifier"),
                };
                match std::fs::metadata(directory.join("meta.json")) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Response::error(404, "laboratory not found");
                    }
                    Err(_) => return Response::error(500, "cannot inspect laboratory metadata"),
                    Ok(_) => {}
                }
                return match store.load(id) {
                    Ok(lab) => Response::json(200, inspect(&lab)),
                    Err(_) => Response::error(500, "invalid laboratory metadata"),
                };
            }
            unsupported()
        }
    }
}

#[cfg(unix)]
fn parse_request(headers: &[u8]) -> Result<(&str, &str)> {
    let text = std::str::from_utf8(headers).context("headers must be UTF-8")?;
    let (line, _) = text.split_once("\r\n").context("missing request line")?;
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.len() != 3
        || !["HTTP/1.0", "HTTP/1.1"].contains(&parts[2])
        || parts[0].is_empty()
        || !parts[0].bytes().all(|byte| byte.is_ascii_uppercase())
        || !parts[1].starts_with('/')
        || parts[1].bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("invalid request line");
    }
    for header in text
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
    {
        if header.starts_with([' ', '\t']) || !header.contains(':') {
            bail!("invalid header");
        }
    }
    Ok((parts[0], parts[1]))
}

#[cfg(unix)]
fn handle_connection(store: &Store, stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    use std::io::{Read, Write};
    use std::time::Duration;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut headers = Vec::new();
    let response = loop {
        let mut buffer = [0; 512];
        let read = match stream.read(&mut buffer) {
            Ok(0) => break Response::error(400, "incomplete HTTP headers"),
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break Response::error(408, "header read timed out");
            }
            Err(error) => return Err(error.into()),
        };
        headers.extend_from_slice(&buffer[..read]);
        if headers.len() > HEADER_LIMIT {
            break Response::error(431, "headers exceed 8 KiB");
        }
        if let Some(end) = headers.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break match parse_request(&headers[..end + 4]) {
                Ok((method, target)) => dispatch(store, method, target),
                Err(_) => Response::error(400, "invalid HTTP request"),
            };
        }
    };
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Not Implemented",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAPI-Version: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len(),
        API_VERSION
    )?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

/// Blocking foreground server. It refuses existing sockets, including stale
/// sockets, rather than unlinking a potentially active service or a symlink.
#[cfg(unix)]
pub fn serve(store: &Store) -> Result<()> {
    use fs2::FileExt;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    crate::labs::private_dir(&store.home)?;
    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(store.home.join("docker.sock.lock"))?;
    lock.try_lock_exclusive()
        .context("DockerCompatBusy: another discovery server owns the socket lock")?;
    let socket = store.home.join("docker.sock");
    match fs::symlink_metadata(&socket) {
        Ok(_) => bail!("DockerCompatBusy: docker.sock already exists; refusing to remove an active socket, stale socket or symlink"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(&socket).context("bind Docker discovery socket")?;
    let metadata = fs::symlink_metadata(&socket)?;
    // Never unlink a replacement path on drop.
    struct SocketCleanup {
        path: std::path::PathBuf,
        device: u64,
        inode: u64,
    }
    impl Drop for SocketCleanup {
        fn drop(&mut self) {
            if let Ok(metadata) = fs::symlink_metadata(&self.path) {
                if metadata.dev() == self.device && metadata.ino() == self.inode {
                    let _ = fs::remove_file(&self.path);
                }
            }
        }
    }
    let _cleanup = SocketCleanup {
        path: socket.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    for stream in listener.incoming() {
        let mut stream = stream.context("accept Docker discovery request")?;
        // Malformed/abandoned clients do not terminate the foreground service.
        let _ = handle_connection(store, &mut stream);
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn serve(_store: &Store) -> Result<()> {
    bail!("Unsupported: Docker discovery requires a Unix socket; Windows transport is not implemented")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn parser_refuses_malformed_requests() {
        assert!(parse_request(b"GET /_ping HTTP/1.1\r\nHost: petri\r\n\r\n").is_ok());
        assert!(parse_request(b"GET /_ping HTTP/2\r\n\r\n").is_err());
        assert!(parse_request(b"GET http://host/ HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_request(b"GET /_ping HTTP/1.1\r\n folded\r\n\r\n").is_err());
    }

    #[test]
    fn inspect_timestamps_use_docker_rfc3339_format() {
        assert_eq!(
            created_timestamp(0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            created_timestamp(86400).as_deref(),
            Some("1970-01-02T00:00:00Z")
        );
    }

    #[test]
    fn discovery_and_mutations_are_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_owned()).unwrap();
        assert_eq!(dispatch(&store, "GET", "/_ping").status, 200);
        assert_eq!(dispatch(&store, "GET", "/v1.44/version").status, 200);
        let response = dispatch(&store, "GET", "/v1.44/containers/json?all=1");
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!([])
        );
        for (method, path) in [
            ("POST", "/v1.44/containers/create"),
            (
                "DELETE",
                "/v1.44/containers/lab-00000000000000000000000000000000",
            ),
            ("POST", "/containers/id/start"),
            ("GET", "/images/json"),
            ("GET", "/networks"),
        ] {
            let response = dispatch(&store, method, path);
            assert_eq!(response.status, 501);
            assert!(
                serde_json::from_slice::<Value>(&response.body).unwrap()["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("NotImplemented")
            );
        }
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn inspect_validates_id_and_missing_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_owned()).unwrap();
        assert_eq!(dispatch(&store, "GET", "/containers/../json").status, 400);
        assert_eq!(
            dispatch(
                &store,
                "GET",
                "/containers/lab-00000000000000000000000000000000/json"
            )
            .status,
            404
        );
    }

    #[cfg(unix)]
    #[test]
    fn socket_symlink_is_never_removed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_owned()).unwrap();
        let target = dir.path().join("untouched");
        std::fs::write(&target, "original").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("docker.sock")).unwrap();
        assert!(serve(&store).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "original");
        assert!(std::fs::symlink_metadata(dir.path().join("docker.sock"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn connection_closes_with_bounded_json_response() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_owned()).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .write_all(b"DELETE /containers/example HTTP/1.1\r\nHost: petri\r\n\r\n")
            .unwrap();
        handle_connection(&store, &mut server).unwrap();
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(serde_json::from_str::<Value>(body).unwrap()["message"].is_string());
    }
}
