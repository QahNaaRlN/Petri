//! Offline, verified stack storage. ADR-013: no registry or build claims;
//! local rootfs imports are trusted input, not signature-verified software.
//! Layers with whiteouts, hardlinks or special files fail closed (never partially
//! publish an image). Sandbox mount targets must be real directories.
use anyhow::{bail, ensure, Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

const MAX_BLOB: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 200_000;
const TARGETS: [&str; 7] = [
    "workspace",
    "logs",
    "tmp",
    "proc",
    "dev",
    "run",
    ".petri-oldroot",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StackInfo {
    pub name: String,
    /// SHA-256 of the normalized filesystem, independent of its import format.
    pub digest: String,
    pub rootfs: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Reference {
    name: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u32,
    manifests: Vec<Descriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct ImageConfig {
    os: String,
    architecture: String,
    rootfs: ImageRootfs,
}

#[derive(Deserialize)]
struct ImageRootfs {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

struct Staging(PathBuf);
impl Staging {
    fn create(store: &Path) -> Result<Self> {
        fs::create_dir_all(store)?;
        let path = store.join(format!(".import-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        fs::create_dir(path.join("rootfs"))?;
        Ok(Self(path))
    }
    fn rootfs(&self) -> PathBuf {
        self.0.join("rootfs")
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = unseal_dirs(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn valid_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 80,
        "stack name must contain 1..80 characters"
    );
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid stack name"
    );
    ensure!(name != "." && name != "..", "invalid stack name");
    Ok(())
}

fn valid_digest(digest: &str) -> Result<&str> {
    let value = digest
        .strip_prefix("sha256:")
        .context("only sha256 digests are supported")?;
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid sha256 digest"
    );
    Ok(value)
}

fn checked_path(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.components().count() <= 128,
        "rootfs path exceeds maximum nesting depth"
    );
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                ensure!(
                    value.to_str().is_some(),
                    "non-UTF8 filesystem names are unsupported"
                );
                result.push(value);
            }
            Component::CurDir => (),
            _ => bail!("archive path escapes rootfs: {}", path.display()),
        }
    }
    Ok(result)
}

/// Resolve a symlink according to container-root semantics, never host semantics.
fn validate_symlink(relative: &Path, target: &Path) -> Result<()> {
    ensure!(
        target.to_str().is_some(),
        "non-UTF8 symlink targets are unsupported"
    );
    let mut depth = if target.is_absolute() {
        0
    } else {
        relative.parent().map_or(0, |p| p.components().count())
    };
    for component in target.components() {
        match component {
            Component::RootDir | Component::CurDir => (),
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                ensure!(
                    depth > 0,
                    "symlink escapes container root: {}",
                    relative.display()
                );
                depth -= 1;
            }
            Component::Prefix(_) => bail!("unsupported symlink target"),
        }
    }
    Ok(())
}

fn ensure_parents(root: &Path, path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new(""));
    let mut current = root.to_path_buf();
    for part in parent.components() {
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "symlink/non-directory in layer parent: {}",
                current.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn executable(_meta: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn create_symlink(target: &Path, path: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, path)?;
    Ok(())
}
#[cfg(not(unix))]
fn create_symlink(_target: &Path, _path: &Path) -> Result<()> {
    bail!("symlink rootfs import requires Unix; Windows rootfs import is not implemented")
}

#[derive(Default)]
struct Budget {
    entries: usize,
    bytes: u64,
    archive_bytes: u64,
}
impl Budget {
    fn add(&mut self, size: u64) -> Result<()> {
        self.entries += 1;
        self.bytes = self
            .bytes
            .checked_add(size)
            .context("stack size overflow")?;
        ensure!(
            self.entries <= MAX_ENTRIES && self.bytes <= MAX_EXPANDED,
            "stack extraction resource limit exceeded"
        );
        Ok(())
    }
}

fn copy_tree(source: &Path, destination: &Path, root: &Path, budget: &mut Budget) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let src = entry.path();
        let dst = destination.join(entry.file_name());
        let meta = fs::symlink_metadata(&src)?;
        let relative = dst.strip_prefix(root)?;
        checked_path(relative)?;
        budget.add(if meta.is_file() { meta.len() } else { 0 })?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&src)?;
            validate_symlink(relative, &target)?;
            create_symlink(&target, &dst)?;
        } else if meta.is_dir() {
            fs::create_dir(&dst)?;
            copy_tree(&src, &dst, root, budget)?;
        } else if meta.is_file() {
            // No hardlinks: the imported tree must not mutate with the source.
            fs::copy(&src, &dst)?;
            set_mode(&dst, if executable(&meta) { 0o755 } else { 0o644 })?;
        } else {
            bail!("special file in rootfs is unsupported: {}", src.display());
        }
    }
    Ok(())
}

fn normalize_mountpoints(root: &Path) -> Result<()> {
    for name in TARGETS {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) => ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "runtime mountpoint /{name} must be a real directory"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&path)?,
            Err(e) => return Err(e.into()),
        }
        // Runtime bind mounts conceal /workspace,/logs; reject image payloads
        // there and in the pivot directory to avoid hidden unexpected state.
        if matches!(name, "workspace" | "logs" | ".petri-oldroot") {
            ensure!(
                fs::read_dir(&path)?.next().is_none(),
                "runtime mountpoint /{name} must be empty"
            );
        }
    }
    Ok(())
}

fn hash_tree(root: &Path) -> Result<String> {
    fn walk(root: &Path, dir: &Path, hash: &mut Sha256) -> Result<()> {
        let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let rel = checked_path(path.strip_prefix(root)?)?;
            let rel = rel.to_str().context("non-UTF8 path")?;
            let meta = fs::symlink_metadata(&path)?;
            hash.update((rel.len() as u64).to_le_bytes());
            hash.update(rel.as_bytes());
            if meta.file_type().is_symlink() {
                hash.update(b"L");
                let target = fs::read_link(&path)?;
                let target = target.to_str().context("non-UTF8 symlink")?;
                hash.update((target.len() as u64).to_le_bytes());
                hash.update(target.as_bytes());
            } else if meta.is_dir() {
                hash.update(b"D");
                walk(root, &path, hash)?;
            } else if meta.is_file() {
                hash.update(if executable(&meta) { b"X" } else { b"F" });
                hash.update(meta.len().to_le_bytes());
                let mut file = File::open(path)?;
                let mut buf = [0; 64 * 1024];
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buf[..n]);
                }
            } else {
                bail!("unexpected special file in stack");
            }
        }
        Ok(())
    }
    let mut hash = Sha256::new();
    hash.update(b"petri-rootfs-v1\0");
    walk(root, root, &mut hash)?;
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

fn seal(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            seal(&path)?;
        } else {
            set_mode(&path, if executable(&meta) { 0o555 } else { 0o444 })?;
        }
    }
    set_mode(root, 0o555)
}

fn unseal_dirs(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    set_mode(root, 0o755)?;
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_dir() && !meta.file_type().is_symlink() {
            unseal_dirs(&path)?;
        }
    }
    Ok(())
}

fn publish(store: &Path, name: &str, stage: &Staging) -> Result<StackInfo> {
    normalize_mountpoints(&stage.rootfs())?;
    let digest = hash_tree(&stage.rootfs())?;
    let hex = valid_digest(&digest)?;
    fs::create_dir_all(store.join("blobs"))?;
    fs::create_dir_all(store.join("refs"))?;
    let blob = store.join("blobs").join(hex);
    seal(&stage.rootfs())?;
    if !blob.exists() {
        if let Err(error) = fs::rename(&stage.0, &blob) {
            if !blob.is_dir() {
                return Err(error.into());
            }
        }
    }
    // Verify existing content too: a colliding directory is not trusted.
    ensure!(
        hash_tree(&blob.join("rootfs"))? == digest,
        "existing stack content failed integrity check"
    );
    let reference = Reference {
        name: name.into(),
        digest: digest.clone(),
    };
    let temp = store
        .join("refs")
        .join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut file = File::create(&temp)?;
    file.write_all(&serde_json::to_vec_pretty(&reference)?)?;
    file.sync_all()?;
    fs::rename(temp, store.join("refs").join(format!("{name}.json")))?;
    Ok(StackInfo {
        name: name.into(),
        digest,
        rootfs: blob.join("rootfs"),
    })
}

/// Import an explicitly trusted local directory, without executing its contents.
pub fn import_rootfs(store: &Path, name: &str, rootfs: &Path) -> Result<StackInfo> {
    valid_name(name)?;
    let source = rootfs
        .canonicalize()
        .context("rootfs directory not found")?;
    ensure!(source.is_dir(), "rootfs must be a directory");
    let stage = Staging::create(store)?;
    let stage_path = stage.0.canonicalize()?;
    ensure!(
        !stage_path.starts_with(&source),
        "stack store must not be inside imported rootfs"
    );
    copy_tree(
        &source,
        &stage.rootfs(),
        &stage.rootfs(),
        &mut Budget::default(),
    )?;
    publish(store, name, &stage)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "JSON must be a regular file"
    );
    ensure!(meta.len() <= 4 * 1024 * 1024, "JSON exceeds size limit");
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn verified_blob(layout: &Path, descriptor: &Descriptor) -> Result<PathBuf> {
    let hex = valid_digest(&descriptor.digest)?;
    ensure!(descriptor.size <= MAX_BLOB, "OCI blob exceeds size limit");
    for parent in [layout.join("blobs"), layout.join("blobs/sha256")] {
        let metadata = fs::symlink_metadata(&parent)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "OCI blob directory must not be a symlink"
        );
    }
    let path = layout.join("blobs/sha256").join(hex);
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "OCI blob must be a regular file"
    );
    ensure!(metadata.len() == descriptor.size, "OCI blob size mismatch");
    let mut file = File::open(&path)?;
    let mut hash = Sha256::new();
    let mut buf = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    ensure!(
        hex::encode(hash.finalize()) == hex,
        "OCI blob digest mismatch"
    );
    Ok(path)
}

struct HashReader<R> {
    inner: R,
    hash: Sha256,
    bytes: u64,
    limit: u64,
}
impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes += n as u64;
        if self.bytes > self.limit {
            return Err(std::io::Error::other(
                "expanded layer exceeds resource limit",
            ));
        }
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

fn extract_layer(
    reader: Box<dyn Read>,
    root: &Path,
    budget: &mut Budget,
    diff_id: &str,
) -> Result<()> {
    let mut reader = HashReader {
        inner: reader,
        hash: Sha256::new(),
        bytes: 0,
        limit: MAX_EXPANDED.saturating_sub(budget.archive_bytes),
    };
    {
        let mut archive = tar::Archive::new(&mut reader);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let relative = checked_path(&entry.path()?)?;
            if relative.as_os_str().is_empty() {
                continue;
            }
            ensure!(
                !relative
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".wh."),
                "OCI whiteout layers are not yet supported; image not imported"
            );
            let size = entry.header().size()?;
            budget.add(size)?;
            ensure_parents(root, &relative)?;
            let path = root.join(&relative);
            let kind = entry.header().entry_type();
            if kind.is_dir() {
                if let Ok(meta) = fs::symlink_metadata(&path) {
                    ensure!(
                        meta.is_dir() && !meta.file_type().is_symlink(),
                        "layer directory would follow a symlink"
                    );
                } else {
                    fs::create_dir(&path)?;
                }
                set_mode(&path, 0o755)?;
            } else if kind.is_file() {
                if let Ok(meta) = fs::symlink_metadata(&path) {
                    ensure!(!meta.is_dir(), "layer file replaces directory");
                    fs::remove_file(&path)?;
                }
                let mut file = File::create(&path)?;
                let copied = std::io::copy(&mut Read::take(&mut entry, size + 1), &mut file)?;
                ensure!(copied == size, "truncated layer entry");
                set_mode(
                    &path,
                    if entry.header().mode()? & 0o111 != 0 {
                        0o755
                    } else {
                        0o644
                    },
                )?;
            } else if kind.is_symlink() {
                let target = entry.link_name()?.context("symlink without target")?;
                validate_symlink(&relative, &target)?;
                if let Ok(meta) = fs::symlink_metadata(&path) {
                    ensure!(!meta.is_dir(), "layer symlink replaces directory");
                    fs::remove_file(&path)?;
                }
                create_symlink(&target, &path)?;
            } else {
                bail!("unsupported OCI entry type (hardlinks, devices, FIFOs and sparse entries are rejected)");
            }
        }
    }
    std::io::copy(&mut reader, &mut std::io::sink())?;
    budget.archive_bytes += reader.bytes;
    ensure!(
        format!("sha256:{}", hex::encode(reader.hash.finalize())) == diff_id,
        "OCI uncompressed layer diff_id mismatch"
    );
    Ok(())
}

/// Import a single-image OCI layout. Manifest/config/layer digests are verified;
/// cryptographic authenticity is NOT inferred from integrity hashes.
pub fn import_oci(store: &Path, name: &str, layout: &Path) -> Result<StackInfo> {
    valid_name(name)?;
    let layout = layout.canonicalize()?;
    let marker: serde_json::Value = read_json(&layout.join("oci-layout"))?;
    ensure!(
        marker["imageLayoutVersion"] == "1.0.0",
        "unsupported OCI layout version"
    );
    let index: Index = read_json(&layout.join("index.json"))?;
    ensure!(
        index.schema_version == 2 && index.manifests.len() == 1,
        "provide a schemaVersion 2 OCI layout with exactly one image manifest"
    );
    let descriptor = &index.manifests[0];
    ensure!(
        descriptor.media_type == "application/vnd.oci.image.manifest.v1+json",
        "unsupported OCI manifest media type"
    );
    let manifest: Manifest = read_json(&verified_blob(&layout, descriptor)?)?;
    ensure!(manifest.schema_version == 2, "unsupported manifest schema");
    ensure!(manifest.layers.len() <= 128, "too many layers");
    let compressed_total = manifest
        .layers
        .iter()
        .try_fold(0u64, |total, layer| total.checked_add(layer.size))
        .context("OCI layer size overflow")?;
    ensure!(
        compressed_total <= MAX_EXPANDED,
        "aggregate OCI layer size limit exceeded"
    );
    ensure!(
        manifest.config.media_type == "application/vnd.oci.image.config.v1+json",
        "unsupported OCI config media type"
    );
    let config: ImageConfig = read_json(&verified_blob(&layout, &manifest.config)?)?;
    ensure!(
        config.os == "linux",
        "only Linux rootfs stacks are supported"
    );
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    ensure!(
        config.architecture == arch,
        "OCI image architecture does not match host"
    );
    ensure!(
        config.rootfs.kind == "layers" && config.rootfs.diff_ids.len() == manifest.layers.len(),
        "invalid OCI rootfs diff_ids"
    );
    let stage = Staging::create(store)?;
    let mut budget = Budget::default();
    for (descriptor, diff_id) in manifest.layers.iter().zip(&config.rootfs.diff_ids) {
        valid_digest(diff_id)?;
        let path = verified_blob(&layout, descriptor)?;
        let reader: Box<dyn Read> = match descriptor.media_type.as_str() {
            "application/vnd.oci.image.layer.v1.tar" => Box::new(File::open(path)?),
            "application/vnd.oci.image.layer.v1.tar+gzip" => {
                Box::new(GzDecoder::new(File::open(path)?))
            }
            _ => bail!("unsupported OCI layer encoding; only tar and tar+gzip are supported"),
        };
        extract_layer(reader, &stage.rootfs(), &mut budget, diff_id)?;
    }
    publish(store, name, &stage)
}

pub fn resolve(store: &Path, name: &str) -> Result<StackInfo> {
    valid_name(name)?;
    let reference: Reference = read_json(&store.join("refs").join(format!("{name}.json")))
        .with_context(|| {
            format!("stack {name:?} not found; import a rootfs or OCI layout first")
        })?;
    ensure!(reference.name == name, "stack reference name mismatch");
    let digest = valid_digest(&reference.digest)?;
    let rootfs = store.join("blobs").join(digest).join("rootfs");
    let info = StackInfo {
        name: name.into(),
        digest: reference.digest,
        rootfs,
    };
    verify(&info)?;
    Ok(info)
}

/// Validate an immutable stack retained by a lab, independently of mutable name
/// references. Removing a stack name must not invalidate a running laboratory.
pub fn verify(info: &StackInfo) -> Result<()> {
    valid_digest(&info.digest)?;
    let meta = fs::symlink_metadata(&info.rootfs).context("missing stack rootfs")?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "stack rootfs must be a real directory"
    );
    ensure!(
        hash_tree(&info.rootfs)? == info.digest,
        "stack integrity check failed"
    );
    Ok(())
}

pub fn list(store: &Path) -> Result<Vec<StackInfo>> {
    let path = store.join("refs");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut names: Vec<_> = fs::read_dir(path)?.collect::<std::io::Result<_>>()?;
    names.sort_by_key(|e| e.file_name());
    let mut result = Vec::new();
    for entry in names {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .context("invalid stack reference")?;
            result.push(resolve(store, name)?);
        }
    }
    Ok(result)
}

/// Remove a name only. Blob GC is intentionally deferred: live labs may retain
/// the digest, so deleting shared content here could break another laboratory.
pub fn remove(store: &Path, name: &str) -> Result<()> {
    valid_name(name)?;
    fs::remove_file(store.join("refs").join(format!("{name}.json")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rootfs_deduplication_is_a_snapshot_and_removal_preserves_other_names() -> Result<()> {
        let t = tempdir()?;
        let source = t.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("hello"), "one")?;
        let store = t.path().join("store");
        let a = import_rootfs(&store, "a", &source)?;
        let b = import_rootfs(&store, "b", &source)?;
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.rootfs, b.rootfs);
        fs::write(source.join("hello"), "two")?;
        assert_eq!(fs::read_to_string(a.rootfs.join("hello"))?, "one");
        assert!(a.rootfs.join(".petri-oldroot").is_dir());
        remove(&store, "a")?;
        verify(&a)?; // Existing labs retain content after a name is removed.
        assert!(resolve(&store, "a").is_err());
        assert_eq!(resolve(&store, "b")?.digest, b.digest);
        assert_eq!(list(&store)?.len(), 1);
        unseal_dirs(t.path())?;
        Ok(())
    }

    #[test]
    fn resolve_detects_mutated_store_content() -> Result<()> {
        let t = tempdir()?;
        let source = t.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("data"), "safe")?;
        let store = t.path().join("store");
        let stack = import_rootfs(&store, "check", &source)?;
        set_mode(&stack.rootfs.join("data"), 0o644)?;
        fs::write(stack.rootfs.join("data"), "evil")?;
        assert!(resolve(&store, "check").is_err());
        assert!(verify(&stack).is_err());
        unseal_dirs(t.path())?;
        Ok(())
    }

    #[test]
    fn rejects_invalid_names_and_store_within_source() -> Result<()> {
        let t = tempdir()?;
        assert!(import_rootfs(&t.path().join("store"), "../evil", t.path()).is_err());
        assert!(import_rootfs(&t.path().join("store"), "okay", t.path()).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_escape_and_mountpoint_symlinks() -> Result<()> {
        let t = tempdir()?;
        let source = t.path().join("rootfs");
        fs::create_dir(&source)?;
        create_symlink(Path::new("../../outside"), &source.join("bad"))?;
        assert!(import_rootfs(&t.path().join("store"), "bad", &source).is_err());
        fs::remove_file(source.join("bad"))?;
        create_symlink(Path::new("somewhere"), &source.join("workspace"))?;
        assert!(import_rootfs(&t.path().join("store"), "bad", &source).is_err());
        Ok(())
    }

    fn layer_file(path: &str, content: &[u8]) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut builder = tar::Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content)?;
        builder.finish()?;
        drop(builder);
        Ok(bytes)
    }
    fn sha(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }
    fn blob(layout: &Path, media: &str, bytes: &[u8]) -> Result<serde_json::Value> {
        let digest = sha(bytes);
        fs::write(
            layout.join("blobs/sha256").join(valid_digest(&digest)?),
            bytes,
        )?;
        Ok(serde_json::json!({"mediaType":media,"digest":digest,"size":bytes.len()}))
    }
    fn fixture(layout: &Path, layer: &[u8]) -> Result<PathBuf> {
        fs::create_dir_all(layout.join("blobs/sha256"))?;
        fs::write(
            layout.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )?;
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            x => x,
        };
        let config = serde_json::to_vec(
            &serde_json::json!({"os":"linux","architecture":arch,"rootfs":{"type":"layers","diff_ids":[sha(layer)]}}),
        )?;
        let config = blob(layout, "application/vnd.oci.image.config.v1+json", &config)?;
        let layer_descriptor = blob(layout, "application/vnd.oci.image.layer.v1.tar", layer)?;
        let layer_path = layout
            .join("blobs/sha256")
            .join(valid_digest(layer_descriptor["digest"].as_str().unwrap())?);
        let manifest = serde_json::to_vec(
            &serde_json::json!({"schemaVersion":2,"config":config,"layers":[layer_descriptor]}),
        )?;
        let manifest = blob(
            layout,
            "application/vnd.oci.image.manifest.v1+json",
            &manifest,
        )?;
        fs::write(
            layout.join("index.json"),
            serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"manifests":[manifest]}))?,
        )?;
        Ok(layer_path)
    }

    #[test]
    fn oci_import_checks_blob_integrity_and_uncompressed_content() -> Result<()> {
        let t = tempdir()?;
        let layout = t.path().join("oci");
        let layer = layer_file("usr/message", b"verified")?;
        let layer_path = fixture(&layout, &layer)?;
        let stack = import_oci(&t.path().join("store"), "image", &layout)?;
        assert_eq!(fs::read(stack.rootfs.join("usr/message"))?, b"verified");
        let mut tampered = layer.clone();
        tampered[512] ^= 1;
        fs::write(layer_path, tampered)?;
        assert!(import_oci(&t.path().join("store"), "tampered", &layout).is_err());
        assert!(resolve(&t.path().join("store"), "tampered").is_err());
        unseal_dirs(t.path())?;
        Ok(())
    }

    #[test]
    fn oci_whiteouts_fail_without_publishing() -> Result<()> {
        let t = tempdir()?;
        let layout = t.path().join("oci");
        fixture(&layout, &layer_file(".wh.secret", b"")?)?;
        assert!(import_oci(&t.path().join("store"), "whiteout", &layout).is_err());
        assert!(list(&t.path().join("store"))?.is_empty());
        Ok(())
    }

    #[test]
    fn tar_path_traversal_is_rejected() -> Result<()> {
        let t = tempdir()?;
        let root = t.path().join("root");
        fs::create_dir(&root)?;
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(3);
        header.as_mut_bytes()[..12].copy_from_slice(b"../escaped\0\0");
        header.set_cksum();
        let mut layer = header.as_bytes().to_vec();
        layer.extend_from_slice(b"bad");
        layer.resize(2048, 0);
        assert!(extract_layer(
            Box::new(std::io::Cursor::new(layer.clone())),
            &root,
            &mut Budget::default(),
            &sha(&layer)
        )
        .is_err());
        assert!(!t.path().join("escaped").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn tar_cannot_write_through_prior_symlink() -> Result<()> {
        let t = tempdir()?;
        let out = t.path().join("out");
        fs::create_dir(&out)?;
        let root = t.path().join("root");
        fs::create_dir(&root)?;
        create_symlink(&out, &root.join("escape"))?;
        let layer = layer_file("escape/pwned", b"bad")?;
        let result = extract_layer(
            Box::new(std::io::Cursor::new(layer.clone())),
            &root,
            &mut Budget::default(),
            &sha(&layer),
        );
        assert!(result.is_err());
        assert!(!out.join("pwned").exists());
        Ok(())
    }
}
