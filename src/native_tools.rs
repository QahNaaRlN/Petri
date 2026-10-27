//! Verified, copied native toolchains for the first Windows CPython profile.
//!
//! Import is inert: it never executes a downloaded/interpreted program. File
//! hashes authenticate the explicitly selected bytes, not their publisher. The
//! package hash is declared provenance: directory import cannot verify an
//! original archive that was not supplied. Runtime qualification remains a
//! separate step. The workload receives RX, never write, access to this store.

use anyhow::{bail, ensure, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const MAX_MANIFEST: u64 = 8 * 1024 * 1024;
const MAX_FILES: usize = 32_768;
const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_PATH: usize = 220;
const DOMAIN: &[u8] = b"petri.native-toolchain/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainFile {
    pub path: String,
    pub size: u64,
    /// SHA-256, normalized to `sha256:<lowercase hex>` on import.
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainManifest {
    pub format_version: u32,
    /// Human-chosen logical identity. The installed identity is content-based.
    pub id: String,
    pub platform: String,
    pub architecture: String,
    pub python_version: String,
    pub entrypoint: String,
    pub source: String,
    /// Expected package digest supplied as provenance, not archive verification.
    pub package_sha256: String,
    pub license: String,
    pub files: Vec<ToolchainFile>,
    #[serde(default)]
    pub readonly_paths: Vec<String>,
    #[serde(default)]
    pub execute_paths: Vec<String>,
    /// Symbolic OS dependency names; this is a declaration, not an ACL grant.
    #[serde(default)]
    pub system_dependencies: Vec<String>,
    #[serde(default)]
    pub notices: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeToolchain {
    pub id: String,
    /// Only the copied `files` directory, never the import source directory.
    pub root: PathBuf,
    pub executable: PathBuf,
    pub digest: String,
    pub manifest: ToolchainManifest,
}

#[derive(Debug)]
pub struct NativeToolStore {
    pub root: PathBuf,
    // Keep the selected store and its existing ancestors pinned throughout use.
    _directory_guards: Vec<File>,
}

impl NativeToolStore {
    pub fn open(root: PathBuf) -> Result<Self> {
        let root = absolute_path(&root)?;
        let parent = root.parent().context("native tool store has no parent")?;
        let mut guards = pin_directory_chain(parent)?;
        private_dir(&root)?;
        let root_guard = pin_directory(&root)?;
        require_ntfs(&root_guard)?;
        guards.push(root_guard);
        #[cfg(windows)]
        let root = absolute_path(&root.canonicalize()?)?;
        Ok(Self {
            root,
            _directory_guards: guards,
        })
    }

    /// Copy exactly the files named by an external manifest into a private,
    /// content-addressed staging directory. An existing identical object is
    /// re-verified; corruption is never repaired silently under the old ID.
    pub fn import(&self, source: &Path, manifest_path: &Path) -> Result<NativeToolchain> {
        let _lock = self.lock()?;
        let source = absolute_path(source)?;
        let _source_guards = pin_directory_chain(&source)?;
        require_ntfs(
            _source_guards
                .last()
                .context("missing source directory handle")?,
        )?;
        #[cfg(windows)]
        let source = absolute_path(&source.canonicalize()?)?;
        // Lexical checks complement held directory handles and exact file hashes.
        ensure!(
            !self.root.starts_with(&source) && !source.starts_with(&self.root),
            "PolicyDenied: tool source and store must not contain one another"
        );
        let manifest_path = absolute_path(manifest_path)?;
        // Keep the exact no-follow manifest and its ancestors pinned before
        // resolving case/short-name spelling for the containment comparison.
        #[cfg(windows)]
        let (_manifest_parents, _manifest_file, manifest_path) = {
            let parent = manifest_path.parent().context("manifest has no parent")?;
            let parents = pin_directory_chain(parent)?;
            let file = crate::git::open_regular_no_links(&manifest_path)?;
            let canonical = absolute_path(&manifest_path.canonicalize()?)?;
            (parents, file, canonical)
        };
        ensure!(
            !manifest_path.starts_with(&source),
            "InvalidRequest: import manifest must be outside the source tree"
        );
        let mut manifest = read_manifest(&manifest_path)?;
        normalize_manifest(&mut manifest)?;
        let digest = manifest_digest(&manifest)?;
        let id = content_id(&digest)?;
        let target = self.root.join(&id);
        if target.try_exists()? {
            let existing = self.resolve(&id)?;
            ensure!(
                existing.manifest == manifest,
                "ArtifactInvalid: content ID collision"
            );
            return Ok(existing);
        }
        let inventory = inventory(&source)?;
        require_inventory(&manifest, &inventory)?;
        let staging = self
            .root
            .join(format!(".import-{}", uuid::Uuid::new_v4().simple()));
        private_dir(&staging)?;
        let mut cleanup = ImportGuard {
            path: staging.clone(),
            published: false,
        };
        let copied_root = staging.join("files");
        private_dir(&copied_root)?;
        for item in &manifest.files {
            let relative = Path::new(&item.path);
            let _parents = pin_relative_parents(&source, relative)?;
            let mut input = crate::git::open_regular_no_links(&source.join(relative))?;
            ensure!(
                input.metadata()?.len() == item.size,
                "ArtifactInvalid: tool size changed: {}",
                item.path
            );
            let destination = copied_root.join(relative);
            create_relative_parents(&copied_root, relative)?;
            let mut output = create_private_file(&destination)?;
            let actual = copy_hashed(&mut input, &mut output, item.size)?;
            ensure!(
                actual == item.sha256,
                "ArtifactInvalid: tool digest mismatch: {}",
                item.path
            );
            output.sync_all()?;
            drop(output);
            // Validate native architecture and isolated configuration on the copy.
            validate_tool_content(&destination, &item.path)?;
        }
        // Re-open/re-hash every copied object before publishing the immutable ID.
        verify_tree(&copied_root, &manifest)?;
        let mut output = create_private_file(&staging.join("manifest.json"))?;
        output.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
        output.sync_all()?;
        drop(output);
        fs::rename(&staging, &target).context("publish native toolchain")?;
        cleanup.published = true;
        sync_directory(&self.root)?;
        self.resolve(&id)
    }

    pub fn list(&self) -> Result<Vec<NativeToolchain>> {
        let mut tools = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let id = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("ArtifactInvalid: non-UTF8 tool store entry"))?;
            if id == ".import.lock" || id.starts_with(".import-") {
                continue;
            }
            tools.push(self.resolve(&id)?);
        }
        tools.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(tools)
    }

    pub fn resolve(&self, id: &str) -> Result<NativeToolchain> {
        validate_content_id(id)?;
        let object = self.root.join(id);
        let _object_guard = pin_directory(&object)?;
        let mut manifest = read_manifest(&object.join("manifest.json"))?;
        let original = manifest.clone();
        normalize_manifest(&mut manifest)?;
        ensure!(
            original == manifest,
            "ArtifactInvalid: stored manifest is not canonical"
        );
        let digest = manifest_digest(&manifest)?;
        ensure!(
            content_id(&digest)? == id,
            "ArtifactInvalid: toolchain manifest digest changed"
        );
        let root = object.join("files");
        verify_tree(&root, &manifest)?;
        Ok(NativeToolchain {
            id: id.to_string(),
            executable: root.join(&manifest.entrypoint),
            root,
            digest,
            manifest,
        })
    }

    pub fn verify(&self, toolchain: &NativeToolchain) -> Result<()> {
        let installed = self.resolve(&toolchain.id)?;
        ensure!(
            &installed == toolchain,
            "ArtifactInvalid: native toolchain binding changed"
        );
        Ok(())
    }

    fn lock(&self) -> Result<File> {
        let path = self.root.join(".import.lock");
        match create_private_file(&path) {
            Ok(file) => {
                file.sync_all()?;
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(e) => return Err(e),
        }
        let file = crate::git::open_regular_no_links(&path)?;
        file.try_lock_exclusive()
            .context("Busy: another native tool import owns the store")?;
        Ok(file)
    }
}

struct ImportGuard {
    path: PathBuf,
    published: bool,
}
impl Drop for ImportGuard {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn digest_value(value: &str) -> Result<String> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "InvalidRequest: expected lowercase SHA-256"
    );
    Ok(format!("sha256:{value}"))
}

fn content_id(digest: &str) -> Result<String> {
    let normalized = digest_value(digest)?;
    Ok(format!("native-tool-{}", &normalized[7..]))
}

fn validate_content_id(id: &str) -> Result<()> {
    let hash = id
        .strip_prefix("native-tool-")
        .context("InvalidRequest: native tool ID prefix")?;
    ensure!(
        digest_value(hash)? == format!("sha256:{hash}"),
        "InvalidRequest: native tool ID"
    );
    Ok(())
}

fn manifest_digest(manifest: &ToolchainManifest) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(serde_json::to_vec(manifest)?);
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

fn tool_path(path: &str) -> Result<()> {
    crate::git::validate_windows_relative_path(path)?;
    ensure!(
        path.len() <= MAX_PATH && path.split('/').count() <= MAX_DEPTH,
        "InvalidRequest: native tool path bound exceeded"
    );
    ensure!(
        !path
            .split('/')
            .any(|part| part.eq_ignore_ascii_case("site-packages")
                || part.eq_ignore_ascii_case(".git")
                || part.eq_ignore_ascii_case(".ssh")
                || part.eq_ignore_ascii_case(".env")
                || part.to_ascii_lowercase().starts_with(".env.")),
        "PolicyDenied: tool import is stdlib-only and excludes secrets/repository metadata"
    );
    Ok(())
}

fn normalize_manifest(manifest: &mut ToolchainManifest) -> Result<()> {
    ensure!(
        manifest.format_version == 1,
        "Unsupported: native tool manifest version"
    );
    ensure!(
        manifest.platform == "windows" && manifest.architecture == "x86_64",
        "Unsupported: only Windows x86_64 native toolchains are implemented"
    );
    ensure!(
        !manifest.id.is_empty()
            && manifest.id.len() <= 80
            && manifest
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "InvalidRequest: logical toolchain identity"
    );
    let version: Vec<_> = manifest.python_version.split('.').collect();
    ensure!(
        version.len() == 3
            && version[0] == "3"
            && version[1] == "12"
            && !version[2].is_empty()
            && version[2].len() <= 5
            && version[2].bytes().all(|b| b.is_ascii_digit()),
        "Unsupported: exact stable CPython 3.12 patch version required"
    );
    ensure!(
        manifest.entrypoint == "python.exe",
        "Unsupported: entrypoint must be python.exe"
    );
    for (field, value) in [("source", &manifest.source), ("license", &manifest.license)] {
        ensure!(
            !value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control),
            "InvalidRequest: native tool {field} must be bounded provenance text"
        );
    }
    manifest.package_sha256 = digest_value(&manifest.package_sha256)?;
    ensure!(
        !manifest.files.is_empty() && manifest.files.len() <= MAX_FILES,
        "InvalidRequest: native tool file count bound exceeded"
    );
    let mut aliases = BTreeMap::new();
    let mut files = BTreeSet::new();
    let mut total = 0u64;
    for entry in &mut manifest.files {
        tool_path(&entry.path)?;
        ensure!(
            entry.size <= MAX_FILE,
            "InvalidRequest: tool file exceeds size bound"
        );
        total = total
            .checked_add(entry.size)
            .context("tool size overflow")?;
        ensure!(
            total <= MAX_TOTAL,
            "InvalidRequest: tool tree exceeds size bound"
        );
        entry.sha256 = digest_value(&entry.sha256)?;
        ensure!(
            files.insert(entry.path.clone()),
            "InvalidRequest: duplicate tool path"
        );
        record_aliases(&entry.path, &mut aliases)?;
    }
    for path in &files {
        let mut ancestor = Path::new(path).parent();
        while let Some(parent) = ancestor {
            ensure!(
                !files.contains(parent.to_str().context("invalid tool parent")?),
                "InvalidRequest: tool file is also a directory"
            );
            ancestor = parent.parent();
        }
    }
    ensure!(
        files.contains("python.exe")
            && files.contains("python312.dll")
            && (files.contains("python312.zip") || files.contains("Lib/encodings/__init__.py")),
        "InvalidRequest: incomplete portable CPython 3.12 tree"
    );
    manifest.files.sort_by(|a, b| a.path.cmp(&b.path));
    if manifest.readonly_paths.is_empty() {
        manifest.readonly_paths.push(".".to_string());
    }
    ensure!(
        manifest.readonly_paths == ["."],
        "Unsupported: the first native profile makes the entire copied tool tree read-only"
    );
    if manifest.execute_paths.is_empty() {
        manifest.execute_paths = manifest
            .files
            .iter()
            .filter(|f| is_pe_path(&f.path))
            .map(|f| f.path.clone())
            .collect();
    }
    for path in &manifest.execute_paths {
        tool_path(path)?;
        ensure!(
            files.contains(path) && is_pe_path(path),
            "InvalidRequest: execute path must name a listed PE tool file"
        );
    }
    ensure!(
        manifest.execute_paths.iter().any(|p| p == "python.exe"),
        "InvalidRequest: python.exe must be an executable tool path"
    );
    manifest.execute_paths.sort();
    ensure!(
        manifest.execute_paths.windows(2).all(|p| p[0] != p[1]),
        "InvalidRequest: duplicate execute path"
    );
    if manifest.notices.is_empty() {
        manifest.notices = manifest
            .files
            .iter()
            .filter(|f| {
                Path::new(&f.path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.to_ascii_lowercase().starts_with("license"))
            })
            .map(|f| f.path.clone())
            .collect();
    }
    ensure!(
        !manifest.notices.is_empty(),
        "InvalidRequest: copied license/notices required"
    );
    for notice in &manifest.notices {
        tool_path(notice)?;
        ensure!(
            files.contains(notice),
            "InvalidRequest: notice is not in copied tree"
        );
    }
    manifest.notices.sort();
    ensure!(
        manifest.notices.windows(2).all(|p| p[0] != p[1]),
        "duplicate notice path"
    );
    ensure!(
        manifest.system_dependencies.len() <= 256,
        "too many OS dependencies"
    );
    for dependency in &manifest.system_dependencies {
        crate::git::validate_windows_relative_path(dependency)?;
        ensure!(
            !dependency.contains('/') && dependency.len() <= 255,
            "InvalidRequest: OS dependencies must be symbolic file names, not paths/grants"
        );
    }
    manifest.system_dependencies.sort();
    ensure!(
        manifest
            .system_dependencies
            .windows(2)
            .all(|p| p[0] != p[1]),
        "duplicate OS dependency"
    );
    Ok(())
}

fn record_aliases(path: &str, aliases: &mut BTreeMap<String, String>) -> Result<()> {
    let mut prefix = String::new();
    for component in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        if let Some(previous) = aliases.insert(prefix.to_ascii_lowercase(), prefix.clone()) {
            ensure!(
                previous == prefix,
                "InvalidRequest: Windows case-colliding tool paths"
            );
        }
    }
    Ok(())
}

fn inventory(root: &Path) -> Result<BTreeMap<String, u64>> {
    let mut files = BTreeMap::new();
    let mut aliases = BTreeMap::new();
    let mut total = 0;
    let mut entries = 0;
    walk(
        root,
        Path::new(""),
        &mut files,
        &mut aliases,
        &mut total,
        &mut entries,
    )?;
    Ok(files)
}

fn walk(
    root: &Path,
    relative: &Path,
    files: &mut BTreeMap<String, u64>,
    aliases: &mut BTreeMap<String, String>,
    total: &mut u64,
    entries: &mut usize,
) -> Result<()> {
    ensure!(
        relative.components().count() <= MAX_DEPTH,
        "ArtifactInvalid: tool tree depth bound"
    );
    let _guard = pin_directory(&root.join(relative))?;
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        *entries += 1;
        ensure!(
            *entries <= MAX_FILES * 2,
            "ArtifactInvalid: tool tree entry bound"
        );
        let child = relative.join(entry.file_name());
        let name = child
            .to_str()
            .context("ArtifactInvalid: non-UTF8 tool filename")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        tool_path(&name)?;
        record_aliases(&name, aliases)?;
        let meta = fs::symlink_metadata(entry.path())?;
        ensure!(
            !meta.file_type().is_symlink(),
            "ArtifactInvalid: tool symlink denied"
        );
        if meta.is_dir() {
            walk(root, &child, files, aliases, total, entries)?;
        } else {
            let file = crate::git::open_regular_no_links(&entry.path())?;
            let size = file.metadata()?.len();
            ensure!(
                size <= MAX_FILE && files.len() < MAX_FILES,
                "ArtifactInvalid: tool file bound"
            );
            *total = total.checked_add(size).context("tool inventory overflow")?;
            ensure!(*total <= MAX_TOTAL, "ArtifactInvalid: tool tree size bound");
            ensure!(
                files.insert(name, size).is_none(),
                "ArtifactInvalid: duplicate tool file"
            );
        }
    }
    Ok(())
}

fn require_inventory(manifest: &ToolchainManifest, actual: &BTreeMap<String, u64>) -> Result<()> {
    let expected = manifest
        .files
        .iter()
        .map(|f| (f.path.clone(), f.size))
        .collect();
    ensure!(
        actual == &expected,
        "ArtifactInvalid: source/tool tree differs from exact manifest inventory"
    );
    Ok(())
}

fn verify_tree(root: &Path, manifest: &ToolchainManifest) -> Result<()> {
    let _root = pin_directory(root)?;
    require_inventory(manifest, &inventory(root)?)?;
    for item in &manifest.files {
        let _parents = pin_relative_parents(root, Path::new(&item.path))?;
        let path = root.join(&item.path);
        let mut file = crate::git::open_regular_no_links(&path)?;
        ensure!(
            file.metadata()?.len() == item.size,
            "ArtifactInvalid: native tool size changed"
        );
        let mut sink = std::io::sink();
        ensure!(
            copy_hashed(&mut file, &mut sink, item.size)? == item.sha256,
            "ArtifactInvalid: native tool digest changed: {}",
            item.path
        );
        validate_tool_content(&path, &item.path)?;
    }
    Ok(())
}

fn copy_hashed(input: &mut File, output: &mut impl Write, expected: u64) -> Result<String> {
    ensure!(expected <= MAX_FILE, "tool read exceeds bound");
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).context("tool read overflow")?;
        ensure!(count <= expected, "ArtifactInvalid: tool grew during read");
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    ensure!(
        count == expected,
        "ArtifactInvalid: tool truncated during read"
    );
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

fn is_pe_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| {
            ["exe", "dll", "pyd"]
                .iter()
                .any(|ext| s.eq_ignore_ascii_case(ext))
        })
}

fn validate_tool_content(path: &Path, relative: &str) -> Result<()> {
    let mut file = crate::git::open_regular_no_links(path)?;
    if is_pe_path(relative) {
        let size = file.metadata()?.len();
        ensure!(size >= 64, "ArtifactInvalid: truncated PE tool: {relative}");
        let mut dos = [0u8; 64];
        file.read_exact(&mut dos)?;
        ensure!(
            &dos[..2] == b"MZ",
            "ArtifactInvalid: tool is not PE: {relative}"
        );
        let offset = u32::from_le_bytes(dos[60..64].try_into()?) as u64;
        ensure!(
            (64..=1024 * 1024).contains(&offset) && offset + 26 <= size,
            "ArtifactInvalid: invalid PE header offset: {relative}"
        );
        file.seek(SeekFrom::Start(offset))?;
        let mut header = [0u8; 26];
        file.read_exact(&mut header)?;
        ensure!(
            &header[..4] == b"PE\0\0"
                && u16::from_le_bytes(header[4..6].try_into()?) == 0x8664
                && u16::from_le_bytes(header[24..26].try_into()?) == 0x20b,
            "Unsupported: tool must be native Windows x86_64 PE32+: {relative}"
        );
    } else if relative.to_ascii_lowercase().ends_with("._pth") {
        ensure!(
            relative == "python312._pth",
            "Unsupported: unrecognized Python path configuration"
        );
        let size = file.metadata()?.len();
        ensure!(
            size <= 4096,
            "ArtifactInvalid: Python path configuration too large"
        );
        let mut text = String::new();
        file.take(4097).read_to_string(&mut text)?;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
        {
            ensure!(
                line == "." || line == "python312.zip",
                "PolicyDenied: isolated Python _pth cannot import site or external paths"
            );
        }
    } else if relative.to_ascii_lowercase().ends_with(".pth") {
        bail!("PolicyDenied: executable Python .pth hooks are not supported");
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<ToolchainManifest> {
    let parent = path.parent().context("manifest has no parent")?;
    let _parents = pin_directory_chain(parent)?;
    let file = crate::git::open_regular_no_links(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_MANIFEST,
        "InvalidRequest: tool manifest too large"
    );
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST,
        "InvalidRequest: tool manifest grew"
    );
    serde_json::from_slice(&bytes).context("InvalidRequest: malformed native tool manifest")
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|c| !matches!(c, Component::CurDir | Component::ParentDir)),
        "InvalidRequest: absolute native path cannot contain dot segments"
    );
    #[cfg(windows)]
    {
        normalize_windows_local_path(&path)
    }
    #[cfg(not(windows))]
    {
        Ok(path)
    }
}

#[cfg(windows)]
fn normalize_windows_local_path(path: &Path) -> Result<PathBuf> {
    use std::{os::windows::ffi::OsStrExt, path::Prefix};
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => {
                bail!("Unsupported: native tools require local drive paths, not UNC/device aliases")
            }
        },
        _ => bail!("Unsupported: native tools require an absolute local drive path"),
    };
    ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "InvalidRequest: native tools require an absolute local drive path"
    );
    // std::fs::canonicalize uses this spelling on Windows. Normalize ordinary
    // and canonical paths alike instead of treating the latter as a device
    // namespace, or allowing the two spellings to bypass containment checks.
    let mut normalized =
        PathBuf::from(format!(r"\\?\{}:\", char::from(drive).to_ascii_uppercase()));
    for component in components {
        let Component::Normal(name) = component else {
            bail!("InvalidRequest: absolute native path cannot contain dot segments");
        };
        let units: Vec<_> = name.encode_wide().collect();
        ensure!(
            !units.is_empty()
                && !units.iter().any(|c| matches!(*c, 0..=31 | 47 | 58 | 92))
                && !matches!(units.last(), Some(32 | 46)),
            "Unsupported: ambiguous local-drive path component"
        );
        normalized.push(name);
    }
    Ok(normalized)
}

fn pin_directory_chain(path: &Path) -> Result<Vec<File>> {
    let path = absolute_path(path)?;
    let mut current = PathBuf::new();
    let mut guards = Vec::new();
    for part in path.components() {
        current.push(part.as_os_str());
        #[cfg(windows)]
        if matches!(part, Component::Prefix(_)) {
            // A verbatim drive prefix alone can report is_absolute(), but
            // \\?\C: opens the volume rather than the root directory. Wait
            // for RootDir before pinning the first real filesystem object.
            continue;
        }
        if current.is_absolute() {
            guards.push(pin_directory(&current)?);
        }
    }
    ensure!(!guards.is_empty(), "InvalidRequest: no directory anchor");
    Ok(guards)
}

fn pin_relative_parents(root: &Path, relative: &Path) -> Result<Vec<File>> {
    let mut current = root.to_path_buf();
    let mut guards = vec![pin_directory(root)?];
    if let Some(parent) = relative.parent() {
        for part in parent.components() {
            ensure!(
                matches!(part, Component::Normal(_)),
                "unsafe relative parent"
            );
            current.push(part.as_os_str());
            guards.push(pin_directory(&current)?);
        }
    }
    Ok(guards)
}

fn create_relative_parents(root: &Path, relative: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for part in parent.components() {
            ensure!(matches!(part, Component::Normal(_)), "unsafe copied parent");
            current.push(part.as_os_str());
            private_dir(&current)?;
        }
    }
    Ok(())
}

fn private_dir(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        crate::windows_native::secure_private_dir(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let _guard = pin_directory(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        bail!("Unsupported: private native tool store on this OS")
    }
}

fn create_private_file(path: &Path) -> Result<File> {
    #[cfg(windows)]
    {
        crate::windows_native::create_private_file(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        Ok(options.open(path)?)
    }
}

#[cfg(windows)]
fn pin_directory(path: &Path) -> Result<File> {
    crate::git::pin_windows_directory(path)
}
#[cfg(unix)]
fn pin_directory(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        file.metadata()?.is_dir(),
        "ArtifactInvalid: tool parent must be a directory"
    );
    Ok(file)
}
#[cfg(not(any(windows, unix)))]
fn pin_directory(_path: &Path) -> Result<File> {
    bail!("Unsupported: directory pinning")
}

#[cfg(windows)]
fn require_ntfs(directory: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    let mut name = [0u16; 32];
    // SAFETY: `directory` owns a valid open handle; all output buffers are bounded.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    ensure!(
        ok != 0,
        "Unsupported: cannot inspect native tool volume: {}",
        std::io::Error::last_os_error()
    );
    let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
    ensure!(
        String::from_utf16(&name[..end])? == "NTFS",
        "Unsupported: native tool store requires NTFS"
    );
    Ok(())
}
#[cfg(not(windows))]
fn require_ntfs(_directory: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    pin_directory(path)?.sync_all().map_err(Into::into)
}
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, ToolchainManifest) {
        let temp = tempfile::TempDir::new_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let source = temp.path().join("input");
        fs::create_dir(&source).unwrap();
        let values = [
            ("python.exe", pe()),
            ("python312.dll", pe()),
            ("python312.zip", b"pinned stdlib fixture".to_vec()),
            ("LICENSE.txt", b"PSF license fixture".to_vec()),
        ];
        let files = values
            .iter()
            .map(|(path, bytes)| {
                fs::write(source.join(path), bytes).unwrap();
                ToolchainFile {
                    path: path.to_string(),
                    size: bytes.len() as u64,
                    sha256: hex::encode(Sha256::digest(bytes)),
                }
            })
            .collect();
        let manifest = ToolchainManifest {
            format_version: 1,
            id: "python312-fixture".into(),
            platform: "windows".into(),
            architecture: "x86_64".into(),
            python_version: "3.12.10".into(),
            entrypoint: "python.exe".into(),
            source: "own nonexecuted test bytes".into(),
            package_sha256: "0".repeat(64),
            license: "PSF".into(),
            files,
            readonly_paths: vec![],
            execute_paths: vec![],
            system_dependencies: vec![],
            notices: vec![],
        };
        let path = temp.path().join("source-manifest.json");
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        (temp, source, path, manifest)
    }

    #[test]
    fn copied_content_identity_survives_source_change_and_detects_store_tampering() {
        let (temp, source, path, _) = fixture();
        let store = NativeToolStore::open(temp.path().join("store")).unwrap();
        let tool = store.import(&source, &path).unwrap();
        assert_eq!(store.import(&source, &path).unwrap(), tool);
        assert_eq!(store.list().unwrap(), vec![tool.clone()]);
        fs::write(source.join("LICENSE.txt"), b"source changed").unwrap();
        store.verify(&tool).unwrap();
        fs::write(tool.root.join("LICENSE.txt"), b"store changed").unwrap();
        assert!(store.verify(&tool).is_err());
    }

    #[test]
    fn rejected_imports_never_publish_an_object() {
        let (temp, source, path, mut manifest) = fixture();
        let store = NativeToolStore::open(temp.path().join("store")).unwrap();
        manifest.files[0].sha256 = "1".repeat(64);
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(store.import(&source, &path).is_err());
        assert!(store.list().unwrap().is_empty());
        manifest.files[0].path = "../python.exe".into();
        assert!(normalize_manifest(&mut manifest).is_err());
        assert!(store.resolve("../../other").is_err());
    }

    #[test]
    fn unlisted_files_and_case_aliases_are_rejected() {
        let (temp, source, path, mut manifest) = fixture();
        let store = NativeToolStore::open(temp.path().join("store")).unwrap();
        fs::write(source.join("unlisted.txt"), b"unknown").unwrap();
        assert!(store.import(&source, &path).is_err());
        let mut alias = manifest.files[0].clone();
        alias.path = "PYTHON.EXE".into();
        manifest.files.push(alias);
        assert!(normalize_manifest(&mut manifest).is_err());
    }

    #[test]
    fn non_x64_or_active_pth_configuration_is_rejected() {
        let (temp, _, _, _) = fixture();
        let file = temp.path().join("bad.exe");
        let mut bytes = pe();
        bytes[68..70].copy_from_slice(&0x14cu16.to_le_bytes());
        fs::write(&file, bytes).unwrap();
        assert!(validate_tool_content(&file, "python.exe").is_err());
        fs::write(&file, "python312.zip\n.\nimport site\n").unwrap();
        assert!(validate_tool_content(&file, "python312._pth").is_err());
        fs::write(&file, "python312.zip\n.\n# import site\n").unwrap();
        validate_tool_content(&file, "python312._pth").unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn local_drive_spellings_match_without_accepting_other_namespaces() {
        assert_eq!(
            normalize_windows_local_path(Path::new(r"c:\private\tools")).unwrap(),
            normalize_windows_local_path(Path::new(r"\\?\C:\private\tools")).unwrap()
        );
        for path in [
            r"\\server\share\tools",
            r"\\?\UNC\server\share\tools",
            r"\\.\C:\tools",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\tools",
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\tools",
            r"C:relative",
            r"\\?\C:\private/../tools",
            r"C:\private\trailing.",
            r"C:\private\tool:stream",
        ] {
            assert!(
                normalize_windows_local_path(Path::new(path)).is_err(),
                "{path}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn canonical_execution_store_path_opens_tool_store_and_imports() {
        let (temp, source, path, _) = fixture();
        let control = crate::execution::Store::open(temp.path().join("private")).unwrap();
        let store = NativeToolStore::open(control.root.join("toolchains")).unwrap();
        assert_eq!(
            store.root,
            control.root.join("toolchains").canonicalize().unwrap()
        );
        let tool = store.import(&source, &path).unwrap();
        store.verify(&tool).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn canonical_directory_chain_starts_at_the_drive_root_directory() {
        let temporary =
            tempfile::TempDir::new_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().canonicalize().unwrap();
        let guards = pin_directory_chain(&path).unwrap();
        let expected = path
            .components()
            .filter(|part| !matches!(part, Component::Prefix(_)))
            .count();
        assert_eq!(guards.len(), expected);
        assert!(guards.first().unwrap().metadata().unwrap().is_dir());
        assert!(guards
            .iter()
            .all(|guard| guard.metadata().unwrap().is_dir()));
    }

    #[cfg(windows)]
    #[test]
    fn canonical_and_ordinary_spellings_cannot_hide_source_store_overlap() {
        let (temp, source, path, _) = fixture();
        let store = NativeToolStore::open(source.join("inside-store")).unwrap();
        assert!(store
            .import(&source, &path)
            .unwrap_err()
            .to_string()
            .contains("must not contain"));
        assert!(store
            .import(&source.canonicalize().unwrap(), &path)
            .unwrap_err()
            .to_string()
            .contains("must not contain"));
        drop(store);

        let store = NativeToolStore::open(temp.path().join("outside-store")).unwrap();
        let nested = temp.path().join("outside-store").join("nested-input");
        fs::create_dir(&nested).unwrap();
        assert!(store
            .import(&nested, &path)
            .unwrap_err()
            .to_string()
            .contains("must not contain"));
        assert!(store
            .import(&nested.canonicalize().unwrap(), &path)
            .unwrap_err()
            .to_string()
            .contains("must not contain"));
    }

    #[cfg(windows)]
    #[test]
    fn manifest_containment_uses_the_same_local_drive_spelling() {
        let (temp, source, path, _) = fixture();
        let store = NativeToolStore::open(temp.path().join("store")).unwrap();
        let inside = source.join("manifest.json");
        fs::copy(&path, &inside).unwrap();
        for (source, manifest) in [
            (source.canonicalize().unwrap(), inside.clone()),
            (source, inside.canonicalize().unwrap()),
        ] {
            assert!(store
                .import(&source, &manifest)
                .unwrap_err()
                .to_string()
                .contains("outside the source"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn linked_tool_bytes_and_linked_ancestors_are_rejected() {
        use std::os::unix::fs::symlink;
        let (temp, source, path, _) = fixture();
        let store = NativeToolStore::open(temp.path().join("store")).unwrap();
        fs::hard_link(source.join("python.exe"), temp.path().join("alias.exe")).unwrap();
        assert!(store.import(&source, &path).is_err());
        symlink(&source, temp.path().join("input-link")).unwrap();
        assert!(store
            .import(&temp.path().join("input-link"), &path)
            .is_err());
    }
}
