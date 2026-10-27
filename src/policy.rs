//! Host-side configuration. Unsupported enforcement is an error, never a hint.
//!
//! ADR-009: phase 1 provides an isolated network namespace only. A DNS allowlist
//! without a matching egress boundary is not a security policy.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub stack: Option<String>,
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Empty means no network. Non-empty requests are rejected until enforced.
    pub network: Vec<String>,
    /// Additional denied path components; the mandatory defaults always apply.
    /// Supported grammar: one exact component or a component ending in `*`.
    pub deny_paths: Vec<String>,
    /// Per-process virtual address-space limit, not a cgroup RSS guarantee.
    pub memory_bytes: u64,
    /// Per-process CPU-time limit, not a CPU utilization percentage.
    pub cpu_seconds: u64,
    /// Per-user process limit; see runtime caveats about shared host UIDs.
    pub max_processes: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            network: Vec::new(),
            deny_paths: vec![".env".into(), ".env.*".into(), ".ssh".into()],
            memory_bytes: 1024 * 1024 * 1024,
            cpu_seconds: 300,
            max_processes: 128,
        }
    }
}

impl Config {
    /// `path` is the configuration file, not the project directory.
    pub fn load(path: &Path) -> Result<Self> {
        let config = match std::fs::read(path) {
            Ok(bytes) => {
                if bytes.len() > 1024 * 1024 {
                    bail!("petri.yaml exceeds the 1 MiB configuration limit");
                }
                serde_saphyr::from_slice::<Self>(&bytes)
                    .with_context(|| format!("invalid configuration {}", path.display()))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", path.display()));
            }
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self
            .stack
            .as_ref()
            .is_some_and(|name| name.trim().is_empty())
        {
            bail!("stack must be a non-empty stack name");
        }
        self.policy.validate()
    }
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        if !self.network.is_empty() {
            bail!("NotImplemented: network allowlists require an enforced egress proxy; phase 1 only supports policy.network: [] (no network)");
        }
        if self.memory_bytes == 0 || self.cpu_seconds == 0 || self.max_processes == 0 {
            bail!("resource limits must be greater than zero");
        }
        // rlim_t differs by target. Reject values that cannot be represented by
        // the signed kernel limits used by supported 64-bit targets.
        if [self.memory_bytes, self.cpu_seconds, self.max_processes]
            .iter()
            .any(|limit| *limit > i64::MAX as u64)
        {
            bail!("resource limits must not exceed i64::MAX");
        }
        // ADR-014: custom export policies are not yet wired through every Git snapshot.
        // Reject them instead of silently weakening a requested policy.
        if self.deny_paths != Self::default().deny_paths {
            bail!("NotImplemented: custom deny_paths; mandatory .env/.env.*/.ssh/docker.sock exclusions are always enforced");
        }
        for rule in &self.deny_paths {
            let prefix = rule.strip_suffix('*').unwrap_or(rule);
            if prefix.is_empty()
                || prefix == "."
                || prefix == ".."
                || prefix.contains(['/', '\\', '*', '?', '[', ']', '\0'])
            {
                bail!("unsupported deny_paths rule {rule:?}; use an exact path component or a non-empty component prefix followed by *");
            }
        }
        Ok(())
    }

    /// Rules apply to path components, so `.ssh/id_rsa` is denied at any depth.
    /// They are enforced by host-side export/checkpoint logic, not Landlock.
    pub fn path_denied(&self, path: &Path) -> bool {
        path_denied(path)
            || path.components().any(|component| match component {
                Component::Normal(name) => name.to_str().is_none_or(|name| {
                    self.deny_paths
                        .iter()
                        .any(|rule| match rule.strip_suffix('*') {
                            Some(prefix) => name.starts_with(prefix),
                            None => name == rule,
                        })
                }),
                _ => false,
            })
    }
}

/// Mandatory export exclusions. Also blocks traversal, absolute paths and
/// non-UTF-8 names so callers cannot accidentally normalize a secret into view.
pub fn path_denied(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => name.to_str().is_none_or(|name| {
            name == ".env" || name.starts_with(".env.") || name == ".ssh" || name == "docker.sock"
        }),
        Component::ParentDir | Component::RootDir | Component::Prefix(_) => true,
        Component::CurDir => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_file_is_safe_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(&dir.path().join("petri.yaml")).unwrap();
        assert!(config.policy.network.is_empty());
        assert_eq!(config.policy.memory_bytes, 1024 * 1024 * 1024);
    }

    #[test]
    fn refuses_unsupported_network_and_unknown_fields() {
        for yaml in [
            "network: []",
            "policy:\n  netwrok: []",
            "policy:\n  network: [registry.npmjs.org]",
            "policy:\n  memory_bytes: 0",
            "policy:\n  deny_paths: ['**/.env']",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("petri.yaml");
            std::fs::write(&path, yaml).unwrap();
            assert!(Config::load(&path).is_err(), "accepted {yaml}");
        }
    }

    #[test]
    fn strict_valid_config_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("petri.yaml");
        std::fs::write(
            &path,
            "stack: alpine\npolicy:\n  network: []\n  cpu_seconds: 30\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.stack.as_deref(), Some("alpine"));
        assert!(config.policy.path_denied(Path::new("nested/.env.local")));
        assert!(!config.policy.path_denied(Path::new("src/main.rs")));
    }

    #[test]
    fn custom_deny_paths_require_enforcement_before_acceptance() {
        let policy = Policy {
            deny_paths: vec!["private*".into()],
            ..Policy::default()
        };
        assert!(policy.path_denied(Path::new("nested/private-key")));
        assert!(policy.path_denied(Path::new("nested/.env.local")));
        assert!(policy
            .validate()
            .unwrap_err()
            .to_string()
            .contains("NotImplemented"));
    }

    #[test]
    fn path_rules_cover_ancestors_and_traversal() {
        for denied in [
            ".env",
            "a/.env.local",
            ".ssh/key",
            "a/docker.sock",
            "../key",
            "/tmp/key",
        ] {
            assert!(path_denied(Path::new(denied)), "not denied: {denied}");
        }
        for allowed in [".environment", "src/env.rs", "a/ssh", "README.md"] {
            assert!(
                !path_denied(Path::new(allowed)),
                "unexpected denial: {allowed}"
            );
        }
    }
}
