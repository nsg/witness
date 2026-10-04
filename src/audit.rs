use std::{
    fs::{File, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;

use crate::api::Notifier;

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent<'a> {
    SessionStarted {
        auto_approve: bool,
    },
    Suggested {
        suggestion_id: u64,
        command: &'a str,
        reason: Option<&'a str>,
        via: &'static str,
    },
    SuggestionRejected {
        command: &'a str,
        error: &'a str,
        via: &'static str,
    },
    /// The human pulled the suggestion into their prompt with Ctrl-G.
    Inserted {
        suggestion_id: u64,
        command: &'a str,
    },
    /// Witness typed the suggestion and Enter into the shell on its own.
    AutoApproved {
        suggestion_id: u64,
        command: &'a str,
        reason: Option<&'a str>,
    },
    CommandStarted {
        command_id: u64,
        command: &'a str,
    },
    CommandFinished {
        command_id: u64,
        exit_code: Option<i32>,
    },
}

#[derive(Serialize)]
struct Entry<'a> {
    at: String,
    session: u32,
    #[serde(flatten)]
    event: &'a AuditEvent<'a>,
}

/// Append-only JSON Lines log shared by every witness session of this user.
pub struct AuditLog {
    file: Mutex<File>,
    path: PathBuf,
    warned: AtomicBool,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create audit log directory {}", parent.display())
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to open audit log {}", path.display()))?;
        // Writes to a device such as /dev/null would succeed and keep nothing.
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            anyhow::bail!("audit log {} is not a regular file", path.display());
        }
        Ok(Self {
            file: Mutex::new(file),
            path: path.to_owned(),
            warned: AtomicBool::new(false),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, event: &AuditEvent) -> io::Result<()> {
        let mut line = serde_json::to_vec(&Entry {
            at: Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true),
            session: std::process::id(),
            event,
        })?;
        line.push(b'\n');
        // One write per entry keeps lines whole when sessions share the file.
        self.file.lock().unwrap().write_all(&line)
    }

    /// For events that record what already happened: a failed write cannot
    /// undo them, so tell the human once instead.
    pub fn record_or_warn(&self, notifier: &Notifier, event: &AuditEvent) {
        if let Err(error) = self.record(event)
            && !self.warned.swap(true, Ordering::Relaxed)
        {
            let _ = notifier.write(
                format!(
                    "\r\n\x1b[1;31m(witness) audit log {} is failing: {error}\x1b[0m\r\n",
                    self.path.display()
                )
                .as_bytes(),
            );
        }
    }
}

pub fn default_path() -> Option<PathBuf> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".local/state")))?;
    Some(state.join("witness/audit.log"))
}

#[cfg(test)]
mod tests {
    use super::{AuditEvent, AuditLog};

    #[test]
    fn appends_one_json_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/audit.log");
        let log = AuditLog::open(&path).unwrap();
        log.record(&AuditEvent::AutoApproved {
            suggestion_id: 3,
            command: "echo \"hi\"",
            reason: None,
        })
        .unwrap();
        log.record(&AuditEvent::CommandFinished {
            command_id: 1,
            exit_code: Some(0),
        })
        .unwrap();
        log.record(&AuditEvent::Suggested {
            suggestion_id: 4,
            command: "echo relay",
            reason: None,
            via: "relay",
        })
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let entries: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0]["event"], "auto_approved");
        assert_eq!(entries[0]["command"], "echo \"hi\"");
        assert_eq!(entries[0]["suggestion_id"], 3);
        assert!(entries[0]["at"].is_string());
        assert_eq!(entries[1]["event"], "command_finished");
        assert_eq!(entries[2]["via"], "relay");
    }
}
