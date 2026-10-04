use std::{
    fs::File,
    io::Write as _,
    sync::{Arc, Mutex},
};

use crate::{
    api::Notifier,
    audit::{AuditEvent, AuditLog},
    store::{Store, Suggestion, SuggestionStatus},
};

/// Runs queued suggestions without waiting for Ctrl-G by typing them, plus
/// Enter, into the shell. Only one is released per idle prompt, so each runs
/// to completion before the next and never lands in a half-typed line or a
/// running program.
pub struct AutoApprover {
    store: Arc<Mutex<Store>>,
    notifier: Notifier,
    audit: Arc<AuditLog>,
    writer: Arc<Mutex<File>>,
}

impl AutoApprover {
    pub fn new(
        store: Arc<Mutex<Store>>,
        notifier: Notifier,
        audit: Arc<AuditLog>,
        writer: Arc<Mutex<File>>,
    ) -> Self {
        Self {
            store,
            notifier,
            audit,
            writer,
        }
    }

    /// Returns whether a suggestion was sent to the shell.
    pub fn dispatch_next(&self) -> bool {
        // Holding the writer keeps human keystrokes from slipping in between
        // the idle check and the injected line. If it is taken, the human is
        // typing right now, so the prompt is theirs anyway; not waiting also
        // keeps the PTY reader from stalling behind a blocked write.
        let Ok(mut writer) = self.writer.try_lock() else {
            return false;
        };
        let suggestion = {
            let mut store = self.store.lock().unwrap();
            if !store.prompt_idle() {
                return false;
            }
            let Some(suggestion) = store.next_pending_suggestion() else {
                return false;
            };
            // Fail closed: nothing runs unless it is on record first.
            if let Err(error) = self.audit.record(&AuditEvent::AutoApproved {
                suggestion_id: suggestion.id,
                command: &suggestion.command,
                reason: suggestion.reason.as_deref(),
            }) {
                drop(store);
                let _ = self.notifier.write(
                    format!(
                        "\r\n\x1b[1;31m(witness) audit log write failed ({error}); suggestion #{} was NOT run\x1b[0m\r\n",
                        suggestion.id
                    )
                    .as_bytes(),
                );
                return false;
            }
            store.resolve_suggestion(suggestion.id, SuggestionStatus::AutoApproved);
            store.prompt_taken();
            suggestion
        };
        let _ = self
            .notifier
            .write(render_auto_notice(&suggestion).as_bytes());
        let mut line = suggestion.command.into_bytes();
        line.push(b'\r');
        writer
            .write_all(&line)
            .and_then(|()| writer.flush())
            .is_ok()
    }
}

fn render_auto_notice(suggestion: &Suggestion) -> String {
    let mut notice = format!(
        "\r\n\x1b[1;33m(witness) auto-approved suggestion #{} — running\x1b[0m\r\n",
        suggestion.id
    );
    if let Some(reason) = suggestion.reason.as_deref() {
        notice.push_str(&format!("\x1b[2m# {reason}\x1b[0m\r\n"));
    }
    notice
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Seek as _},
        sync::{Arc, Mutex},
    };

    use super::AutoApprover;
    use crate::{
        api::Notifier,
        audit::AuditLog,
        store::{Store, SuggestionStatus},
    };

    fn approver(store: &Arc<Mutex<Store>>) -> (AutoApprover, std::fs::File, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(&dir.path().join("audit.log")).unwrap());
        let shell = tempfile::tempfile().unwrap();
        let writer = Arc::new(Mutex::new(shell.try_clone().unwrap()));
        let approver = AutoApprover::new(Arc::clone(store), Notifier::new(), audit, writer);
        (approver, shell, dir)
    }

    fn typed(shell: &mut std::fs::File) -> String {
        let mut typed = String::new();
        shell.rewind().unwrap();
        shell.read_to_string(&mut typed).unwrap();
        typed
    }

    #[test]
    fn runs_one_suggestion_per_idle_prompt() {
        let store = Arc::new(Mutex::new(Store::new(10, 1024)));
        let (approver, mut shell, dir) = approver(&store);
        {
            let mut store = store.lock().unwrap();
            store.add_suggestion("echo one".into(), None).unwrap();
            store.add_suggestion("echo two".into(), None).unwrap();
            store.prompt_shown();
        }

        assert!(approver.dispatch_next());
        assert!(!approver.dispatch_next(), "second waits for a new prompt");
        assert_eq!(typed(&mut shell), "echo one\r");

        let suggestions = store.lock().unwrap().suggestions();
        assert_eq!(suggestions[0].status, SuggestionStatus::AutoApproved);
        assert_eq!(suggestions[1].status, SuggestionStatus::Pending);
        let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(audit.contains(r#""event":"auto_approved""#) && audit.contains("echo one"));
    }

    #[test]
    fn holds_suggestions_while_the_prompt_is_busy() {
        let store = Arc::new(Mutex::new(Store::new(10, 1024)));
        let (approver, mut shell, _dir) = approver(&store);
        store
            .lock()
            .unwrap()
            .add_suggestion("echo one".into(), None)
            .unwrap();

        assert!(!approver.dispatch_next());
        assert_eq!(typed(&mut shell), "");
        assert_eq!(store.lock().unwrap().pending_suggestions(), 1);
    }
}
