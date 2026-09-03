use std::collections::VecDeque;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub last_id: Option<u64>,
    pub last_command_at: Option<String>,
    pub age_seconds: Option<f64>,
    pub running: bool,
    pub count: u64,
    pub pending_suggestions: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SuggestionStatus {
    Pending,
    Inserted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    pub id: u64,
    pub command: String,
    pub reason: Option<String>,
    pub created_at: String,
    pub status: SuggestionStatus,
    pub inserted_at: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuggestError {
    QueueFull,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommandRecord {
    pub id: u64,
    pub command: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub exit_code: Option<i32>,
    pub output: String,
    pub truncated: bool,
    pub running: bool,
}

#[derive(Debug)]
struct OpenCommand {
    id: u64,
    command: String,
    started_at: String,
    output: Vec<u8>,
    truncated: bool,
}

#[derive(Debug)]
pub struct Store {
    records: VecDeque<CommandRecord>,
    next_id: u64,
    open: Option<OpenCommand>,
    suggestions: Vec<Suggestion>,
    next_suggestion_id: u64,
    pending_notices: Vec<String>,
    max_commands: usize,
    max_output_bytes: usize,
}

impl Store {
    pub fn new(max_commands: usize, max_output_bytes: usize) -> Self {
        Self {
            records: VecDeque::new(),
            next_id: 1,
            open: None,
            suggestions: Vec::new(),
            next_suggestion_id: 1,
            pending_notices: Vec::new(),
            max_commands,
            max_output_bytes,
        }
    }

    pub fn begin(&mut self, command: String) {
        self.finish_open(None);
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.open = Some(OpenCommand {
            id,
            command,
            started_at: now(),
            output: Vec::new(),
            truncated: false,
        });
    }

    pub fn append_output(&mut self, bytes: &[u8]) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let remaining = self.max_output_bytes.saturating_sub(open.output.len());
        let accepted = remaining.min(bytes.len());
        open.output.extend_from_slice(&bytes[..accepted]);
        if accepted < bytes.len() {
            open.truncated = true;
        }
    }

    pub fn end(&mut self, code: i32) {
        if self.open.is_some() {
            self.finish_open(Some(code));
        }
    }

    pub fn finish_open(&mut self, exit_code: Option<i32>) {
        let Some(open) = self.open.take() else {
            return;
        };
        let record = CommandRecord {
            id: open.id,
            command: open.command,
            started_at: open.started_at,
            finished_at: Some(now()),
            exit_code,
            output: String::from_utf8_lossy(&open.output).into_owned(),
            truncated: open.truncated,
            running: false,
        };
        self.push(record);
    }

    pub fn commands_since(&self, since: u64) -> Vec<CommandRecord> {
        let mut records: Vec<_> = self
            .records
            .iter()
            .filter(|record| record.id > since)
            .cloned()
            .collect();
        if let Some(open) = &self.open
            && open.id > since
        {
            records.push(open_record(open));
        }
        records
    }

    pub fn command(&self, id: u64) -> Option<CommandRecord> {
        self.records
            .iter()
            .find(|record| record.id == id)
            .cloned()
            .or_else(|| {
                self.open
                    .as_ref()
                    .filter(|open| open.id == id)
                    .map(open_record)
            })
    }

    pub fn tail(&self, count: usize) -> Vec<CommandRecord> {
        let skip = self.records.len().saturating_sub(count);
        self.records.iter().skip(skip).cloned().collect()
    }

    pub fn add_suggestion(
        &mut self,
        command: String,
        reason: Option<String>,
    ) -> Result<Suggestion, SuggestError> {
        if self.pending_suggestions() >= 10 {
            return Err(SuggestError::QueueFull);
        }
        let suggestion = Suggestion {
            id: self.next_suggestion_id,
            command,
            reason,
            created_at: now(),
            status: SuggestionStatus::Pending,
            inserted_at: None,
        };
        self.next_suggestion_id = self.next_suggestion_id.saturating_add(1);
        self.suggestions.push(suggestion.clone());
        Ok(suggestion)
    }

    pub fn pop_pending_suggestion(&mut self) -> Option<Suggestion> {
        loop {
            let index = self
                .suggestions
                .iter()
                .position(|suggestion| suggestion.status == SuggestionStatus::Pending)?;
            if validate_suggestion(&self.suggestions[index].command).is_err() {
                self.suggestions.remove(index);
                continue;
            }
            let suggestion = &mut self.suggestions[index];
            suggestion.status = SuggestionStatus::Inserted;
            suggestion.inserted_at = Some(now());
            return Some(suggestion.clone());
        }
    }

    pub fn suggestions(&self) -> Vec<Suggestion> {
        self.suggestions.clone()
    }

    pub fn pending_suggestions(&self) -> usize {
        self.suggestions
            .iter()
            .filter(|suggestion| suggestion.status == SuggestionStatus::Pending)
            .count()
    }

    pub fn command_is_open(&self) -> bool {
        self.open.is_some()
    }

    pub fn push_pending_notice(&mut self, notice: String) {
        self.pending_notices.push(notice);
    }

    pub fn take_pending_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_notices)
    }

    /// Lightweight snapshot for cheap polling: the newest command's id and
    /// timestamp, how long ago it happened, and whether one is running.
    pub fn status(&self) -> Status {
        let (last_id, at, running) = if let Some(open) = &self.open {
            (Some(open.id), Some(open.started_at.clone()), true)
        } else if let Some(last) = self.records.back() {
            let at = last
                .finished_at
                .clone()
                .unwrap_or_else(|| last.started_at.clone());
            (Some(last.id), Some(at), false)
        } else {
            (None, None, false)
        };
        Status {
            last_id,
            age_seconds: at.as_deref().and_then(age_seconds),
            last_command_at: at,
            running,
            count: self.next_id.saturating_sub(1),
            pending_suggestions: self.pending_suggestions(),
        }
    }

    fn push(&mut self, record: CommandRecord) {
        if self.max_commands == 0 {
            return;
        }
        if self.records.len() == self.max_commands {
            self.records.pop_front();
        }
        self.records.push_back(record);
    }
}

pub fn validate_suggestion(command: &str) -> Result<(), &'static str> {
    if command.trim().is_empty() {
        return Err("empty command");
    }
    if command.len() > 1024 {
        return Err("command too long");
    }
    if command.chars().any(char::is_control) {
        return Err("control characters not allowed");
    }
    Ok(())
}

fn open_record(open: &OpenCommand) -> CommandRecord {
    CommandRecord {
        id: open.id,
        command: open.command.clone(),
        started_at: open.started_at.clone(),
        finished_at: None,
        exit_code: None,
        output: String::from_utf8_lossy(&open.output).into_owned(),
        truncated: open.truncated,
        running: true,
    }
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn age_seconds(rfc3339: &str) -> Option<f64> {
    let parsed = DateTime::parse_from_rfc3339(rfc3339).ok()?;
    let elapsed = Utc::now()
        .signed_duration_since(parsed.with_timezone(&Utc))
        .num_milliseconds() as f64
        / 1000.0;
    Some(elapsed.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::{Store, SuggestError, SuggestionStatus, validate_suggestion};

    #[test]
    fn validates_safe_suggestion() {
        assert_eq!(validate_suggestion("systemctl status nginx"), Ok(()));
    }

    #[test]
    fn rejects_empty_suggestion() {
        assert_eq!(validate_suggestion(" \u{2003} "), Err("empty command"));
    }

    #[test]
    fn rejects_too_long_suggestion() {
        assert_eq!(
            validate_suggestion(&"x".repeat(1025)),
            Err("command too long")
        );
    }

    #[test]
    fn rejects_newline_in_suggestion() {
        assert_eq!(
            validate_suggestion("printf hello\nwhoami"),
            Err("control characters not allowed")
        );
    }

    #[test]
    fn rejects_escape_in_suggestion() {
        assert_eq!(
            validate_suggestion("echo \x1b[31mred"),
            Err("control characters not allowed")
        );
    }

    #[test]
    fn suggestion_queue_caps_pending_items_at_ten() {
        let mut store = Store::new(10, 1024);
        for index in 0..10 {
            store.add_suggestion(format!("echo {index}"), None).unwrap();
        }
        assert_eq!(store.pending_suggestions(), 10);
        assert_eq!(
            store.add_suggestion("echo overflow".into(), None),
            Err(SuggestError::QueueFull)
        );
    }

    #[test]
    fn suggestions_pop_fifo_and_are_marked_inserted() {
        let mut store = Store::new(10, 1024);
        let first = store.add_suggestion("echo first".into(), None).unwrap();
        let second = store.add_suggestion("echo second".into(), None).unwrap();

        let popped = store.pop_pending_suggestion().unwrap();
        assert_eq!(popped.id, first.id);
        assert_eq!(popped.status, SuggestionStatus::Inserted);
        assert!(popped.inserted_at.is_some());
        assert_eq!(store.pending_suggestions(), 1);
        assert_eq!(store.pop_pending_suggestion().unwrap().id, second.id);

        let suggestions = store.suggestions();
        assert_eq!(suggestions.len(), 2);
        assert!(
            suggestions
                .iter()
                .all(|suggestion| suggestion.status == SuggestionStatus::Inserted)
        );
    }

    #[test]
    fn invalid_pending_suggestions_are_dropped_at_pop() {
        let mut store = Store::new(10, 1024);
        store.add_suggestion("bad\ncommand".into(), None).unwrap();
        let valid = store.add_suggestion("echo safe".into(), None).unwrap();

        assert_eq!(store.pop_pending_suggestion().unwrap().id, valid.id);
        assert_eq!(store.suggestions().len(), 1);
    }

    #[test]
    fn status_includes_pending_suggestion_count() {
        let mut store = Store::new(10, 1024);
        store.add_suggestion("echo one".into(), None).unwrap();
        store.add_suggestion("echo two".into(), None).unwrap();
        assert_eq!(store.status().pending_suggestions, 2);
        store.pop_pending_suggestion();
        assert_eq!(store.status().pending_suggestions, 1);
    }
}
