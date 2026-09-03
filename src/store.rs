use std::collections::VecDeque;

use chrono::{SecondsFormat, Utc};
use serde::Serialize;

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
    max_commands: usize,
    max_output_bytes: usize,
}

impl Store {
    pub fn new(max_commands: usize, max_output_bytes: usize) -> Self {
        Self {
            records: VecDeque::new(),
            next_id: 1,
            open: None,
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
