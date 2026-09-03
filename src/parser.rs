const WITNESS_PREFIX: &[u8] = b"\x1b]1337;witness;";
const ALT_SEQUENCES: &[(&[u8], bool)] = &[
    (b"\x1b[?1049h", true),
    (b"\x1b[?47h", true),
    (b"\x1b[?1047h", true),
    (b"\x1b[?1049l", false),
    (b"\x1b[?47l", false),
    (b"\x1b[?1047l", false),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseEvent {
    Begin(String),
    End(i32),
}

#[derive(Debug, PartialEq, Eq)]
pub enum StreamAction {
    Output(Vec<u8>, bool),
    Event(ParseEvent),
}

#[derive(Debug, Default)]
pub struct FeedResult {
    pub cleaned: Vec<u8>,
    pub events: Vec<ParseEvent>,
    pub actions: Vec<StreamAction>,
}

#[derive(Default)]
pub struct MarkerParser {
    candidate: Vec<u8>,
    marker_payload: Vec<u8>,
    in_marker: bool,
    marker_escape: bool,
    alt: AltScreenTracker,
}

impl MarkerParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> FeedResult {
        let mut result = FeedResult::default();
        for &byte in bytes {
            if self.in_marker {
                self.feed_marker(byte, &mut result);
            } else {
                self.feed_candidate(byte, &mut result);
            }
        }
        result
    }

    pub fn finish(&mut self) -> FeedResult {
        let mut result = FeedResult::default();
        if self.in_marker {
            self.emit_clean(WITNESS_PREFIX, &mut result);
            let payload = std::mem::take(&mut self.marker_payload);
            self.emit_clean(&payload, &mut result);
            if self.marker_escape {
                self.emit_clean(b"\x1b", &mut result);
            }
        } else {
            let candidate = std::mem::take(&mut self.candidate);
            self.emit_clean(&candidate, &mut result);
        }
        self.in_marker = false;
        self.marker_escape = false;
        for (bytes, capture) in self.alt.flush() {
            push_output_action(&mut result.actions, bytes, capture);
        }
        result
    }

    #[allow(dead_code)]
    pub fn alt_screen_active(&self) -> bool {
        self.alt.active
    }

    fn feed_candidate(&mut self, byte: u8, result: &mut FeedResult) {
        if self.candidate.is_empty() && byte != 0x1b {
            self.emit_clean(&[byte], result);
            return;
        }

        self.candidate.push(byte);
        while !self.candidate.is_empty() && !WITNESS_PREFIX.starts_with(&self.candidate) {
            let first = self.candidate.remove(0);
            self.emit_clean(&[first], result);
        }
        if self.candidate == WITNESS_PREFIX {
            self.candidate.clear();
            self.in_marker = true;
            self.marker_payload.clear();
            self.marker_escape = false;
        }
    }

    fn feed_marker(&mut self, byte: u8, result: &mut FeedResult) {
        if self.marker_escape {
            self.marker_escape = false;
            if byte == b'\\' {
                self.finish_marker(b"\x1b\\", result);
                return;
            }
            self.marker_payload.push(0x1b);
        }

        match byte {
            0x07 => self.finish_marker(b"\x07", result),
            0x1b => self.marker_escape = true,
            _ => self.marker_payload.push(byte),
        }
    }

    fn finish_marker(&mut self, terminator: &[u8], result: &mut FeedResult) {
        self.in_marker = false;
        self.marker_escape = false;
        let payload = std::mem::take(&mut self.marker_payload);
        let event = if let Some(command) = payload.strip_prefix(b"B;") {
            Some(ParseEvent::Begin(
                String::from_utf8_lossy(command).into_owned(),
            ))
        } else if let Some(code) = payload.strip_prefix(b"E;") {
            String::from_utf8_lossy(code)
                .parse::<i32>()
                .ok()
                .map(ParseEvent::End)
        } else {
            None
        };
        if let Some(event) = event {
            for (bytes, capture) in self.alt.flush() {
                push_output_action(&mut result.actions, bytes, capture);
            }
            result.events.push(event.clone());
            result.actions.push(StreamAction::Event(event));
        } else {
            self.emit_clean(WITNESS_PREFIX, result);
            self.emit_clean(&payload, result);
            self.emit_clean(terminator, result);
        }
    }

    fn emit_clean(&mut self, bytes: &[u8], result: &mut FeedResult) {
        result.cleaned.extend_from_slice(bytes);
        for &byte in bytes {
            for (bytes, capture) in self.alt.feed(byte) {
                push_output_action(&mut result.actions, bytes, capture);
            }
        }
    }
}

#[derive(Default)]
struct AltScreenTracker {
    active: bool,
    candidate: Vec<u8>,
}

impl AltScreenTracker {
    fn feed(&mut self, byte: u8) -> Vec<(Vec<u8>, bool)> {
        let mut output = Vec::new();
        if self.candidate.is_empty() && byte != 0x1b {
            output.push((vec![byte], !self.active));
            return output;
        }

        self.candidate.push(byte);
        loop {
            if let Some((_, entering)) = ALT_SEQUENCES
                .iter()
                .find(|(sequence, _)| *sequence == self.candidate)
            {
                let sequence = std::mem::take(&mut self.candidate);
                output.push((sequence, false));
                self.active = *entering;
                break;
            }
            if ALT_SEQUENCES
                .iter()
                .any(|(sequence, _)| sequence.starts_with(&self.candidate))
            {
                break;
            }
            let first = self.candidate.remove(0);
            output.push((vec![first], !self.active));
            if self.candidate.is_empty() {
                break;
            }
        }
        output
    }

    fn flush(&mut self) -> Vec<(Vec<u8>, bool)> {
        if self.candidate.is_empty() {
            Vec::new()
        } else {
            vec![(std::mem::take(&mut self.candidate), !self.active)]
        }
    }
}

fn push_output_action(actions: &mut Vec<StreamAction>, bytes: Vec<u8>, capture: bool) {
    if let Some(StreamAction::Output(previous, previous_capture)) = actions.last_mut()
        && *previous_capture == capture
    {
        previous.extend(bytes);
    } else {
        actions.push(StreamAction::Output(bytes, capture));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn apply(store: &mut Store, actions: Vec<StreamAction>) {
        for action in actions {
            match action {
                StreamAction::Output(bytes, true) => store.append_output(&bytes),
                StreamAction::Output(_, false) => {}
                StreamAction::Event(ParseEvent::Begin(command)) => store.begin(command),
                StreamAction::Event(ParseEvent::End(code)) => store.end(code),
            }
        }
    }

    #[test]
    fn plain_bytes_pass_through() {
        let result = MarkerParser::new().feed(b"hello");
        assert_eq!(result.cleaned, b"hello");
        assert!(result.events.is_empty());
    }

    #[test]
    fn full_begin_marker_is_stripped() {
        let result = MarkerParser::new().feed(b"\x1b]1337;witness;B;ls -la\x07");
        assert!(result.cleaned.is_empty());
        assert_eq!(result.events, [ParseEvent::Begin("ls -la".into())]);
    }

    #[test]
    fn split_begin_marker_is_stripped() {
        let mut parser = MarkerParser::new();
        let first = parser.feed(b"\x1b]1337;wit");
        let second = parser.feed(b"ness;B;pwd\x07");
        assert!(first.cleaned.is_empty());
        assert!(second.cleaned.is_empty());
        assert!(first.events.is_empty());
        assert_eq!(second.events, [ParseEvent::Begin("pwd".into())]);
    }

    #[test]
    fn output_then_end_marker() {
        let result = MarkerParser::new().feed(b"done\r\n\x1b]1337;witness;E;0\x07");
        assert_eq!(result.cleaned, b"done\r\n");
        assert_eq!(result.events, [ParseEvent::End(0)]);
    }

    #[test]
    fn non_witness_osc_passes_through() {
        let input = b"\x1b]0;title\x07";
        let result = MarkerParser::new().feed(input);
        assert_eq!(result.cleaned, input);
        assert!(result.events.is_empty());
    }

    #[test]
    fn full_cycle_updates_store() {
        let mut parser = MarkerParser::new();
        let result = parser.feed(b"\x1b]1337;witness;B;printf hi\x07hi\x1b]1337;witness;E;0\x07");
        let mut store = Store::new(10, 1024);
        apply(&mut store, result.actions);
        let records = store.commands_since(0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].command, "printf hi");
        assert_eq!(records[0].output, "hi");
        assert_eq!(records[0].exit_code, Some(0));
        assert!(!records[0].running);
    }

    #[test]
    fn alternate_screen_output_is_not_captured() {
        let mut parser = MarkerParser::new();
        let result = parser.feed(
            b"\x1b]1337;witness;B;vim notes.txt\x07before\x1b[?1049hhidden\x1b[?1049lafter\x1b]1337;witness;E;0\x07",
        );
        assert!(!parser.alt_screen_active());
        let mut store = Store::new(10, 1024);
        apply(&mut store, result.actions);
        let record = store.command(1).unwrap();
        assert_eq!(record.output, "beforeafter");
    }

    #[test]
    fn st_terminated_marker_is_accepted() {
        let result = MarkerParser::new().feed(b"\x1b]1337;witness;B;echo hi\x1b\\");
        assert_eq!(result.events, [ParseEvent::Begin("echo hi".into())]);
        assert!(result.cleaned.is_empty());
    }

    #[test]
    fn malformed_witness_sequence_passes_through() {
        let input = b"\x1b]1337;witness;not-a-marker\x07";
        let result = MarkerParser::new().feed(input);
        assert_eq!(result.cleaned, input);
        assert!(result.events.is_empty());
    }
}
