//! Bounded per-sandbox ring buffer for network decisions.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

use super::emit::DecisionRecord;
use super::types::{
    DEFAULT_DECISION_BUFFER_CAPACITY, NetworkDecisionEvent, clamp_decision_buffer_capacity,
    utc_timestamp,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Inner {
    events: VecDeque<NetworkDecisionEvent>,
    next_sequence: u64,
    dropped_count: u64,
    earliest_retained_sequence: u64,
    closed: bool,
}

/// In-process ring buffer of enforcement decisions for one sandbox.
#[derive(Clone)]
pub struct DecisionLog {
    inner: Arc<Mutex<Inner>>,
    cv: Arc<Condvar>,
    capacity: usize,
}

/// Cheap cloneable handle to a [`DecisionLog`].
pub type DecisionHandle = DecisionLog;

/// Snapshot of retained events after an exclusive sequence cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionSnapshot {
    /// Events with `sequence > after`.
    pub events: Vec<NetworkDecisionEvent>,
    /// Events discarded because the buffer wrapped.
    pub dropped_count: u64,
    /// Oldest retained sequence, or `0` when the buffer is empty.
    pub earliest_retained_sequence: u64,
    /// Next sequence that will be assigned.
    pub next_sequence: u64,
    /// Whether the sandbox (or log) has closed.
    pub closed: bool,
}

/// Result of waiting for events after a cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowOutcome {
    /// One or more new events, possibly with a closed flag.
    Events {
        /// Newly available events.
        events: Vec<NetworkDecisionEvent>,
        /// The log closed after these events.
        closed: bool,
        /// Cumulative wrap count.
        dropped_count: u64,
        /// Oldest retained sequence.
        earliest_retained_sequence: u64,
    },
    /// No further events will arrive.
    Closed {
        /// Cumulative wrap count.
        dropped_count: u64,
        /// Oldest retained sequence.
        earliest_retained_sequence: u64,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DecisionLog {
    /// Create a log with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_DECISION_BUFFER_CAPACITY)
    }

    /// Create a log with a clamped capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = clamp_decision_buffer_capacity(capacity);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                events: VecDeque::with_capacity(capacity),
                next_sequence: 1,
                dropped_count: 0,
                earliest_retained_sequence: 0,
                closed: false,
            })),
            cv: Arc::new(Condvar::new()),
            capacity,
        }
    }

    /// Configured capacity after clamping.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Append a decision. Returns the recorded event.
    ///
    /// When the buffer is full the oldest event is dropped and
    /// `dropped_count` increases. Callers observe the wrap through
    /// [`NetworkDecisionEvent::dropped_count`].
    pub fn emit(&self, record: DecisionRecord) -> NetworkDecisionEvent {
        let mut inner = self.inner.lock().expect("decision log mutex");
        if inner.events.len() == self.capacity {
            inner.events.pop_front();
            inner.dropped_count = inner.dropped_count.saturating_add(1);
        }
        let sequence = inner.next_sequence;
        inner.next_sequence = inner.next_sequence.saturating_add(1);
        let event = NetworkDecisionEvent {
            sequence,
            timestamp: utc_timestamp(),
            phase: record.phase,
            action: record.action,
            reason: record.reason,
            destination_host: record.destination_host,
            destination_ip: record.destination_ip,
            destination_port: record.destination_port,
            transport: record.transport,
            protocol: record.protocol,
            sni: record.sni,
            http_authority: record.http_authority,
            correlation_id: record.correlation_id,
            matched_rule: record.matched_rule,
            dropped_count: inner.dropped_count,
            earliest_retained_sequence: 0,
        };
        inner.events.push_back(event.clone());
        let earliest = inner
            .events
            .front()
            .map(|event| event.sequence)
            .unwrap_or(0);
        inner.earliest_retained_sequence = earliest;
        if let Some(stored) = inner.events.back_mut() {
            stored.earliest_retained_sequence = earliest;
        }
        let event = inner.events.back().cloned().expect("just pushed");
        self.cv.notify_all();
        event
    }

    /// Copy events with `sequence > after`.
    pub fn snapshot_after(&self, after: u64) -> DecisionSnapshot {
        let inner = self.inner.lock().expect("decision log mutex");
        DecisionSnapshot {
            events: events_after(&inner, after),
            dropped_count: inner.dropped_count,
            earliest_retained_sequence: inner.earliest_retained_sequence,
            next_sequence: inner.next_sequence,
            closed: inner.closed,
        }
    }

    /// Block until events after `after` exist or the log is closed.
    pub fn wait_after(&self, after: u64) -> FollowOutcome {
        let mut inner = self.inner.lock().expect("decision log mutex");
        loop {
            let events = events_after(&inner, after);
            if !events.is_empty() {
                return FollowOutcome::Events {
                    events,
                    closed: inner.closed,
                    dropped_count: inner.dropped_count,
                    earliest_retained_sequence: inner.earliest_retained_sequence,
                };
            }
            if inner.closed {
                return FollowOutcome::Closed {
                    dropped_count: inner.dropped_count,
                    earliest_retained_sequence: inner.earliest_retained_sequence,
                };
            }
            inner = self.cv.wait(inner).expect("decision log condvar");
        }
    }

    /// Mark the log closed and wake followers. Further emits are still
    /// recorded until process exit so a late snapshot can drain.
    pub fn close(&self) {
        let mut inner = self.inner.lock().expect("decision log mutex");
        inner.closed = true;
        self.cv.notify_all();
    }

    /// Whether [`Self::close`] has been called.
    pub fn is_closed(&self) -> bool {
        self.inner.lock().expect("decision log mutex").closed
    }
}

impl Default for DecisionLog {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn events_after(inner: &Inner, after: u64) -> Vec<NetworkDecisionEvent> {
    inner
        .events
        .iter()
        .filter(|event| event.sequence > after)
        .cloned()
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{DecisionAction, DecisionPhase};

    fn record(reason: &str) -> DecisionRecord {
        DecisionRecord {
            phase: DecisionPhase::Tcp,
            action: DecisionAction::Allow,
            reason: reason.into(),
            destination_host: Some("example.com".into()),
            destination_ip: None,
            destination_port: Some(443),
            transport: "tcp".into(),
            protocol: Some("tls".into()),
            sni: None,
            http_authority: None,
            correlation_id: Some("tcp-1".into()),
            matched_rule: Some("rule[0] allow any".into()),
        }
    }

    #[test]
    fn sequences_are_monotonic_and_contiguous() {
        let log = DecisionLog::with_capacity(16);
        for i in 1..=5 {
            let event = log.emit(record("policy_allow"));
            assert_eq!(event.sequence, i);
        }
        let snap = log.snapshot_after(0);
        let seqs: Vec<u64> = snap.events.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
        assert_eq!(snap.dropped_count, 0);
        assert_eq!(snap.earliest_retained_sequence, 1);
        assert_eq!(snap.next_sequence, 6);
    }

    #[test]
    fn overflow_reports_dropped_count_and_earliest_retained() {
        let log = DecisionLog::with_capacity(16);
        for _ in 0..20 {
            log.emit(record("policy_allow"));
        }
        let snap = log.snapshot_after(0);
        assert_eq!(snap.events.len(), 16);
        assert_eq!(snap.dropped_count, 4);
        assert_eq!(snap.earliest_retained_sequence, 5);
        assert_eq!(snap.events[0].sequence, 5);
        assert_eq!(snap.events.last().unwrap().sequence, 20);
        assert_eq!(snap.events.last().unwrap().dropped_count, 4);
    }

    #[test]
    fn snapshot_after_cursor_excludes_seen_events() {
        let log = DecisionLog::with_capacity(16);
        for _ in 0..3 {
            log.emit(record("policy_allow"));
        }
        let snap = log.snapshot_after(2);
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.events[0].sequence, 3);
    }

    #[test]
    fn follow_unblocks_on_close() {
        let log = DecisionLog::with_capacity(16);
        log.close();
        match log.wait_after(0) {
            FollowOutcome::Closed { dropped_count, .. } => assert_eq!(dropped_count, 0),
            other => panic!("expected closed, got {other:?}"),
        }
    }

    #[test]
    fn follow_receives_live_events_then_close() {
        let log = DecisionLog::with_capacity(16);
        let follower = log.clone();
        let handle = std::thread::spawn(move || follower.wait_after(0));
        log.emit(record("policy_allow"));
        match handle.join().unwrap() {
            FollowOutcome::Events { events, closed, .. } => {
                assert_eq!(events.len(), 1);
                assert!(!closed);
            }
            other => panic!("expected events, got {other:?}"),
        }
        log.close();
        match log.wait_after(1) {
            FollowOutcome::Closed { .. } => {}
            other => panic!("expected closed after drain, got {other:?}"),
        }
    }
}
