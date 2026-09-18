//! Per-sandbox network-policy decision log.
//!
//! Every DNS, TCP, UDP, TLS, and HTTP enforcement decision is recorded
//! into a bounded ring buffer. Consumers replay retained events after a
//! sequence cursor and can follow new events until the sandbox stops.
//! Overflow is never silent: dropped-event counts travel with every event
//! and snapshot.

mod emit;
mod log;
mod types;

#[cfg(test)]
mod tests_enforcement;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use emit::{
    DecisionRecord, emit, emit_dns, emit_error, emit_http, emit_tcp, emit_tls, emit_udp,
    reason_for_action,
};
pub use log::{DecisionHandle, DecisionLog, DecisionSnapshot, FollowOutcome};
pub use types::{
    DEFAULT_DECISION_BUFFER_CAPACITY, DecisionAction, DecisionPhase, MAX_DECISION_BUFFER_CAPACITY,
    MIN_DECISION_BUFFER_CAPACITY, NetworkDecisionEvent, clamp_decision_buffer_capacity,
};
