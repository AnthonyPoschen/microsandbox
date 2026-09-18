//! Wire-stable network-decision event types.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default per-sandbox ring-buffer capacity.
pub const DEFAULT_DECISION_BUFFER_CAPACITY: usize = 4096;

/// Lower bound accepted for [`clamp_decision_buffer_capacity`].
pub const MIN_DECISION_BUFFER_CAPACITY: usize = 16;

/// Upper bound accepted for [`clamp_decision_buffer_capacity`].
pub const MAX_DECISION_BUFFER_CAPACITY: usize = 100_000;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Enforcement phase that produced a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionPhase {
    /// DNS query policy.
    Dns,
    /// TCP connection policy.
    Tcp,
    /// UDP datagram policy.
    Udp,
    /// TLS/SNI inspection.
    Tls,
    /// HTTP request policy (plaintext or intercepted).
    Http,
}

/// Final action taken at an enforcement point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    /// Traffic was permitted.
    Allow,
    /// Traffic was refused by policy.
    Deny,
    /// Enforcement failed operationally (timeout, malformed handshake).
    Error,
}

/// One recorded enforcement decision.
///
/// The schema is intentionally header- and body-free. Request bodies,
/// credentials, authorization headers, cookies, TLS private material, and
/// secret-substitution values must never appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDecisionEvent {
    /// Monotonic per-sandbox sequence, starting at 1.
    pub sequence: u64,
    /// UTC timestamp as RFC 3339 with millisecond precision.
    pub timestamp: String,
    /// Enforcement phase.
    pub phase: DecisionPhase,
    /// Action taken.
    pub action: DecisionAction,
    /// Stable machine-readable reason (`policy_allow`, `policy_deny`, …).
    pub reason: String,
    /// Destination hostname when known (query name, SNI, or HTTP authority).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_host: Option<String>,
    /// Resolved destination IP when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<IpAddr>,
    /// Destination port when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    /// Transport (`tcp` or `udp`).
    pub transport: String,
    /// Application protocol when known (`dns`, `tls`, `http`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// TLS SNI when this decision inspected a ClientHello.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// HTTP authority (`Host` / `:authority`) when inspected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_authority: Option<String>,
    /// Connection or request correlation identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Matched rule identifier or stable policy-match description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// Count of events discarded because the ring buffer wrapped.
    pub dropped_count: u64,
    /// Sequence of the oldest event still retained, or `0` when empty.
    pub earliest_retained_sequence: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Clamp a configured ring-buffer capacity into the supported range.
pub fn clamp_decision_buffer_capacity(capacity: usize) -> usize {
    capacity.clamp(MIN_DECISION_BUFFER_CAPACITY, MAX_DECISION_BUFFER_CAPACITY)
}

/// Format `SystemTime` as UTC RFC 3339 with millisecond precision.
pub(crate) fn utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339_millis(duration.as_secs() as i64, duration.subsec_millis())
}

fn rfc3339_millis(unix_secs: i64, millis: u32) -> String {
    let days = unix_secs.div_euclid(86_400);
    let tod = unix_secs.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_rejects_zero_and_huge_values() {
        assert_eq!(
            clamp_decision_buffer_capacity(0),
            MIN_DECISION_BUFFER_CAPACITY
        );
        assert_eq!(
            clamp_decision_buffer_capacity(1),
            MIN_DECISION_BUFFER_CAPACITY
        );
        assert_eq!(
            clamp_decision_buffer_capacity(DEFAULT_DECISION_BUFFER_CAPACITY),
            DEFAULT_DECISION_BUFFER_CAPACITY
        );
        assert_eq!(
            clamp_decision_buffer_capacity(usize::MAX),
            MAX_DECISION_BUFFER_CAPACITY
        );
    }

    #[test]
    fn rfc3339_known_epoch() {
        assert_eq!(rfc3339_millis(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339_millis(1_700_000_000, 123),
            "2023-11-14T22:13:20.123Z"
        );
    }

    #[test]
    fn event_json_omits_bodies_and_credentials() {
        let event = NetworkDecisionEvent {
            sequence: 1,
            timestamp: "2026-01-01T00:00:00.000Z".into(),
            phase: DecisionPhase::Http,
            action: DecisionAction::Allow,
            reason: "policy_allow".into(),
            destination_host: Some("api.example.com".into()),
            destination_ip: Some("1.2.3.4".parse().unwrap()),
            destination_port: Some(443),
            transport: "tcp".into(),
            protocol: Some("http".into()),
            sni: Some("api.example.com".into()),
            http_authority: Some("api.example.com".into()),
            correlation_id: Some("tcp-1".into()),
            matched_rule: Some("rule[0] allow domain:api.example.com".into()),
            dropped_count: 0,
            earliest_retained_sequence: 1,
        };
        let json = serde_json::to_string(&event).unwrap();
        for forbidden in [
            "authorization",
            "cookie",
            "set-cookie",
            "body",
            "password",
            "secret",
            "placeholder",
            "private_key",
            "certificate",
        ] {
            assert!(
                !json.to_ascii_lowercase().contains(forbidden),
                "serialized event must not mention {forbidden}: {json}"
            );
        }
        assert!(json.contains("\"phase\":\"http\""));
        assert!(json.contains("\"action\":\"allow\""));
    }
}
