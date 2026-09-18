//! Helpers that record a decision without attaching request bodies or secrets.

use std::net::{IpAddr, SocketAddr};

use crate::netstack::shared::SharedState;
use crate::policy::{Action, EgressEvaluation, PolicyDecision, Protocol};

use super::log::DecisionLog;
use super::types::{DecisionAction, DecisionPhase, NetworkDecisionEvent};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fields supplied by an enforcement site. Sequence, timestamp, and
/// overflow counters are filled by the ring buffer.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    /// Enforcement phase.
    pub phase: DecisionPhase,
    /// Action taken.
    pub action: DecisionAction,
    /// Stable reason string.
    pub reason: String,
    /// Destination hostname when known.
    pub destination_host: Option<String>,
    /// Destination IP when known.
    pub destination_ip: Option<IpAddr>,
    /// Destination port when known.
    pub destination_port: Option<u16>,
    /// `tcp` or `udp`.
    pub transport: String,
    /// Application protocol when known.
    pub protocol: Option<String>,
    /// TLS SNI when inspected.
    pub sni: Option<String>,
    /// HTTP authority when inspected.
    pub http_authority: Option<String>,
    /// Correlation identifier.
    pub correlation_id: Option<String>,
    /// Matched rule description.
    pub matched_rule: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Record `record` on `shared`'s decision log.
pub fn emit(shared: &SharedState, record: DecisionRecord) -> NetworkDecisionEvent {
    shared.decisions().emit(record)
}

/// Map a policy action onto a stable reason string.
pub fn reason_for_action(action: Action, matched_rule: &str) -> String {
    match action {
        Action::Allow if matched_rule == "default_egress" => "default_egress_allow".into(),
        Action::Deny if matched_rule == "default_egress" => "default_egress_deny".into(),
        Action::Allow if matched_rule == "platform_policy" => "platform_policy_allow".into(),
        Action::Deny if matched_rule == "platform_policy" => "platform_policy_deny".into(),
        Action::Allow => "policy_allow".into(),
        Action::Deny => "policy_deny".into(),
    }
}

/// Convert an [`Action`] into a decision action.
pub fn action_from_policy(action: Action) -> DecisionAction {
    match action {
        Action::Allow => DecisionAction::Allow,
        Action::Deny => DecisionAction::Deny,
    }
}

/// Emit a DNS query decision.
pub fn emit_dns(
    log: &DecisionLog,
    action: Action,
    matched_rule: String,
    host: Option<String>,
    transport: Protocol,
    port: u16,
    correlation_id: Option<String>,
) -> NetworkDecisionEvent {
    log.emit(DecisionRecord {
        phase: DecisionPhase::Dns,
        action: action_from_policy(action),
        reason: reason_for_action(action, &matched_rule),
        destination_host: host,
        destination_ip: None,
        destination_port: Some(port),
        transport: transport_label(transport),
        protocol: Some("dns".into()),
        sni: None,
        http_authority: None,
        correlation_id,
        matched_rule: Some(matched_rule),
    })
}

/// Emit a TCP connection-policy decision when evaluation is final.
pub fn emit_tcp(
    shared: &SharedState,
    decision: &PolicyDecision,
    dst: SocketAddr,
    host: Option<String>,
    correlation_id: Option<String>,
) -> Option<NetworkDecisionEvent> {
    emit_connection(
        shared,
        DecisionPhase::Tcp,
        "tcp",
        None,
        decision,
        dst,
        host,
        None,
        None,
        correlation_id,
    )
}

/// Emit a UDP datagram-policy decision when evaluation is final.
pub fn emit_udp(
    shared: &SharedState,
    decision: &PolicyDecision,
    dst: SocketAddr,
    host: Option<String>,
    correlation_id: Option<String>,
) -> Option<NetworkDecisionEvent> {
    emit_connection(
        shared,
        DecisionPhase::Udp,
        "udp",
        None,
        decision,
        dst,
        host,
        None,
        None,
        correlation_id,
    )
}

/// Emit a TLS/SNI inspection decision when evaluation is final.
pub fn emit_tls(
    shared: &SharedState,
    decision: &PolicyDecision,
    dst: SocketAddr,
    sni: &str,
    correlation_id: Option<String>,
    reason_override: Option<&str>,
) -> Option<NetworkDecisionEvent> {
    emit_connection(
        shared,
        DecisionPhase::Tls,
        "tcp",
        Some("tls"),
        decision,
        dst,
        Some(sni.to_string()),
        Some(sni.to_string()),
        None,
        correlation_id,
    )
    .map(|mut event| {
        if let Some(reason) = reason_override {
            event.reason = reason.to_string();
        }
        event
    })
}

/// Emit an HTTP request-policy decision when evaluation is final.
pub fn emit_http(
    shared: &SharedState,
    decision: &PolicyDecision,
    dst: SocketAddr,
    authority: Option<String>,
    sni: Option<String>,
    correlation_id: Option<String>,
) -> Option<NetworkDecisionEvent> {
    emit_connection(
        shared,
        DecisionPhase::Http,
        "tcp",
        Some("http"),
        decision,
        dst,
        authority.clone().or_else(|| sni.clone()),
        sni,
        authority,
        correlation_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_connection(
    shared: &SharedState,
    phase: DecisionPhase,
    transport: &str,
    protocol: Option<&str>,
    decision: &PolicyDecision,
    dst: SocketAddr,
    host: Option<String>,
    sni: Option<String>,
    http_authority: Option<String>,
    correlation_id: Option<String>,
) -> Option<NetworkDecisionEvent> {
    let action = match decision.evaluation {
        EgressEvaluation::Allow => DecisionAction::Allow,
        EgressEvaluation::Deny => DecisionAction::Deny,
        EgressEvaluation::DeferUntilHostname | EgressEvaluation::DeferUntilHttp => {
            return None;
        }
    };
    let policy_action = match action {
        DecisionAction::Allow => Action::Allow,
        DecisionAction::Deny => Action::Deny,
        DecisionAction::Error => return None,
    };
    Some(shared.decisions().emit(DecisionRecord {
        phase,
        action,
        reason: reason_for_action(policy_action, &decision.matched_rule),
        destination_host: host,
        destination_ip: Some(dst.ip()),
        destination_port: Some(dst.port()),
        transport: transport.into(),
        protocol: protocol.map(str::to_string),
        sni,
        http_authority,
        correlation_id,
        matched_rule: Some(decision.matched_rule.clone()),
    }))
}

/// Emit an operational error at an enforcement point.
#[allow(clippy::too_many_arguments)]
pub fn emit_error(
    shared: &SharedState,
    phase: DecisionPhase,
    reason: &str,
    dst: SocketAddr,
    transport: &str,
    protocol: Option<&str>,
    host: Option<String>,
    sni: Option<String>,
    correlation_id: Option<String>,
) -> NetworkDecisionEvent {
    shared.decisions().emit(DecisionRecord {
        phase,
        action: DecisionAction::Error,
        reason: reason.into(),
        destination_host: host,
        destination_ip: Some(dst.ip()),
        destination_port: Some(dst.port()),
        transport: transport.into(),
        protocol: protocol.map(str::to_string),
        sni,
        http_authority: None,
        correlation_id,
        matched_rule: None,
    })
}

fn transport_label(protocol: Protocol) -> String {
    match protocol {
        Protocol::Tcp => "tcp".into(),
        Protocol::Udp => "udp".into(),
        Protocol::Icmpv4 | Protocol::Icmpv6 => "icmp".into(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{DecisionLog, DecisionPhase};
    use crate::policy::{Action, EgressEvaluation};

    #[test]
    fn deferred_evaluations_are_not_emitted() {
        let shared = SharedState::new(8);
        let decision = PolicyDecision {
            evaluation: EgressEvaluation::DeferUntilHostname,
            matched_rule: "rule[0] allow domain:example.com".into(),
        };
        let dst = "1.2.3.4:443".parse().unwrap();
        assert!(emit_tcp(&shared, &decision, dst, None, None).is_none());
        assert!(shared.decisions().snapshot_after(0).events.is_empty());
    }

    #[test]
    fn dns_allow_and_deny_record_stable_reasons() {
        let log = DecisionLog::with_capacity(16);
        let allow = emit_dns(
            &log,
            Action::Allow,
            "rule[0] allow group:host".into(),
            Some("example.com".into()),
            Protocol::Udp,
            53,
            Some("dns-1".into()),
        );
        assert_eq!(allow.phase, DecisionPhase::Dns);
        assert_eq!(allow.reason, "policy_allow");
        assert_eq!(allow.correlation_id.as_deref(), Some("dns-1"));
        let deny = emit_dns(
            &log,
            Action::Deny,
            "default_egress".into(),
            Some("evil.com".into()),
            Protocol::Udp,
            53,
            Some("dns-2".into()),
        );
        assert_eq!(deny.reason, "default_egress_deny");
        assert_eq!(deny.action, DecisionAction::Deny);
    }
}
