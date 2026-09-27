//! Runtime-level coverage for DNS/TCP/TLS/HTTP allow and deny events.

use std::net::SocketAddr;
use std::time::Duration;

use crate::decision::{DecisionAction, DecisionPhase, emit_dns, emit_http, emit_tcp, emit_tls};
use crate::netstack::shared::{ResolvedHostnameFamily, SharedState};
use crate::policy::{
    Action, Destination, Direction, HostnameSource, HttpMethod, HttpRequestMatch, NetworkPolicy,
    PortRange, Protocol, Rule,
};

fn dst() -> SocketAddr {
    "1.2.3.4:443".parse().unwrap()
}

fn allow_example() -> NetworkPolicy {
    NetworkPolicy::allow_all()
        .allow_domain("example.com")
        .unwrap()
}

fn allow_example_http() -> NetworkPolicy {
    NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![Rule {
            direction: Direction::Egress,
            destination: Destination::Domain("example.com".parse().unwrap()),
            protocols: vec![Protocol::Tcp],
            ports: vec![PortRange::single(443)],
            methods: vec![HttpMethod::Get],
            paths: vec!["/ok".into()],
            action: Action::Allow,
        }],
    }
}

#[test]
fn allowed_and_denied_dns_tcp_tls_http_are_ordered() {
    let shared = SharedState::with_decision_capacity(8, 32);
    shared.cache_resolved_hostname(
        "example.com",
        ResolvedHostnameFamily::Ipv4,
        [dst().ip()],
        Duration::from_secs(60),
    );
    let conn_policy = allow_example();
    let http_policy = allow_example_http();

    let dns_allow = conn_policy.evaluate_dns_query_decision(
        Some(&"example.com".parse().unwrap()),
        Protocol::Udp,
        53,
    );
    emit_dns(
        shared.decisions(),
        dns_allow.0,
        dns_allow.1,
        Some("example.com".into()),
        Protocol::Udp,
        53,
        Some("dns-1".into()),
        Some("dns-1".into()),
    );

    let tcp = conn_policy.evaluate_egress_http_decision(
        dst(),
        Protocol::Tcp,
        &shared,
        HostnameSource::CacheOnly,
        HttpRequestMatch::NotHttp,
    );
    emit_tcp(&shared, &tcp, dst(), None, Some("tcp-1".into()));

    let tls = conn_policy.evaluate_egress_http_decision(
        dst(),
        Protocol::Tcp,
        &shared,
        HostnameSource::Sni("example.com"),
        HttpRequestMatch::NotHttp,
    );
    emit_tls(
        &shared,
        &tls,
        dst(),
        "example.com",
        Some("tcp-1".into()),
        None,
    );

    let http_ok = http_policy.evaluate_egress_http_decision(
        dst(),
        Protocol::Tcp,
        &shared,
        HostnameSource::Sni("example.com"),
        HttpRequestMatch::Request {
            method: "GET",
            path: "/ok",
        },
    );
    emit_http(
        &shared,
        &http_ok,
        dst(),
        Some("example.com".into()),
        Some("example.com".into()),
        Some("tcp-1".into()),
    );

    let http_deny_method = http_policy.evaluate_egress_http_decision(
        dst(),
        Protocol::Tcp,
        &shared,
        HostnameSource::Sni("example.com"),
        HttpRequestMatch::Request {
            method: "POST",
            path: "/ok",
        },
    );
    emit_http(
        &shared,
        &http_deny_method,
        dst(),
        Some("example.com".into()),
        Some("example.com".into()),
        Some("tcp-1".into()),
    );

    let http_deny_path = http_policy.evaluate_egress_http_decision(
        dst(),
        Protocol::Tcp,
        &shared,
        HostnameSource::Sni("example.com"),
        HttpRequestMatch::Request {
            method: "GET",
            path: "/secret",
        },
    );
    emit_http(
        &shared,
        &http_deny_path,
        dst(),
        Some("example.com".into()),
        Some("example.com".into()),
        Some("tcp-1".into()),
    );

    let events = shared.decisions().snapshot_after(0).events;
    let phases: Vec<_> = events.iter().map(|e| e.phase).collect();
    assert_eq!(
        phases,
        vec![
            DecisionPhase::Dns,
            DecisionPhase::Tcp,
            DecisionPhase::Tls,
            DecisionPhase::Http,
            DecisionPhase::Http,
            DecisionPhase::Http,
        ]
    );
    let seqs: Vec<_> = events.iter().map(|e| e.sequence).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(events[0].action, DecisionAction::Allow);
    assert_eq!(events[1].action, DecisionAction::Allow);
    assert_eq!(events[2].action, DecisionAction::Allow);
    assert_eq!(events[3].action, DecisionAction::Allow);
    assert_eq!(events[4].action, DecisionAction::Deny);
    assert_eq!(events[5].action, DecisionAction::Deny);
    assert_eq!(events[2].sni.as_deref(), Some("example.com"));
    assert_eq!(events[3].correlation_id.as_deref(), Some("tcp-1"));
    assert_eq!(events[4].correlation_id.as_deref(), Some("tcp-1"));
    assert!(
        events[3]
            .matched_rule
            .as_deref()
            .unwrap()
            .contains("rule[0]")
    );
    assert_eq!(events[3].http_authority.as_deref(), Some("example.com"));
}

#[test]
fn denied_dns_and_tcp_use_policy_deny() {
    let shared = SharedState::new(8);
    let policy = NetworkPolicy::none();
    let (action, matched) =
        policy.evaluate_dns_query_decision(Some(&"evil.com".parse().unwrap()), Protocol::Udp, 53);
    emit_dns(
        shared.decisions(),
        action,
        matched,
        Some("evil.com".into()),
        Protocol::Udp,
        53,
        Some("dns-9".into()),
        None,
    );
    let tcp = policy.evaluate_egress_http_decision(
        dst(),
        Protocol::Tcp,
        &shared,
        HostnameSource::CacheOnly,
        HttpRequestMatch::NotHttp,
    );
    emit_tcp(&shared, &tcp, dst(), None, Some("tcp-9".into()));
    let events = shared.decisions().snapshot_after(0).events;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].phase, DecisionPhase::Dns);
    assert_eq!(events[0].action, DecisionAction::Deny);
    assert_eq!(events[0].reason, "default_egress_deny");
    assert_eq!(events[1].phase, DecisionPhase::Tcp);
    assert_eq!(events[1].action, DecisionAction::Deny);
}

#[test]
fn dns_queries_and_the_connection_share_lookup_id() {
    let shared = SharedState::with_decision_capacity(8, 32);
    let (v4_query, lookup) = shared.begin_dns_lookup("example.com");
    let (v6_query, v6_lookup) = shared.begin_dns_lookup("example.com");
    assert_eq!(v6_lookup, lookup);
    assert_ne!(v4_query, v6_query);

    let policy = NetworkPolicy::allow_all();
    for query in [&v4_query, &v6_query] {
        let (action, matched) = policy.evaluate_dns_query_decision(
            Some(&"example.com".parse().unwrap()),
            Protocol::Udp,
            53,
        );
        emit_dns(
            shared.decisions(),
            action,
            matched,
            Some("example.com".into()),
            Protocol::Udp,
            53,
            Some(query.clone()),
            Some(lookup.clone()),
        );
    }

    let v4 = dst();
    let v6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
    shared.cache_resolved_hostname(
        "example.com",
        ResolvedHostnameFamily::Ipv4,
        [v4.ip()],
        Duration::from_secs(60),
    );
    shared.cache_resolved_lookup(
        "example.com",
        ResolvedHostnameFamily::Ipv4,
        &lookup,
        Duration::from_secs(60),
    );
    shared.cache_resolved_hostname(
        "example.com",
        ResolvedHostnameFamily::Ipv6,
        [v6.ip()],
        Duration::from_secs(60),
    );
    shared.cache_resolved_lookup(
        "example.com",
        ResolvedHostnameFamily::Ipv6,
        &lookup,
        Duration::from_secs(60),
    );

    let tcp_v6 = policy.evaluate_egress_http_decision(
        v6,
        Protocol::Tcp,
        &shared,
        HostnameSource::Deferred,
        HttpRequestMatch::Unknown,
    );
    emit_tcp(&shared, &tcp_v6, v6, None, Some("tcp-6".into()));
    let tcp_v4 = policy.evaluate_egress_http_decision(
        v4,
        Protocol::Tcp,
        &shared,
        HostnameSource::Deferred,
        HttpRequestMatch::Unknown,
    );
    emit_tcp(&shared, &tcp_v4, v4, None, Some("tcp-4".into()));
    let tls = policy.evaluate_egress_http_decision(
        v4,
        Protocol::Tcp,
        &shared,
        HostnameSource::Sni("example.com"),
        HttpRequestMatch::NotHttp,
    );
    emit_tls(&shared, &tls, v4, "example.com", Some("tcp-4".into()), None);
    let http = policy.evaluate_egress_http_decision(
        v4,
        Protocol::Tcp,
        &shared,
        HostnameSource::Sni("example.com"),
        HttpRequestMatch::Request {
            method: "GET",
            path: "/",
        },
    );
    emit_http(
        &shared,
        &http,
        v4,
        Some("example.com".into()),
        Some("example.com".into()),
        Some("tcp-4".into()),
    );

    let events = shared.decisions().snapshot_after(0).events;
    assert!(events.len() >= 5, "expected dns, tcp, tls, and http events");
    assert!(
        events
            .iter()
            .all(|event| event.lookup_id.as_deref() == Some(lookup.as_str()))
    );
    assert_eq!(events[0].correlation_id.as_deref(), Some(v4_query.as_str()));
    assert_eq!(events[1].correlation_id.as_deref(), Some(v6_query.as_str()));
    let connections: Vec<_> = events
        .iter()
        .filter(|event| event.phase != DecisionPhase::Dns)
        .map(|event| event.correlation_id.as_deref())
        .collect();
    assert!(connections.contains(&Some("tcp-6")));
    assert!(connections.contains(&Some("tcp-4")));
}

#[test]
fn shared_address_omits_lookup_until_sni_confirms_the_name() {
    let shared = SharedState::with_decision_capacity(8, 32);
    let policy = NetworkPolicy::allow_all();
    let addr = dst();
    shared.cache_resolved_hostname(
        "a.example",
        ResolvedHostnameFamily::Ipv4,
        [addr.ip()],
        Duration::from_secs(60),
    );
    shared.cache_resolved_hostname(
        "b.example",
        ResolvedHostnameFamily::Ipv4,
        [addr.ip()],
        Duration::from_secs(60),
    );
    shared.cache_resolved_lookup(
        "a.example",
        ResolvedHostnameFamily::Ipv4,
        "dns-1",
        Duration::from_secs(60),
    );
    shared.cache_resolved_lookup(
        "b.example",
        ResolvedHostnameFamily::Ipv4,
        "dns-2",
        Duration::from_secs(60),
    );

    let decision = policy.evaluate_egress_http_decision(
        addr,
        Protocol::Tcp,
        &shared,
        HostnameSource::Deferred,
        HttpRequestMatch::Unknown,
    );
    let tcp = emit_tcp(&shared, &decision, addr, None, Some("tcp-1".into())).expect("tcp event");
    assert_eq!(tcp.lookup_id, None);

    let tls = emit_tls(
        &shared,
        &decision,
        addr,
        "a.example",
        Some("tcp-1".into()),
        None,
    )
    .expect("tls event");
    assert_eq!(tls.lookup_id.as_deref(), Some("dns-1"));
    assert_eq!(tls.correlation_id.as_deref(), Some("tcp-1"));
}

#[test]
fn stream_cancel_via_close_is_terminal() {
    let log = crate::decision::DecisionLog::with_capacity(16);
    let follower = log.clone();
    let join = std::thread::spawn(move || follower.wait_after(0));
    log.close();
    match join.join().unwrap() {
        crate::decision::FollowOutcome::Closed { .. } => {}
        other => panic!("expected closed, got {other:?}"),
    }
}
