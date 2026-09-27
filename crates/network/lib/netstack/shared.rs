//! Shared state between the NetWorker thread, smoltcp poll thread, and tokio
//! proxy tasks.
//!
//! All inter-thread communication flows through [`SharedState`], which holds
//! lock-free frame queues and cross-platform [`WakePipe`] notifications.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;
use microsandbox_utils::ttl_reverse_index::TtlReverseIndex;
pub use microsandbox_utils::wake_pipe::WakePipe;
use parking_lot::RwLock;

use crate::addr::normalize_ip_addr;
use crate::decision::{
    DEFAULT_DECISION_BUFFER_CAPACITY, DecisionLog, clamp_decision_buffer_capacity,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default frame queue capacity. Matches libkrun's virtio queue size.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// How long a later DNS query for the same name joins the lookup already open.
///
/// Parallel A and AAAA queries, and a truncated UDP answer retried over TCP,
/// land inside this window. A query that starts after it is a new lookup.
pub(crate) const LOOKUP_SIBLING_WINDOW: Duration = Duration::from_secs(1);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// All shared state between the three threads:
///
/// - **NetWorker** (libkrun) — pushes guest frames to `tx_ring`, pops
///   response frames from `rx_ring`.
/// - **smoltcp poll thread** — pops from `tx_ring`, processes through smoltcp,
///   pushes responses to `rx_ring`.
/// - **tokio proxy tasks** — relay data between smoltcp sockets and real
///   network connections.
///
/// Queue naming follows the **guest's perspective** (matching libkrun's
/// convention): `tx_ring` = "transmit from guest", `rx_ring` = "receive at
/// guest".
pub struct SharedState {
    /// Frames from guest → smoltcp (NetWorker writes, smoltcp reads).
    pub tx_ring: ArrayQueue<Vec<u8>>,

    /// Frames from smoltcp → guest (smoltcp writes, NetWorker reads).
    pub rx_ring: ArrayQueue<Vec<u8>>,

    /// Wakes NetWorker: "rx_ring has frames for the guest."
    /// Written by `SmoltcpDevice::transmit()`. Read end polled by NetWorker's
    /// epoll loop.
    pub rx_wake: WakePipe,

    /// Wakes smoltcp poll thread: "tx_ring has frames from the guest."
    /// Written by `SmoltcpBackend::write_frame()`. Read end polled by the
    /// poll loop.
    pub tx_wake: WakePipe,

    /// Wakes smoltcp poll thread: "proxy task has data to write to a smoltcp
    /// socket." Written by proxy tasks via channels. Read end polled by the
    /// poll loop.
    pub proxy_wake: WakePipe,

    /// Optional host-side termination hook used for fatal policy violations.
    termination_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,

    /// Resolved hostname index used to map destination IPs back to queried hostnames.
    resolved_hostnames: RwLock<TtlReverseIndex<ResolvedHostnameKey, IpAddr>>,

    /// Per-sandbox gateway IPv4. Set once at boot; used by
    /// `DestinationGroup::Host` rule matching and `host.microsandbox.internal`
    /// DNS synthesis. `None` in isolated unit tests.
    gateway_ipv4: OnceLock<Ipv4Addr>,

    /// Per-sandbox gateway IPv6. Set once at boot. See `gateway_ipv4`.
    gateway_ipv6: OnceLock<Ipv6Addr>,

    /// Aggregate network byte counters at the guest/runtime boundary.
    metrics: NetworkMetrics,

    /// Bounded log of network-policy enforcement decisions.
    decisions: DecisionLog,

    /// Monotonic generator for connection/request correlation ids.
    correlation_seq: AtomicU64,

    /// DNS lookups opened within [`LOOKUP_SIBLING_WINDOW`], keyed by name.
    open_lookups: Mutex<HashMap<String, OpenLookup>>,

    /// Lookup id of a cached A/AAAA answer, keyed like `resolved_hostnames`.
    resolution_lookups: RwLock<HashMap<ResolvedHostnameKey, ResolutionLookup>>,
}

/// Aggregate network byte counters shared with the runtime metrics sampler.
pub struct NetworkMetrics {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

/// Address family for resolved hostname entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedHostnameFamily {
    Ipv4,
    Ipv6,
}

/// Composite cache key for a single DNS resolution.
///
/// `family` partitions entries so that `A` and `AAAA` responses for the
/// same hostname refresh independently instead of overwriting each other.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ResolvedHostnameKey {
    hostname: String,
    family: ResolvedHostnameFamily,
}

/// A name lookup that sibling DNS queries can still join.
struct OpenLookup {
    lookup_id: String,
    opened_at: Instant,
}

/// The lookup that produced one cached address family.
struct ResolutionLookup {
    lookup_id: String,
    started_at: Instant,
    expires_at: Instant,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SharedState {
    /// Create shared state with the given queue capacity.
    pub fn new(queue_capacity: usize) -> Self {
        Self::with_decision_capacity(queue_capacity, DEFAULT_DECISION_BUFFER_CAPACITY)
    }

    /// Create shared state with an explicit decision-log capacity.
    pub fn with_decision_capacity(queue_capacity: usize, decision_capacity: usize) -> Self {
        Self {
            tx_ring: ArrayQueue::new(queue_capacity),
            rx_ring: ArrayQueue::new(queue_capacity),
            rx_wake: WakePipe::new(),
            tx_wake: WakePipe::new(),
            proxy_wake: WakePipe::new(),
            termination_hook: Mutex::new(None),
            resolved_hostnames: RwLock::new(TtlReverseIndex::default()),
            gateway_ipv4: OnceLock::new(),
            gateway_ipv6: OnceLock::new(),
            metrics: NetworkMetrics::default(),
            decisions: DecisionLog::with_capacity(clamp_decision_buffer_capacity(
                decision_capacity,
            )),
            correlation_seq: AtomicU64::new(0),
            open_lookups: Mutex::new(HashMap::new()),
            resolution_lookups: RwLock::new(HashMap::new()),
        }
    }

    /// Per-sandbox network-decision log.
    pub fn decisions(&self) -> &DecisionLog {
        &self.decisions
    }

    /// Allocate a correlation identifier (`{kind}-{n}`).
    pub fn next_correlation_id(&self, kind: &str) -> String {
        let n = self.correlation_seq.fetch_add(1, Ordering::Relaxed) + 1;
        format!("{kind}-{n}")
    }

    /// Open or join the lookup for one DNS query name.
    ///
    /// Returns `(correlation_id, lookup_id)`. Queries for the same name that
    /// start within [`LOOKUP_SIBLING_WINDOW`] share `lookup_id`. The first
    /// query's correlation id is that lookup id.
    pub(crate) fn begin_dns_lookup(&self, domain: &str) -> (String, String) {
        self.begin_dns_lookup_at(domain, Instant::now())
    }

    fn begin_dns_lookup_at(&self, domain: &str, now: Instant) -> (String, String) {
        let correlation_id = self.next_correlation_id("dns");
        let hostname = normalize_hostname(domain);
        let mut open = self.open_lookups.lock().expect("open lookup mutex");
        open.retain(|_, entry| {
            now.saturating_duration_since(entry.opened_at) <= LOOKUP_SIBLING_WINDOW
        });
        if let Some(existing) = open.get(&hostname) {
            return (correlation_id, existing.lookup_id.clone());
        }
        let lookup_id = correlation_id.clone();
        open.insert(
            hostname,
            OpenLookup {
                lookup_id: lookup_id.clone(),
                opened_at: now,
            },
        );
        (correlation_id, lookup_id)
    }

    /// Remember which lookup produced the addresses just cached for `domain`.
    ///
    /// The TTL matches the resolved-hostname cache entry. A connection to one
    /// of those addresses can then copy this lookup id onto its decision.
    pub(crate) fn cache_resolved_lookup(
        &self,
        domain: &str,
        family: ResolvedHostnameFamily,
        lookup_id: &str,
        ttl: Duration,
    ) {
        self.cache_resolved_lookup_at(domain, family, lookup_id, ttl, Instant::now());
    }

    fn cache_resolved_lookup_at(
        &self,
        domain: &str,
        family: ResolvedHostnameFamily,
        lookup_id: &str,
        ttl: Duration,
        now: Instant,
    ) {
        let hostname = normalize_hostname(domain);
        if hostname.is_empty() || lookup_id.is_empty() {
            return;
        }
        let key = ResolvedHostnameKey { hostname, family };
        self.resolution_lookups.write().insert(
            key,
            ResolutionLookup {
                lookup_id: lookup_id.to_string(),
                started_at: now,
                expires_at: now + ttl,
            },
        );
    }

    /// Lookup id for a connection to `addr`.
    ///
    /// `confirmed_name` is the TLS SNI or HTTP authority when that is already
    /// known. With one cached name for the address, or with a confirmed name,
    /// the id is that name's lookup. When several names share the address and
    /// the name is still unknown, the id is set only when a single lookup was
    /// cached inside [`LOOKUP_SIBLING_WINDOW`] and the others are older.
    pub(crate) fn lookup_id_for_destination(
        &self,
        addr: IpAddr,
        confirmed_name: Option<&str>,
    ) -> Option<String> {
        self.lookup_id_for_destination_at(addr, confirmed_name, Instant::now())
    }

    fn lookup_id_for_destination_at(
        &self,
        addr: IpAddr,
        confirmed_name: Option<&str>,
        now: Instant,
    ) -> Option<String> {
        let addr = normalize_ip_addr(addr);
        let confirmed = confirmed_name.map(normalize_hostname);
        let index = self.resolved_hostnames.read();
        let lookups = self.resolution_lookups.read();
        let mut candidates = Vec::new();
        index.for_each_live_key(&addr, now, |key| {
            if confirmed.as_ref().is_some_and(|name| name != &key.hostname) {
                return;
            }
            let Some(lookup) = lookups.get(key) else {
                return;
            };
            if lookup.expires_at <= now {
                return;
            }
            candidates.push((lookup.lookup_id.clone(), lookup.started_at));
        });
        drop(lookups);
        drop(index);
        select_lookup_id(&candidates, confirmed.is_some(), now)
    }

    /// Set the per-sandbox gateway IPs. Called once at boot. Each family is
    /// only published when active for this sandbox.
    pub fn set_gateway_ips(&self, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        if let Some(ipv4) = ipv4 {
            let _ = self.gateway_ipv4.set(ipv4);
        }
        if let Some(ipv6) = ipv6 {
            let _ = self.gateway_ipv6.set(ipv6);
        }
    }

    /// Gateway IPv4 address, if set.
    pub fn gateway_ipv4(&self) -> Option<Ipv4Addr> {
        self.gateway_ipv4.get().copied()
    }

    /// Gateway IPv6 address, if set.
    pub fn gateway_ipv6(&self) -> Option<Ipv6Addr> {
        self.gateway_ipv6.get().copied()
    }

    /// Install a host-side termination hook.
    pub fn set_termination_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self.termination_hook.lock().unwrap() = Some(hook);
    }

    /// Trigger host-side termination if a hook is installed.
    pub fn trigger_termination(&self) {
        let hook = self.termination_hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Replace the resolved addresses for a hostname within the given address family.
    pub fn cache_resolved_hostname(
        &self,
        domain: &str,
        family: ResolvedHostnameFamily,
        addrs: impl IntoIterator<Item = IpAddr>,
        ttl: Duration,
    ) {
        let hostname = normalize_hostname(domain);
        let key = ResolvedHostnameKey { hostname, family };
        let addrs = addrs.into_iter().map(normalize_ip_addr);
        self.resolved_hostnames
            .write()
            .insert(key, addrs, ttl, Instant::now());
    }

    /// Clear the resolved addresses for a hostname within the given address family.
    pub fn clear_resolved_hostname(&self, domain: &str, family: ResolvedHostnameFamily) {
        let hostname = normalize_hostname(domain);
        let key = ResolvedHostnameKey { hostname, family };
        self.resolved_hostnames.write().remove(&key, Instant::now());
        self.resolution_lookups.write().remove(&key);
    }

    /// Returns `true` when any resolved hostname for `addr` satisfies `predicate`.
    pub fn any_resolved_hostname(
        &self,
        addr: IpAddr,
        mut predicate: impl FnMut(&str) -> bool,
    ) -> bool {
        let addr = normalize_ip_addr(addr);

        self.resolved_hostnames
            .read()
            .member_matches(&addr, Instant::now(), |key| predicate(&key.hostname))
    }

    /// Best-effort expiry maintenance for resolved hostnames.
    ///
    /// This runs outside the hot egress read path. If the index is currently
    /// busy, cleanup is skipped and retried on the next maintenance pass.
    pub fn cleanup_resolved_hostnames(&self) {
        let now = Instant::now();
        if let Some(mut idx) = self.resolved_hostnames.try_write() {
            idx.evict_expired(now);
        }
        if let Some(mut lookups) = self.resolution_lookups.try_write() {
            lookups.retain(|_, entry| entry.expires_at > now);
        }
        if let Ok(mut open) = self.open_lookups.try_lock() {
            open.retain(|_, entry| {
                now.saturating_duration_since(entry.opened_at) <= LOOKUP_SIBLING_WINDOW
            });
        }
    }

    /// Increment the guest -> runtime byte counter.
    pub fn add_tx_bytes(&self, bytes: usize) {
        self.metrics
            .tx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Increment the runtime -> guest byte counter.
    pub fn add_rx_bytes(&self, bytes: usize) {
        self.metrics
            .rx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Push a runtime -> guest ethernet frame and update RX metrics on success.
    pub(crate) fn push_rx_frame(&self, frame: Vec<u8>) -> bool {
        let frame_len = frame.len();
        if self.rx_ring.push(frame).is_err() {
            return false;
        }

        self.add_rx_bytes(frame_len);
        true
    }

    /// Push a runtime -> guest ethernet frame, update RX metrics, and wake libkrun.
    pub(crate) fn push_rx_frame_and_wake(&self, frame: Vec<u8>) -> bool {
        if !self.push_rx_frame(frame) {
            return false;
        }

        self.rx_wake.wake();
        true
    }

    /// Total bytes transmitted by the guest into the runtime.
    pub fn tx_bytes(&self) -> u64 {
        self.metrics.tx_bytes.load(Ordering::Relaxed)
    }

    /// Total bytes delivered by the runtime to the guest.
    pub fn rx_bytes(&self) -> u64 {
        self.metrics.rx_bytes.load(Ordering::Relaxed)
    }
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }
}

pub(crate) fn normalize_hostname(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Pick the lookup id a connection should carry.
///
/// `candidates` is `(lookup_id, cached_at)` for every live name that resolved
/// to the destination. A confirmed hostname has already discarded other names.
fn select_lookup_id(
    candidates: &[(String, Instant)],
    confirmed: bool,
    now: Instant,
) -> Option<String> {
    let mut by_id: Vec<(String, Instant)> = Vec::new();
    for (id, started) in candidates {
        if let Some((_, existing)) = by_id.iter_mut().find(|(existing_id, _)| existing_id == id) {
            if *started > *existing {
                *existing = *started;
            }
        } else {
            by_id.push((id.clone(), *started));
        }
    }

    if by_id.len() <= 1 {
        return by_id.pop().map(|(id, _)| id);
    }
    if confirmed {
        by_id.sort_by_key(|(_, started)| *started);
        return by_id.pop().map(|(id, _)| id);
    }

    let mut fresh: Vec<&str> = by_id
        .iter()
        .filter(|(_, started)| now.saturating_duration_since(*started) <= LOOKUP_SIBLING_WINDOW)
        .map(|(id, _)| id.as_str())
        .collect();
    fresh.sort_unstable();
    fresh.dedup();
    if fresh.len() == 1 {
        Some(fresh[0].to_string())
    } else {
        None
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_state_queue_push_pop() {
        let state = SharedState::new(4);

        // Push frames to tx_ring.
        state.tx_ring.push(vec![1, 2, 3]).unwrap();
        state.tx_ring.push(vec![4, 5, 6]).unwrap();

        // Pop in FIFO order.
        assert_eq!(state.tx_ring.pop(), Some(vec![1, 2, 3]));
        assert_eq!(state.tx_ring.pop(), Some(vec![4, 5, 6]));
        assert_eq!(state.tx_ring.pop(), None);
    }

    #[test]
    fn shared_state_queue_full() {
        let state = SharedState::new(2);

        state.rx_ring.push(vec![1]).unwrap();
        state.rx_ring.push(vec![2]).unwrap();
        // Queue is full — push returns the frame back.
        assert!(state.rx_ring.push(vec![3]).is_err());
    }

    #[test]
    fn push_rx_frame_counts_only_successful_pushes() {
        let state = SharedState::new(1);

        assert!(state.push_rx_frame(vec![1, 2, 3]));
        assert_eq!(state.rx_bytes(), 3);

        assert!(!state.push_rx_frame(vec![4, 5]));
        assert_eq!(state.rx_bytes(), 3);
    }

    #[test]
    fn resolved_hostnames_are_isolated_per_family() {
        let state = SharedState::new(4);
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();

        state.cache_resolved_hostname(
            "Example.com.",
            ResolvedHostnameFamily::Ipv4,
            [v4],
            Duration::from_secs(30),
        );
        state.cache_resolved_hostname(
            "example.com",
            ResolvedHostnameFamily::Ipv6,
            [v6],
            Duration::from_secs(30),
        );

        assert!(state.any_resolved_hostname(v4, |h| h == "example.com"));
        assert!(state.any_resolved_hostname(v6, |h| h == "example.com"));
        assert!(!state.any_resolved_hostname(v4, |h| h == "other.example"));
    }

    #[test]
    fn resolved_hostnames_normalize_ipv4_mapped_ipv6() {
        let state = SharedState::new(4);
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        let embedded: IpAddr = "169.254.169.254".parse().unwrap();

        state.cache_resolved_hostname(
            "metadata.example",
            ResolvedHostnameFamily::Ipv6,
            [mapped],
            Duration::from_secs(30),
        );

        assert!(state.any_resolved_hostname(embedded, |h| h == "metadata.example"));
        assert!(state.any_resolved_hostname(mapped, |h| h == "metadata.example"));
    }

    #[test]
    fn sibling_dns_queries_share_lookup_id() {
        let state = SharedState::new(4);
        let opened = Instant::now();

        let (first_query, first_lookup) = state.begin_dns_lookup_at("Example.com.", opened);
        let (second_query, second_lookup) =
            state.begin_dns_lookup_at("example.com", opened + Duration::from_millis(200));
        let (later_query, later_lookup) =
            state.begin_dns_lookup_at("example.com", opened + Duration::from_secs(2));

        assert_eq!(first_lookup, first_query);
        assert_eq!(second_lookup, first_lookup);
        assert_ne!(second_query, first_query);
        assert_eq!(later_lookup, later_query);
        assert_ne!(later_lookup, first_lookup);
    }

    #[test]
    fn lookup_id_follows_each_resolved_address() {
        let state = SharedState::new(4);
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        let (v4_query, lookup) = state.begin_dns_lookup("example.com");
        let (v6_query, v6_lookup) = state.begin_dns_lookup("example.com");
        assert_eq!(v6_lookup, lookup);
        assert_ne!(v4_query, v6_query);

        state.cache_resolved_hostname(
            "example.com",
            ResolvedHostnameFamily::Ipv4,
            [v4],
            Duration::from_secs(30),
        );
        state.cache_resolved_lookup(
            "example.com",
            ResolvedHostnameFamily::Ipv4,
            &lookup,
            Duration::from_secs(30),
        );
        state.cache_resolved_hostname(
            "example.com",
            ResolvedHostnameFamily::Ipv6,
            [v6],
            Duration::from_secs(30),
        );
        state.cache_resolved_lookup(
            "example.com",
            ResolvedHostnameFamily::Ipv6,
            &lookup,
            Duration::from_secs(30),
        );

        assert_eq!(
            state.lookup_id_for_destination(v4, None).as_deref(),
            Some(lookup.as_str())
        );
        assert_eq!(
            state.lookup_id_for_destination(v6, None).as_deref(),
            Some(lookup.as_str())
        );
        assert_eq!(
            state.lookup_id_for_destination(v4, Some("example.com")),
            Some(lookup)
        );
    }

    #[test]
    fn shared_address_stays_unlinked_until_the_name_matches() {
        let state = SharedState::new(4);
        let shared_ip: IpAddr = "151.101.0.223".parse().unwrap();
        let now = Instant::now();

        state.cache_resolved_hostname(
            "a.example",
            ResolvedHostnameFamily::Ipv4,
            [shared_ip],
            Duration::from_secs(60),
        );
        state.cache_resolved_hostname(
            "b.example",
            ResolvedHostnameFamily::Ipv4,
            [shared_ip],
            Duration::from_secs(60),
        );
        state.cache_resolved_lookup_at(
            "a.example",
            ResolvedHostnameFamily::Ipv4,
            "dns-1",
            Duration::from_secs(60),
            now,
        );
        state.cache_resolved_lookup_at(
            "b.example",
            ResolvedHostnameFamily::Ipv4,
            "dns-2",
            Duration::from_secs(60),
            now,
        );

        assert_eq!(
            state.lookup_id_for_destination_at(shared_ip, None, now),
            None
        );
        assert_eq!(
            state
                .lookup_id_for_destination_at(shared_ip, Some("B.example."), now)
                .as_deref(),
            Some("dns-2")
        );
    }

    #[test]
    fn fresh_lookup_wins_over_an_older_shared_address() {
        let state = SharedState::new(4);
        let shared_ip: IpAddr = "142.250.0.1".parse().unwrap();
        let now = Instant::now();

        state.cache_resolved_hostname(
            "old.example",
            ResolvedHostnameFamily::Ipv4,
            [shared_ip],
            Duration::from_secs(60),
        );
        state.cache_resolved_hostname(
            "new.example",
            ResolvedHostnameFamily::Ipv4,
            [shared_ip],
            Duration::from_secs(60),
        );
        state.cache_resolved_lookup_at(
            "old.example",
            ResolvedHostnameFamily::Ipv4,
            "dns-old",
            Duration::from_secs(60),
            now - Duration::from_secs(30),
        );
        state.cache_resolved_lookup_at(
            "new.example",
            ResolvedHostnameFamily::Ipv4,
            "dns-new",
            Duration::from_secs(60),
            now,
        );

        assert_eq!(
            state
                .lookup_id_for_destination_at(shared_ip, None, now)
                .as_deref(),
            Some("dns-new")
        );
        assert_eq!(
            state
                .lookup_id_for_destination_at(shared_ip, Some("old.example"), now)
                .as_deref(),
            Some("dns-old")
        );
    }

    #[test]
    fn expired_lookup_is_not_reused() {
        let state = SharedState::new(4);
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        let now = Instant::now();

        state.cache_resolved_hostname(
            "example.com",
            ResolvedHostnameFamily::Ipv4,
            [addr],
            Duration::from_secs(60),
        );
        state.cache_resolved_lookup_at(
            "example.com",
            ResolvedHostnameFamily::Ipv4,
            "dns-1",
            Duration::from_secs(1),
            now - Duration::from_secs(5),
        );

        assert_eq!(
            state.lookup_id_for_destination_at(addr, Some("example.com"), now),
            None
        );
    }

    #[test]
    fn clearing_a_resolution_drops_its_lookup() {
        let state = SharedState::new(4);
        let addr: IpAddr = "1.2.3.4".parse().unwrap();

        state.cache_resolved_hostname(
            "example.com",
            ResolvedHostnameFamily::Ipv4,
            [addr],
            Duration::from_secs(60),
        );
        state.cache_resolved_lookup(
            "example.com",
            ResolvedHostnameFamily::Ipv4,
            "dns-1",
            Duration::from_secs(60),
        );
        state.clear_resolved_hostname("example.com", ResolvedHostnameFamily::Ipv4);

        assert_eq!(
            state.lookup_id_for_destination(addr, Some("example.com")),
            None
        );
    }
}
