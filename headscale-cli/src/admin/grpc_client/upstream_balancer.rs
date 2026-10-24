// Copyright 2017 gRPC authors.
// Copyright 2022 gRPC authors.
// Copyright 2024 gRPC authors.
// Licensed under the Apache License, Version 2.0. See LICENSE-GRPC-GO and
// NOTICE-GRPC-GO in the headscale-cli package for the license and notices.

//! DNS subchannel ownership, happy-eyeballs and graceful policy changes,
//! adapted from grpc-go v1.81.1 balancer/{pickfirst,roundrobin,endpointsharding}
//! and internal/balancer/gracefulswitch. DNS endpoints each have one address.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, mpsc, watch};
use tokio::time::Instant;

use super::UpstreamConnectBackoff;
use super::upstream_connection::{IdleWake, Picker};
use super::upstream_dns::{DnsAuthority, LookupResult};
use super::upstream_service_config::Balancing;
use super::upstream_transport::{ActiveTransport, Recipe, Scope};

const CONNECTION_DELAY: Duration = Duration::from_millis(250);

enum State {
    Idle,
    Connecting,
    Ready(Arc<ActiveTransport>),
    Failed(String),
}

struct Event {
    pool: u64,
    address: SocketAddr,
    generation: u64,
    state: State,
}

struct Child {
    generation: u64,
    state: State,
    failed_in_pass: bool,
    sticky_failure: bool,
    last_error: Option<String>,
    connect: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Child {
    fn start(&mut self) {
        if matches!(&self.state, State::Idle) {
            self.state = State::Connecting;
            self.connect.notify_one();
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if let State::Ready(transport) = &self.state {
            // Stop only new picks. Dispatch/response owners retain the lease
            // until the in-flight call finishes, like Go SubConn Shutdown.
            transport.retire("gRPC endpoint retired by resolver or policy update".into());
        }
        self.task.abort();
    }
}

struct Pool {
    id: u64,
    balancing: Balancing,
    addresses: Vec<SocketAddr>,
    children: HashMap<SocketAddr, Child>,
    selected: Option<SocketAddr>,
    idle: bool,
    idle_wake: Option<Arc<IdleWake>>,
    first_pass: bool,
    cursor: usize,
    launch_at: Option<Instant>,
    failure: Option<String>,
    failures_since_report: usize,
    next_generation: u64,
}

struct Factory {
    recipe: Recipe,
    scope: Arc<Scope>,
    resolver: DnsAuthority,
    host: String,
    events: mpsc::Sender<Event>,
    wake: Arc<Notify>,
}

impl Factory {
    fn spawn(&self, pool: u64, address: SocketAddr, generation: u64) -> Child {
        let connect = Arc::new(Notify::new());
        let task = tokio::spawn(supervise_child(
            self.recipe.endpoint(address),
            self.scope.clone(),
            self.resolver.clone(),
            self.host.clone(),
            self.events.clone(),
            connect.clone(),
            ChildIdentity {
                pool,
                address,
                generation,
            },
        ));
        Child {
            generation,
            state: State::Idle,
            failed_in_pass: false,
            sticky_failure: false,
            last_error: None,
            connect,
            task,
        }
    }
}

#[derive(Clone, Copy)]
struct ChildIdentity {
    pool: u64,
    address: SocketAddr,
    generation: u64,
}

impl Pool {
    fn new(id: u64, balancing: Balancing) -> Self {
        Self {
            id,
            balancing,
            addresses: Vec::new(),
            children: HashMap::new(),
            selected: None,
            idle: false,
            idle_wake: None,
            first_pass: false,
            cursor: 0,
            launch_at: None,
            failure: None,
            failures_since_report: 0,
            next_generation: 0,
        }
    }

    fn spawn(&mut self, address: SocketAddr, factory: &Factory) {
        self.next_generation = self.next_generation.wrapping_add(1);
        let child = factory.spawn(self.id, address, self.next_generation);
        self.children.insert(address, child);
    }

    fn update(&mut self, result: LookupResult, factory: &Factory) {
        let mut addresses = match result {
            Ok(mut addresses) => {
                let mut seen = HashSet::new();
                addresses.retain(|address| seen.insert(*address));
                addresses
            }
            Err((kind, message)) => {
                if matches!(
                    kind,
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) {
                    // ResolverError preserves a good state unless the policy
                    // already reports transient failure (A62).
                    if self.addresses.is_empty() || self.failure.is_some() {
                        self.failure = Some(format!("name resolver error: {message}"));
                    }
                    if self.balancing == Balancing::RoundRobin {
                        for child in self
                            .children
                            .values_mut()
                            .filter(|child| child.sticky_failure)
                        {
                            child.last_error = Some(format!("name resolver error: {message}"));
                        }
                    }
                    return;
                }
                Vec::new()
            }
        };
        if self.balancing == Balancing::PickFirst {
            addresses = super::upstream_transport::interleave(addresses);
        }
        let was_empty = self.addresses.is_empty();
        let was_ready = self.selected.is_some();
        let keep_ready = self.selected.is_some_and(|address| {
            addresses.contains(&address)
                && self.children.get(&address).is_some_and(
                    |child| matches!(&child.state, State::Ready(transport) if transport.alive()),
                )
        });
        self.addresses = addresses;
        let wanted: HashSet<_> = self.addresses.iter().copied().collect();
        self.children.retain(|address, _| wanted.contains(address));
        if self.addresses.is_empty() {
            self.selected = None;
            self.idle = false;
            self.idle_wake = None;
            self.first_pass = false;
            self.launch_at = None;
            self.failure = Some("name resolver error: produced zero addresses".into());
            return;
        }
        match self.balancing {
            Balancing::RoundRobin => {
                self.failure = None;
                let mut addresses = self.addresses.clone();
                let rotation = super::upstream_service_config::random_below(addresses.len());
                addresses.rotate_left(rotation);
                for address in addresses {
                    if !self.children.contains_key(&address) {
                        self.spawn(address, factory);
                    }
                    if let Some(child) = self.children.get_mut(&address) {
                        child.start();
                    }
                }
            }
            Balancing::PickFirst => {
                if keep_ready {
                    if let Some(address) = self.selected {
                        self.select(address);
                    }
                    return;
                }
                self.selected = None;
                if was_ready || was_empty {
                    self.failure = None;
                    self.idle = false;
                }
                // Resolver updates while IDLE reconcile addresses, but demand
                // must still use the idle picker before dialing starts.
                if !self.idle {
                    self.start_pass(factory);
                }
            }
        }
    }

    fn select(&mut self, address: SocketAddr) {
        self.children.retain(|candidate, _| *candidate == address);
        self.selected = Some(address);
        self.idle = false;
        self.idle_wake = None;
        self.first_pass = false;
        self.launch_at = None;
        self.failure = None;
        self.cursor = self
            .addresses
            .iter()
            .position(|candidate| *candidate == address)
            .unwrap_or(0);
    }

    fn start_pass(&mut self, factory: &Factory) {
        self.idle = false;
        self.idle_wake = None;
        self.first_pass = true;
        self.cursor = 0;
        self.failures_since_report = 0;
        self.launch_at = None;
        for child in self.children.values_mut() {
            child.failed_in_pass = false;
        }
        self.request_connection(factory);
    }

    fn request_connection(&mut self, factory: &Factory) {
        let mut last_error = None;
        while let Some(address) = self.addresses.get(self.cursor).copied() {
            if !self.children.contains_key(&address) {
                self.spawn(address, factory);
            }
            let Some(child) = self.children.get_mut(&address) else {
                return;
            };
            match &child.state {
                State::Idle | State::Connecting => {
                    child.start();
                    self.launch_at = (self.cursor + 1 < self.addresses.len())
                        .then(|| Instant::now() + CONNECTION_DELAY);
                    return;
                }
                State::Failed(_) => {
                    child.failed_in_pass = true;
                    last_error.clone_from(&child.last_error);
                    self.cursor += 1;
                }
                State::Ready(_) => {
                    self.select(address);
                    return;
                }
            }
        }
        self.launch_at = None;
        self.end_pass(last_error);
    }

    fn end_pass(&mut self, last_error: Option<String>) {
        if !self.first_pass
            || self.cursor < self.addresses.len()
            || self.children.values().any(|child| !child.failed_in_pass)
        {
            return;
        }
        self.first_pass = false;
        self.failure = last_error
            .or_else(|| self.failure.clone())
            .or_else(|| {
                self.children
                    .values()
                    .find_map(|child| child.last_error.clone())
            })
            .or_else(|| Some("connection failed".into()));
        // Backoff can finish before the pass does. Those children remain IDLE
        // until the entire first pass fails; then all resume independently.
        for child in self.children.values_mut() {
            child.start();
        }
    }

    fn exit_idle(&mut self, factory: &Factory) {
        if self.idle && !self.addresses.is_empty() {
            self.start_pass(factory);
        }
    }

    fn timer(&mut self, now: Instant, factory: &Factory) {
        if self.launch_at.is_some_and(|deadline| deadline <= now) {
            self.launch_at = None;
            self.cursor += 1;
            self.request_connection(factory);
        }
    }

    fn event(&mut self, event: Event, factory: &Factory) -> bool {
        let Some(child) = self
            .children
            .get_mut(&event.address)
            .filter(|child| child.generation == event.generation)
        else {
            return false;
        };
        let was_ready = matches!(&child.state, State::Ready(_));
        let is_idle = matches!(&event.state, State::Idle);
        let ready = matches!(&event.state, State::Ready(transport) if transport.alive());
        let failure = if let State::Failed(message) = &event.state {
            Some(message.clone())
        } else {
            None
        };
        if let Some(message) = &failure {
            child.last_error = Some(message.clone());
            child.failed_in_pass = true;
            child.sticky_failure = true;
        } else if ready {
            child.last_error = None;
            child.sticky_failure = false;
        }
        child.state = event.state;
        if self.balancing == Balancing::RoundRobin {
            if is_idle {
                child.start();
            }
            return true;
        }
        if ready {
            self.select(event.address);
        } else if was_ready && is_idle {
            self.children.retain(|address, _| *address == event.address);
            self.selected = None;
            self.cursor = 0;
            self.launch_at = None;
            self.first_pass = false;
            self.failure = None;
            self.idle = true;
            self.idle_wake = Some(IdleWake::new(factory.wake.clone()));
        } else if let Some(message) = failure {
            if self.first_pass {
                if self.addresses.get(self.cursor) == Some(&event.address) {
                    self.launch_at = None;
                    self.cursor += 1;
                    if self.cursor < self.addresses.len() {
                        self.request_connection(factory);
                        return true;
                    }
                }
                self.end_pass(Some(message));
            } else {
                self.failures_since_report =
                    (self.failures_since_report + 1) % self.children.len().max(1);
                if self.failures_since_report == 0 {
                    self.failure = Some(message);
                }
            }
        } else if is_idle
            && !self.first_pass
            && !self.idle
            && let Some(child) = self.children.get_mut(&event.address)
        {
            child.start();
        }
        true
    }

    fn picker(&self) -> Picker {
        if self.balancing == Balancing::PickFirst {
            if let Some(transport) = self
                .selected
                .and_then(|address| self.children.get(&address))
                .and_then(|child| {
                    if let State::Ready(transport) = &child.state {
                        Some(transport)
                    } else {
                        None
                    }
                })
                .filter(|transport| transport.alive())
            {
                return Picker::ready(vec![transport.clone()]);
            }
            if self.idle
                && let Some(wake) = &self.idle_wake
            {
                return Picker::Idle(wake.clone());
            }
            if let Some(message) = &self.failure {
                return Picker::Failed(message.clone());
            }
            return Picker::Connecting;
        }
        let ready: Vec<_> = self
            .children
            .values()
            .filter_map(|child| match &child.state {
                State::Ready(transport) if transport.alive() => Some(transport.clone()),
                _ => None,
            })
            .collect();
        if !ready.is_empty() {
            return Picker::ready(ready);
        }
        if self.children.values().any(|child| !child.sticky_failure) {
            return Picker::Connecting;
        }
        if self.children.is_empty() {
            return Picker::Failed("no children to pick from".into());
        }
        let failure = self
            .children
            .values()
            .find_map(|child| child.last_error.clone())
            .or_else(|| self.failure.clone());
        Picker::Failed(failure.unwrap_or_else(|| "no children to pick from".into()))
    }
}

/// Own all child tasks without capturing the Connection owner. Dropping the
/// owner aborts this task, drops both pools, and cancels current/retiring IO.
pub(super) async fn supervise(recipe: Recipe, scope: Arc<Scope>, send: watch::Sender<Picker>) {
    let Some((host, port, resolver)) = recipe.dns() else {
        let _ = send.send_replace(Picker::Failed("missing DNS resolver".into()));
        return;
    };
    // Start the resolver before choosing a policy: its first TXT response can
    // select round-robin, which must connect all children concurrently.
    let _ = resolver.lookup(&host, port).await;
    let Some(mut updates) = resolver.updates(&host) else {
        let _ = send.send_replace(Picker::Failed("gRPC DNS resolver stopped".into()));
        return;
    };
    let (events, mut received) = mpsc::channel(64);
    let factory = Factory {
        recipe,
        scope,
        resolver,
        host,
        events,
        wake: Arc::new(Notify::new()),
    };
    let mut active: Option<Pool> = None;
    let mut pending: Option<Pool> = None;
    let mut next_pool = 0u64;
    let mut update = updates.borrow_and_update().clone();
    let mut publish_picker = true;
    loop {
        if let Some(result) = update.take() {
            publish_picker = true;
            let balancing = factory
                .resolver
                .service_config()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .current()
                .map_or(Balancing::PickFirst, |config| config.balancing);
            let latest = pending.as_ref().or(active.as_ref());
            if latest.is_none_or(|pool| pool.balancing != balancing) {
                next_pool = next_pool.wrapping_add(1);
                let pool = Pool::new(next_pool, balancing);
                if active.is_none() {
                    active = Some(pool);
                } else {
                    pending = Some(pool);
                }
            }
            let result = result.map(|addresses| {
                addresses
                    .into_iter()
                    .map(|mut address| {
                        address.set_port(port);
                        address
                    })
                    .collect()
            });
            // Only the newest policy receives resolver updates during a
            // graceful switch; the old ready policy serves until handoff.
            if let Some(pool) = pending.as_mut().or(active.as_mut()) {
                pool.update(result, &factory);
            }
        }
        if publish_picker {
            let mut picker = active.as_ref().map_or(Picker::Connecting, Pool::picker);
            if let Some(candidate) = &pending {
                let candidate_picker = candidate.picker();
                // Go swaps when the candidate leaves CONNECTING (READY or failure)
                // or the old policy loses READY, whichever happens first.
                if !candidate_picker.is_connecting() || !picker.is_ready() {
                    active = pending.take();
                    picker = candidate_picker;
                }
            }
            let _ = send.send_replace(picker);
            publish_picker = false;
        }
        let next_launch = active
            .as_ref()
            .and_then(|pool| pool.launch_at)
            .into_iter()
            .chain(pending.as_ref().and_then(|pool| pool.launch_at))
            .min();
        tokio::select! {
            changed = updates.changed() => {
                if changed.is_err() {
                    let _ = send.send_replace(Picker::Failed("gRPC DNS resolver stopped".into()));
                    return;
                }
                update.clone_from(&updates.borrow_and_update());
            }
            event = received.recv() => {
                let Some(event) = event else { return; };
                publish_picker = if let Some(pool) = active.as_mut().filter(|pool| pool.id == event.pool) {
                    pool.event(event, &factory)
                } else if let Some(pool) = pending.as_mut().filter(|pool| pool.id == event.pool) {
                    pool.event(event, &factory)
                } else { false };
            }
            () = factory.wake.notified() => {
                if let Some(pool) = &mut active {
                    publish_picker = pool.idle;
                    pool.exit_idle(&factory);
                }
            }
            () = tokio::time::sleep_until(next_launch.unwrap_or_else(Instant::now)), if next_launch.is_some() => {
                let now = Instant::now();
                if let Some(pool) = &mut active { pool.timer(now, &factory); }
                if let Some(pool) = &mut pending { pool.timer(now, &factory); }
                publish_picker = true;
            }
        }
    }
}

async fn supervise_child(
    recipe: Recipe,
    scope: Arc<Scope>,
    resolver: DnsAuthority,
    host: String,
    events: mpsc::Sender<Event>,
    connect: Arc<Notify>,
    identity: ChildIdentity,
) {
    let mut backoff = UpstreamConnectBackoff::default();
    loop {
        connect.notified().await;
        if publish(&events, identity, State::Connecting).await.is_err() {
            return;
        }
        let delay = backoff.next_delay();
        let result = recipe
            .dial(delay.max(Duration::from_secs(20)), &scope)
            .await;
        let failure = match result {
            Ok(transport) if transport.alive() => {
                let transport = Arc::new(transport);
                let mut closed = transport.closed.clone();
                if publish(&events, identity, State::Ready(transport.clone()))
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    if closed.borrow_and_update().is_some() {
                        break;
                    }
                    if closed.changed().await.is_err() {
                        break;
                    }
                }
                resolver.resolve_now(&host);
                if publish(&events, identity, State::Idle).await.is_err() {
                    return;
                }
                drop(transport);
                backoff = UpstreamConnectBackoff::default();
                continue;
            }
            Ok(_) => "connection closed during setup".into(),
            Err(error) => error.to_string(),
        };
        resolver.resolve_now(&host);
        if publish(&events, identity, State::Failed(failure))
            .await
            .is_err()
        {
            return;
        }
        // Backoff belongs to this address, survives DNS passes and is reset
        // only after a successful transport. The policy decides when IDLE
        // should reconnect, retaining effective sticky failure until READY.
        tokio::time::sleep(delay).await;
        if publish(&events, identity, State::Idle).await.is_err() {
            return;
        }
    }
}

async fn publish(
    events: &mpsc::Sender<Event>,
    identity: ChildIdentity,
    state: State,
) -> Result<(), mpsc::error::SendError<Event>> {
    events
        .send(Event {
            pool: identity.pool,
            address: identity.address,
            generation: identity.generation,
            state,
        })
        .await
}
