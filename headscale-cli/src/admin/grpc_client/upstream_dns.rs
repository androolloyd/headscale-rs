//! Owned DNS resolver lifecycle and explicit-authority DNS transport.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, watch};
use tokio::time::Instant;

use super::{
    UpstreamConnectBackoff,
    upstream_nss::{self, LookupOrder},
    upstream_rfc6724,
    upstream_service_config::{self, ConfigState, SharedConfig},
    upstream_target,
};

const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_REFRESH: Duration = Duration::from_secs(30);
const A: u16 = 1;
const AAAA: u16 = 28;
const TXT: u16 = 16;

#[derive(Clone, Debug)]
pub(super) struct DnsAuthority {
    server: Option<(String, u16)>,
    state: Arc<Mutex<Option<ResolverWatcher>>>,
    config: SharedConfig,
}

#[derive(Debug)]
struct ResolverWatcher {
    host: String,
    refresh: Arc<Notify>,
    received: watch::Receiver<Option<LookupResult>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ResolverWatcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) type LookupResult = Result<Vec<SocketAddr>, (io::ErrorKind, String)>;

impl DnsAuthority {
    pub(super) fn new(authority: &str) -> Result<Self, String> {
        let server = upstream_target::dns_server_destination(authority)
            .map_err(|error| format!("invalid DNS resolver authority: {error}"))?;
        Ok(Self {
            server: Some(server),
            state: Arc::new(Mutex::new(None)),
            config: Arc::new(Mutex::new(ConfigState::default())),
        })
    }

    pub(super) fn system() -> Self {
        Self {
            server: None,
            state: Arc::new(Mutex::new(None)),
            config: Arc::new(Mutex::new(ConfigState::default())),
        }
    }

    pub(super) fn service_config(&self) -> SharedConfig {
        self.config.clone()
    }

    pub(super) fn resolve_now(&self, host: &str) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(watcher) = state.as_ref().filter(|watcher| watcher.host == host) {
            watcher.refresh.notify_one();
        }
    }

    pub(super) fn updates(&self, host: &str) -> Option<watch::Receiver<Option<LookupResult>>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|watcher| watcher.host == host)
            .map(|watcher| watcher.received.clone())
    }

    pub(super) async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let mut received = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(watcher) = state.as_ref()
                && watcher.host == host
            {
                // Reading a snapshot does not request another resolution.
                // Connection owners request it explicitly on failure/close.
                watcher.received.clone()
            } else {
                let refresh = Arc::new(Notify::new());
                let (send, received) = watch::channel(None);
                let task = tokio::spawn(watch_resolver(
                    host.to_owned(),
                    self.server.clone(),
                    refresh.clone(),
                    send,
                    self.config.clone(),
                ));
                *state = Some(ResolverWatcher {
                    host: host.to_owned(),
                    refresh,
                    received: received.clone(),
                    task,
                });
                received
            }
        };
        loop {
            let result = received.borrow().clone();
            if let Some(result) = result {
                return cached_result(&result, port);
            }
            received
                .changed()
                .await
                .map_err(|_| io::Error::other("gRPC DNS resolver stopped"))?;
        }
    }
}

async fn watch_resolver(
    host: String,
    server: Option<(String, u16)>,
    refresh: Arc<Notify>,
    send: watch::Sender<Option<LookupResult>>,
    service_config: SharedConfig,
) {
    let mut backoff = UpstreamConnectBackoff { retries: 1 };
    loop {
        let deadline = Instant::now() + RESOLUTION_TIMEOUT;
        let lookup = async {
            let addresses = async {
                if let Some(server) = &server {
                    resolve(&host, server).await.map(|addresses| {
                        addresses
                            .into_iter()
                            .map(|ip| SocketAddr::new(ip, 0))
                            .collect::<Vec<_>>()
                    })
                } else {
                    tokio::net::lookup_host((host.as_str(), 0))
                        .await
                        .map(std::iter::Iterator::collect::<Vec<_>>)
                }
            };
            let addresses = tokio::time::timeout_at(deadline, addresses)
                .await
                .unwrap_or_else(|_| Err(dns_timeout()));
            if addresses.as_ref().is_err_and(|error| {
                matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                )
            }) {
                // ReportError does not apply a service config or reset its
                // retry throttle. No TXT lookup follows a temporary A failure.
                return (addresses, None);
            }
            let config = if txt_flags().0 {
                match tokio::time::timeout_at(deadline, lookup_txt(&host, server.as_ref()))
                    .await
                    .unwrap_or_else(|_| Err(dns_timeout()))
                {
                    Ok(records) => upstream_service_config::select(&records),
                    Err(error)
                        if txt_flags().1
                            || !matches!(
                                error.kind(),
                                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                            ) =>
                    {
                        Ok(None)
                    }
                    Err(error) => Err(error.to_string()),
                }
            } else {
                Ok(None)
            };
            (addresses, Some(config))
        };
        let (mut result, config) = lookup.await;
        if result.as_ref().is_ok_and(Vec::is_empty) {
            result = Err(no_host());
        }
        let (config_ok, current) = {
            let mut state = service_config
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let accepted = config.is_none_or(|config| state.update(config));
            (accepted, state.current())
        };
        if !config_ok && current.is_none() {
            result = Err(io::Error::other("invalid DNS gRPC service configuration"));
        }
        if current
            .as_ref()
            .is_some_and(|config| config.shuffle_addresses)
            && let Ok(addresses) = &mut result
        {
            upstream_service_config::shuffle(addresses);
        }
        let successful = result.is_ok() && config_ok;
        // Keep ReportError distinct from a successful address update. The
        // balancer retains its own last good state for temporary failures.
        let published = result.map_err(|error| (error.kind(), error.to_string()));
        let _ = send.send_replace(Some(published));
        let delay = if successful {
            backoff = UpstreamConnectBackoff { retries: 1 };
            MIN_REFRESH
        } else {
            backoff.next_delay()
        };
        let next = Instant::now() + delay;
        if successful {
            refresh.notified().await;
        }
        tokio::time::sleep_until(next).await;
    }
}

fn txt_flags() -> (bool, bool) {
    static FLAGS: OnceLock<(bool, bool)> = OnceLock::new();
    *FLAGS.get_or_init(|| {
        let boolean =
            |name| std::env::var(name).map_or(true, |value| !value.eq_ignore_ascii_case("false"));
        (
            boolean("GRPC_ENABLE_TXT_SERVICE_CONFIG"),
            boolean("GRPC_GO_IGNORE_TXT_ERRORS"),
        )
    })
}

async fn lookup_txt(host: &str, server: Option<&(String, u16)>) -> io::Result<Vec<Vec<u8>>> {
    let config = ResolverConfig::load();
    let servers = if let Some(server) = server {
        tokio::net::lookup_host((server.0.as_str(), server.1))
            .await?
            .collect::<Vec<_>>()
    } else {
        config
            .nameservers
            .iter()
            .filter_map(|server| server.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 53))
            .collect()
    };
    let slots = if server.is_some() {
        config.server_slots
    } else {
        1
    };
    let mut last_error = no_host();
    'candidate: for name in config.names(&format!("_grpc_config.{host}")) {
        query(&name, TXT, 0, config.trust_ad)?;
        for _ in 0..config.attempts {
            for _ in 0..slots {
                for server in &servers {
                    match exchange(&name, TXT, *server, &config).await {
                        Ok(answer) if !answer.txt.is_empty() => return Ok(answer.txt),
                        Ok(_) => {
                            last_error = no_host();
                            continue 'candidate;
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            last_error = error;
                            continue 'candidate;
                        }
                        Err(error) => last_error = error,
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    }
    Err(last_error)
}

fn cached_result(result: &LookupResult, port: u16) -> io::Result<Vec<SocketAddr>> {
    match result {
        Ok(addresses) => Ok(addresses
            .iter()
            .map(|address| {
                let mut address = *address;
                address.set_port(port);
                address
            })
            .collect()),
        Err((kind, message)) => Err(io::Error::new(*kind, message.clone())),
    }
}

async fn resolve(host: &str, server: &(String, u16)) -> io::Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let config = ResolverConfig::load();
    let order = upstream_nss::lookup_order(&config.lookup, config.resolv_missing);
    if matches!(order, LookupOrder::FilesDns | LookupOrder::Files) {
        let from_hosts = hosts_file(host);
        if !from_hosts.is_empty() {
            // Go LookupHost returns file-first entries in file order before
            // reaching its RFC6724-sorted IP lookup path.
            return Ok(from_hosts);
        }
        if order == LookupOrder::Files {
            return Err(no_host());
        }
    }
    if !domain_name(host) {
        return Err(no_host());
    }
    let result = resolve_dns(host, server, &config).await;
    if result.is_err() && order == LookupOrder::DnsFiles {
        let mut from_hosts = hosts_file(host);
        if !from_hosts.is_empty() {
            upstream_rfc6724::sort_addresses(&mut from_hosts).await;
            return Ok(from_hosts);
        }
    }
    result
}

async fn resolve_dns(
    host: &str,
    server: &(String, u16),
    config: &ResolverConfig,
) -> io::Result<Vec<IpAddr>> {
    let servers = tokio::net::lookup_host((server.0.as_str(), server.1))
        .await?
        .collect::<Vec<_>>();
    if servers.is_empty() {
        return Err(no_host());
    }
    let mut last_error = no_host();
    for name in config.names(host) {
        let (v4, v6) = if config.single_request {
            (
                lookup_family(&name, A, &servers, config).await,
                lookup_family(&name, AAAA, &servers, config).await,
            )
        } else {
            tokio::join!(
                lookup_family(&name, A, &servers, config),
                lookup_family(&name, AAAA, &servers, config),
            )
        };
        let mut ips = Vec::new();
        for result in std::iter::once(v4).chain(std::iter::once(v6)) {
            match result {
                Ok(found) => {
                    for ip in found {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
                Err(error) => last_error = error,
            }
        }
        if !ips.is_empty() {
            upstream_rfc6724::sort_addresses(&mut ips).await;
            return Ok(ips);
        }
    }
    Err(last_error)
}

fn hosts_file(host: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(source) = std::fs::read_to_string("/etc/hosts") {
        for line in source.lines() {
            let mut fields = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_ascii_whitespace();
            let Some(ip) = fields.next().and_then(|ip| ip.parse::<IpAddr>().ok()) else {
                continue;
            };
            if fields.any(|name| unrooted(name).eq_ignore_ascii_case(unrooted(host)))
                && !ips.contains(&ip)
            {
                ips.push(ip);
            }
        }
    }
    ips
}

struct ResolverConfig {
    lookup: Vec<String>,
    resolv_missing: bool,
    search: Vec<String>,
    ndots: usize,
    timeout: Duration,
    attempts: usize,
    server_slots: usize,
    nameservers: Vec<String>,
    single_request: bool,
    use_tcp: bool,
    trust_ad: bool,
}

impl ResolverConfig {
    fn load() -> Self {
        let mut config = Self {
            lookup: Vec::new(),
            resolv_missing: false,
            search: Vec::new(),
            ndots: 1,
            timeout: Duration::from_secs(5),
            attempts: 2,
            server_slots: 0,
            nameservers: Vec::new(),
            single_request: false,
            use_tcp: false,
            trust_ad: false,
        };
        let source = std::fs::read_to_string("/etc/resolv.conf");
        config.resolv_missing = source
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound);
        if let Ok(source) = source {
            for line in source.lines() {
                let mut fields = line
                    .split(['#', ';'])
                    .next()
                    .unwrap_or_default()
                    .split_ascii_whitespace();
                match fields.next() {
                    Some("lookup") => config.lookup = fields.map(str::to_string).collect(),
                    Some("nameserver") => {
                        if let Some(server) = fields
                            .next()
                            .filter(|server| server.parse::<IpAddr>().is_ok())
                            && config.server_slots < 3
                        {
                            config.server_slots += 1;
                            config.nameservers.push(server.to_owned());
                        }
                    }
                    Some("domain") => {
                        if let Some(domain) = fields.next() {
                            config.search = vec![rooted(domain)];
                        }
                    }
                    Some("search") => {
                        config.search = fields.filter(|name| *name != ".").map(rooted).collect();
                    }
                    Some("options") => {
                        for option in fields {
                            if let Some(ndots) = option.strip_prefix("ndots:") {
                                config.ndots = ndots.parse::<usize>().unwrap_or_default().min(15);
                            } else if let Some(timeout) = option.strip_prefix("timeout:") {
                                config.timeout = Duration::from_secs(
                                    timeout.parse::<u64>().unwrap_or_default().max(1),
                                )
                                .min(RESOLUTION_TIMEOUT);
                            } else if let Some(attempts) = option.strip_prefix("attempts:") {
                                config.attempts =
                                    attempts.parse::<usize>().unwrap_or_default().max(1);
                            } else if matches!(option, "single-request" | "single-request-reopen") {
                                config.single_request = true;
                            } else if matches!(option, "use-vc" | "usevc" | "tcp") {
                                config.use_tcp = true;
                            } else if option == "trust-ad" {
                                config.trust_ad = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if config.server_slots == 0 {
            // Go's default resolver config has IPv4 and IPv6 loopback entries.
            // With an explicit DNS authority, its dialer overrides both.
            config.server_slots = 2;
            config.nameservers = vec!["127.0.0.1".into(), "::1".into()];
        }
        if config.search.is_empty()
            && let Ok(hostname) = hostname::get()
            && let Some((_, domain)) = hostname.to_str().and_then(|name| name.split_once('.'))
            && !domain.is_empty()
        {
            config.search.push(rooted(domain));
        }
        config
    }

    fn names(&self, host: &str) -> Vec<String> {
        if host.is_empty() || host.len() > 254 || (host.len() == 254 && !host.ends_with('.')) {
            return Vec::new();
        }
        let allowed = |name: &str| !unrooted(name).to_ascii_lowercase().ends_with(".onion");
        if host.ends_with('.') {
            return if allowed(host) {
                vec![host.into()]
            } else {
                Vec::new()
            };
        }
        let root = rooted(host);
        let first = host.bytes().filter(|byte| *byte == b'.').count() >= self.ndots;
        let mut names = Vec::new();
        if first && allowed(&root) {
            names.push(root.clone());
        }
        for suffix in &self.search {
            let name = format!("{root}{suffix}");
            if name.len() <= 254 && allowed(&name) && !names.contains(&name) {
                names.push(name);
            }
        }
        if !first && allowed(&root) {
            names.push(root);
        }
        names
    }
}

fn rooted(name: &str) -> String {
    if name.ends_with('.') {
        name.into()
    } else {
        format!("{name}.")
    }
}

async fn lookup_family(
    name: &str,
    qtype: u16,
    servers: &[SocketAddr],
    config: &ResolverConfig,
) -> io::Result<Vec<IpAddr>> {
    // Go assumes this is a recursive resolver: CNAMEs prefix the complete
    // address answer. It does not issue additional alias-chasing queries.
    // Reject invalid names before a potentially large configured retry loop.
    query(name, qtype, 0, config.trust_ad)?;
    let mut last_error = no_host();
    for _ in 0..config.attempts {
        for _ in 0..config.server_slots {
            for server in servers {
                match exchange(name, qtype, *server, config).await {
                    Ok(answer) if !answer.ips.is_empty() => return Ok(answer.ips),
                    Ok(_) => return Err(no_host()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(error),
                    Err(error) => last_error = error,
                }
                // Permit the outer absolute deadline to interrupt immediate I/O
                // failures even with a large system-config attempts value.
                tokio::task::yield_now().await;
            }
        }
    }
    Err(last_error)
}

#[derive(Default)]
struct Answer {
    ips: Vec<IpAddr>,
    txt: Vec<Vec<u8>>,
}

async fn exchange(
    name: &str,
    qtype: u16,
    server: SocketAddr,
    config: &ResolverConfig,
) -> io::Result<Answer> {
    let id = OsRng.next_u32() as u16;
    let query = query(name, qtype, id, config.trust_ad)?;
    if !config.use_tcp {
        let result = tokio::time::timeout(config.timeout, async {
            let socket = UdpSocket::bind(if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            socket.connect(server).await?;
            socket.send(&query).await?;
            let mut buffer = vec![0_u8; 1232];
            loop {
                let len = socket.recv(&mut buffer).await?;
                if let Some(response) = response(&buffer[..len], name, qtype, id, true)? {
                    return Ok::<_, io::Error>(response);
                }
            }
        })
        .await
        .map_err(|_| dns_timeout())??;
        if let DnsResponse::Answer(answer) = result {
            return Ok(answer);
        }
    }
    tokio::time::timeout(config.timeout, async {
        let mut stream = TcpStream::connect(server).await?;
        stream.write_u16(query.len() as u16).await?;
        stream.write_all(&query).await?;
        let len = usize::from(stream.read_u16().await?);
        let mut buffer = vec![0_u8; len];
        stream.read_exact(&mut buffer).await?;
        match response(&buffer, name, qtype, id, false)? {
            Some(DnsResponse::Answer(answer)) => Ok(answer),
            _ => Err(invalid_dns()),
        }
    })
    .await
    .map_err(|_| dns_timeout())?
}

fn query(name: &str, qtype: u16, id: u16, trust_ad: bool) -> io::Result<Vec<u8>> {
    if !domain_name(name) {
        return Err(invalid_dns());
    }
    let name = unrooted(name);
    let mut bytes = Vec::with_capacity(name.len() + 30);
    for word in [id, if trust_ad { 0x0120 } else { 0x0100 }, 1, 0, 0, 1] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    for label in name.split('.').filter(|_| !name.is_empty()) {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid_dns());
        }
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&qtype.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    // EDNS0, matching Go's default 1232-byte advertised UDP payload size.
    bytes.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    Ok(bytes)
}

enum DnsResponse {
    Truncated,
    Answer(Answer),
}

fn response(
    packet: &[u8],
    name: &str,
    qtype: u16,
    id: u16,
    udp: bool,
) -> io::Result<Option<DnsResponse>> {
    if packet.len() < 12 || word(packet, 0)? != id {
        return Ok(None);
    }
    let flags = word(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || word(packet, 4)? != 1 {
        return Ok(None);
    }
    let mut offset = 12;
    let Ok(question) = read_name(packet, &mut offset) else {
        return Ok(None);
    };
    if !question.eq_ignore_ascii_case(unrooted(name))
        || word(packet, offset).ok() != Some(qtype)
        || word(packet, offset + 2).ok() != Some(1)
    {
        return Ok(None);
    }
    offset += 4;
    if udp && flags & 0x0200 != 0 {
        return Ok(Some(DnsResponse::Truncated));
    }
    let mut answer = Answer::default();
    let mut requested = false;
    let mut rcode = flags & 15;
    for section in 0..3 {
        let count = word(packet, 6 + section * 2)?;
        for _ in 0..count {
            read_name(packet, &mut offset)?;
            let kind = word(packet, offset)?;
            word(packet, offset + 2)?;
            let len = usize::from(word(packet, offset + 8)?);
            let data = offset.checked_add(10).ok_or_else(invalid_dns)?;
            let end = data
                .checked_add(len)
                .filter(|end| *end <= packet.len())
                .ok_or_else(invalid_dns)?;
            if section == 2 && kind == 41 {
                rcode |= u16::from(*packet.get(offset + 4).ok_or_else(invalid_dns)?) << 4;
            } else if section == 0 {
                requested |= kind == qtype;
                // Match Go's skipToAnswer followed by address extraction:
                // CNAME-only responses are empty, and no extra query is sent.
                if requested && matches!(qtype, A | AAAA) && kind == A {
                    if len != 4 {
                        return Err(invalid_dns());
                    }
                    answer.ips.push(IpAddr::V4(Ipv4Addr::new(
                        packet[data],
                        packet[data + 1],
                        packet[data + 2],
                        packet[data + 3],
                    )));
                } else if requested && matches!(qtype, A | AAAA) && kind == AAAA {
                    if len != 16 {
                        return Err(invalid_dns());
                    }
                    let bytes: [u8; 16] =
                        packet[data..end].try_into().map_err(|_| invalid_dns())?;
                    answer.ips.push(IpAddr::V6(Ipv6Addr::from(bytes)));
                } else if requested && qtype == TXT && kind == TXT {
                    let mut text = Vec::new();
                    let mut cursor = data;
                    while cursor < end {
                        let length = usize::from(packet[cursor]);
                        cursor += 1;
                        let next = cursor
                            .checked_add(length)
                            .filter(|next| *next <= end)
                            .ok_or_else(invalid_dns)?;
                        text.extend_from_slice(&packet[cursor..next]);
                        cursor = next;
                    }
                    answer.txt.push(text);
                } else if requested && kind == 5 {
                    let mut cname_offset = data;
                    read_name(packet, &mut cname_offset)?;
                    if cname_offset != end {
                        return Err(invalid_dns());
                    }
                }
            }
            offset = end;
        }
    }
    match rcode {
        0 => Ok(Some(DnsResponse::Answer(answer))),
        3 => Err(no_host()),
        2 => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "DNS server returned rcode 2",
        )),
        _ => Err(io::Error::other(format!(
            "DNS server returned rcode {rcode}"
        ))),
    }
}

fn word(packet: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = packet
        .get(offset..offset.checked_add(2).ok_or_else(invalid_dns)?)
        .ok_or_else(invalid_dns)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_name(packet: &[u8], offset: &mut usize) -> io::Result<String> {
    let mut current = *offset;
    let mut jumped = false;
    let mut pointers = 0;
    let mut name = Vec::new();
    loop {
        let len = *packet.get(current).ok_or_else(invalid_dns)?;
        if len & 0xc0 == 0xc0 {
            let second = *packet.get(current + 1).ok_or_else(invalid_dns)?;
            if !jumped {
                *offset = current + 2;
            }
            pointers += 1;
            if pointers > 10 {
                return Err(invalid_dns());
            }
            current = (usize::from(len & 63) << 8) | usize::from(second);
            jumped = true;
        } else if len & 0xc0 != 0 {
            return Err(invalid_dns());
        } else {
            current += 1;
            if len == 0 {
                if !jumped {
                    *offset = current;
                }
                return String::from_utf8(name).map_err(|_| invalid_dns());
            }
            let label = packet
                .get(current..current + usize::from(len))
                .ok_or_else(invalid_dns)?;
            if label
                .iter()
                .any(|byte| !byte.is_ascii() || *byte == b'.' || *byte == 0)
            {
                return Err(invalid_dns());
            }
            if !name.is_empty() {
                name.push(b'.');
            }
            name.extend(label.iter().map(u8::to_ascii_lowercase));
            if name.len() > 253 {
                return Err(invalid_dns());
            }
            current += usize::from(len);
            if !jumped {
                *offset = current;
            }
        }
    }
}

fn invalid_dns() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS response or name")
}
fn no_host() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "DNS name has no matching addresses",
    )
}
fn dns_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out")
}

fn unrooted(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

fn domain_name(name: &str) -> bool {
    if name == "." {
        return true;
    }
    if name.is_empty() || name.len() > 254 || (name.len() == 254 && !name.ends_with('.')) {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut len = 0;
    for byte in name.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                len += 1;
            }
            b'0'..=b'9' => len += 1,
            b'-' if last != b'.' => {
                non_numeric = true;
                len += 1;
            }
            b'.' if last != b'.' && last != b'-' && (1..=63).contains(&len) => len = 0,
            _ => return false,
        }
        last = byte;
    }
    last != b'-' && len <= 63 && non_numeric
}
