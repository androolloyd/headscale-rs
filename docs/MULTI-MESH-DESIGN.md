# Multi-Mesh Federation Design

## Overview

This document describes the architecture for supporting multiple interconnected mesh networks (multi-mesh) in headscale-rs. Multi-mesh enables:

1. **Fleet Isolation**: Separate organizational meshes with distinct IP ranges and policies
2. **Cross-Mesh Rentals**: Nodes from one mesh can rent resources from another mesh
3. **Federated Identity**: DIDs work across mesh boundaries
4. **Mesh Peering**: Selective connectivity between trusted meshes

## Current Architecture (Single Mesh)

```
┌─────────────────────────────────────────────────────────────┐
│                    Single Mesh (100.64.0.0/10)              │
│                                                             │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐  │
│  │ Node A  │────│ Node B  │────│ Node C  │────│ Node D  │  │
│  │100.64.0.1│    │100.64.0.2│    │100.64.0.3│    │100.64.0.4│  │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘  │
│       │                              │                      │
│       └──────────────────────────────┘                      │
│              Full Mesh Connectivity                         │
│                                                             │
│  MeshCoordinator (single instance)                         │
│  - IP Allocator: 100.64.0.0/10                            │
│  - ACL Policy: allow-fleet                                 │
│  - DERP Servers: shared                                    │
└─────────────────────────────────────────────────────────────┘
```

### Limitations

- Single IP space (100.64.0.0/10)
- All nodes share one ACL policy
- No isolation between organizations
- Cannot selectively expose resources

## Multi-Mesh Architecture

### Mesh Identifier

Each mesh is identified by a unique `MeshId`:

```rust
/// Unique identifier for a mesh network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshId {
    /// DID of the mesh (derived from mesh root key)
    pub did: String,
    /// Human-readable name
    pub name: String,
    /// Short identifier (e.g., "acme-prod", "startup-dev")
    pub short_id: String,
}

impl MeshId {
    pub fn new(name: &str, root_pubkey: &[u8; 32]) -> Self {
        let did = format!("did:mesh:{}", hex::encode(&root_pubkey[..16]));
        let short_id = slug::slugify(name);
        Self {
            did,
            name: name.to_string(),
            short_id,
        }
    }
}
```

### Network Topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Multi-Mesh Federation                           │
│                                                                         │
│  ┌─────────────────────────────────┐  ┌─────────────────────────────────┐
│  │     Mesh A (acme-corp)          │  │     Mesh B (startup-dev)        │
│  │     100.64.0.0/16               │  │     100.65.0.0/16               │
│  │                                 │  │                                 │
│  │  ┌─────┐  ┌─────┐  ┌─────┐     │  │  ┌─────┐  ┌─────┐              │
│  │  │ A1  │──│ A2  │──│ A3  │     │  │  │ B1  │──│ B2  │              │
│  │  └─────┘  └─────┘  └─────┘     │  │  └─────┘  └─────┘              │
│  │      │                         │  │      │                         │
│  │  ┌───┴───┐                     │  │  ┌───┴───┐                     │
│  │  │Gateway│─────────────────────┼──┼──│Gateway│                     │
│  │  │  AG   │    Peering Link     │  │  │  BG   │                     │
│  │  └───────┘                     │  │  └───────┘                     │
│  │                                 │  │                                 │
│  │  ACL: internal-only            │  │  ACL: allow-rentals            │
│  └─────────────────────────────────┘  └─────────────────────────────────┘
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐
│  │                    Mesh Registry (Global)                           │
│  │  - Mesh discovery                                                   │
│  │  - Peering agreements                                               │
│  │  - Cross-mesh routing                                               │
│  └─────────────────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────────────────┘
```

### IP Address Allocation

Each mesh gets a distinct CIDR range within 100.64.0.0/10:

```rust
/// IP allocation strategy for multi-mesh.
pub struct MultiMeshAllocator {
    /// Maps mesh ID to allocated CIDR
    allocations: HashMap<MeshId, IpNet>,
    /// Available pool for new meshes
    available_pool: IpNet,
}

impl MultiMeshAllocator {
    /// Create allocator with the CGNAT range.
    pub fn new() -> Self {
        Self {
            allocations: HashMap::new(),
            available_pool: "100.64.0.0/10".parse().unwrap(),
        }
    }

    /// Allocate a /16 for a new mesh.
    pub fn allocate_mesh(&mut self, mesh_id: &MeshId) -> Result<IpNet, AllocationError> {
        // Strategy: sequential /16 allocation
        // 100.64.0.0/16, 100.65.0.0/16, ... 100.127.0.0/16
        // Gives us 64 possible meshes with 65,534 IPs each
        let count = self.allocations.len() as u8;
        if count >= 64 {
            return Err(AllocationError::Exhausted);
        }

        let cidr = format!("100.{}.0.0/16", 64 + count);
        let net: IpNet = cidr.parse().unwrap();

        self.allocations.insert(mesh_id.clone(), net.clone());
        Ok(net)
    }

    /// Get CIDR for a mesh.
    pub fn get_cidr(&self, mesh_id: &MeshId) -> Option<IpNet> {
        self.allocations.get(mesh_id).cloned()
    }
}
```

## Core Components

### 1. MeshRegistry

Central registry for mesh metadata and discovery:

```rust
/// Registry of all known meshes.
pub struct MeshRegistry {
    /// Local mesh (the one this node belongs to)
    local_mesh: MeshId,
    /// Known remote meshes
    remote_meshes: HashMap<MeshId, MeshInfo>,
    /// Peering agreements
    peerings: HashMap<(MeshId, MeshId), PeeringAgreement>,
}

/// Information about a mesh.
pub struct MeshInfo {
    pub id: MeshId,
    /// CIDR range for this mesh
    pub cidr: IpNet,
    /// Gateway nodes for external access
    pub gateways: Vec<GatewayInfo>,
    /// Supported capabilities
    pub capabilities: MeshCapabilities,
    /// Public key for mesh-level auth
    pub pubkey: [u8; 32],
    /// Last seen/updated
    pub last_seen: u64,
}

/// Gateway node information.
pub struct GatewayInfo {
    pub node_id: String,
    pub endpoints: Vec<SocketAddr>,
    pub derp_server: Option<String>,
    pub capabilities: Vec<String>,
}

/// What a mesh can provide to federated partners.
pub struct MeshCapabilities {
    /// Allows external rentals
    pub allows_rentals: bool,
    /// Provides inference resources
    pub provides_inference: bool,
    /// Provides storage
    pub provides_storage: bool,
    /// Provides compute
    pub provides_compute: bool,
    /// Provides exit nodes
    pub provides_exit: bool,
}
```

### 2. Peering Agreements

Meshes establish peering agreements for inter-mesh communication:

```rust
/// A peering agreement between two meshes.
pub struct PeeringAgreement {
    /// First mesh
    pub mesh_a: MeshId,
    /// Second mesh
    pub mesh_b: MeshId,
    /// Type of peering
    pub peering_type: PeeringType,
    /// ACL rules for cross-mesh traffic
    pub acl: CrossMeshAcl,
    /// Accounting terms
    pub accounting: PeeringAccounting,
    /// Agreement start time
    pub starts_at: u64,
    /// Agreement expiry (None = indefinite)
    pub expires_at: Option<u64>,
    /// Signatures from both meshes
    pub signatures: PeeringSignatures,
}

/// Type of peering relationship.
pub enum PeeringType {
    /// Full mesh connectivity (both directions)
    Full,
    /// One-way: A can access B's resources
    OneWay { provider: MeshId, consumer: MeshId },
    /// Transit: A can route through B to reach C
    Transit { via: MeshId },
    /// Rental-only: Only resource rental, no direct L3
    RentalOnly,
}

/// ACL for cross-mesh traffic.
pub struct CrossMeshAcl {
    /// Allowed source CIDRs from peer mesh
    pub allowed_sources: Vec<IpNet>,
    /// Allowed destination CIDRs in local mesh
    pub allowed_destinations: Vec<IpNet>,
    /// Allowed ports
    pub allowed_ports: Vec<PortRange>,
    /// Allowed protocols
    pub allowed_protocols: Vec<Protocol>,
}

/// Accounting terms for cross-mesh traffic.
pub struct PeeringAccounting {
    /// Billing model
    pub model: BillingModel,
    /// Settlement currency
    pub currency: String,
    /// Settlement period (seconds)
    pub settlement_period: u64,
}

pub enum BillingModel {
    /// No charges (settlement-free peering)
    Free,
    /// Pay per byte transferred
    PerByte { rate_per_gb: u64 },
    /// Pay per session/connection
    PerSession { rate_per_session: u64 },
    /// Flat monthly fee
    FlatRate { monthly_rate: u64 },
}
```

### 3. Cross-Mesh Routing

Extended routing table for multi-mesh:

```rust
/// Extended routing table with mesh awareness.
pub struct MultiMeshRouter {
    /// Local routing table (within mesh)
    local_routes: RoutingTable,
    /// Cross-mesh routes (prefix -> gateway)
    cross_mesh_routes: HashMap<IpNet, CrossMeshRoute>,
    /// Known mesh CIDRs
    mesh_cidrs: HashMap<MeshId, IpNet>,
}

/// A route to another mesh.
pub struct CrossMeshRoute {
    /// Target mesh
    pub target_mesh: MeshId,
    /// Local gateway to use
    pub gateway: String,
    /// Peering agreement governing this route
    pub peering_id: String,
    /// Metrics
    pub latency_ms: Option<u32>,
    pub available: bool,
}

impl MultiMeshRouter {
    /// Look up next hop for a destination.
    pub fn lookup(&self, dst: IpAddr) -> Option<NextHop> {
        // First check local routes
        if let Some(peer) = self.local_routes.lookup(dst) {
            return Some(NextHop::Local { peer_id: peer.to_string() });
        }

        // Check cross-mesh routes
        for (cidr, route) in &self.cross_mesh_routes {
            if cidr.contains(&dst) && route.available {
                return Some(NextHop::CrossMesh {
                    gateway: route.gateway.clone(),
                    target_mesh: route.target_mesh.clone(),
                });
            }
        }

        None
    }
}

pub enum NextHop {
    /// Route to local peer
    Local { peer_id: String },
    /// Route through gateway to another mesh
    CrossMesh { gateway: String, target_mesh: MeshId },
    /// Drop (no route)
    Drop,
}
```

### 4. Gateway Nodes

Special nodes that handle cross-mesh traffic:

```rust
/// A gateway node that bridges meshes.
pub struct MeshGateway {
    /// Local mesh identity
    local_mesh: MeshId,
    /// Node identity
    node_id: String,
    /// Peering connections to other meshes
    peers: HashMap<MeshId, GatewayPeer>,
    /// Traffic accounting
    accounting: CrossMeshAccounting,
    /// Rate limiter
    rate_limiter: RateLimiter,
}

/// Connection to a peer mesh's gateway.
pub struct GatewayPeer {
    pub mesh_id: MeshId,
    pub endpoint: SocketAddr,
    pub pubkey: [u8; 32],
    pub tunnel: Option<TunnelState>,
    pub last_handshake: Option<Instant>,
}

impl MeshGateway {
    /// Forward a packet to another mesh.
    pub async fn forward(&self, packet: &[u8], target_mesh: &MeshId) -> Result<(), GatewayError> {
        // Check peering agreement
        let peer = self.peers.get(target_mesh)
            .ok_or(GatewayError::NoPeering)?;

        // Rate limit
        if !self.rate_limiter.check(target_mesh) {
            return Err(GatewayError::RateLimited);
        }

        // Account for traffic
        self.accounting.record(target_mesh, packet.len() as u64);

        // Forward through tunnel
        if let Some(tunnel) = &peer.tunnel {
            tunnel.send(packet).await?;
        } else {
            return Err(GatewayError::TunnelDown);
        }

        Ok(())
    }
}
```

## Cross-Mesh Rentals

### Rental Flow

```
Consumer Mesh (A)                              Provider Mesh (B)
     │                                              │
     │  1. Discover resources via federation       │
     │─────────────────────────────────────────────▶
     │                                              │
     │  2. Create escrow (cross-mesh accounting)   │
     │─────────────────────────────────────────────▶
     │                                              │
     │  3. Request rental context                  │
     │─────────────────────────────────────────────▶
     │                                              │
     │  4. Receive isolated WireGuard config       │
     │◀─────────────────────────────────────────────
     │                                              │
     │  5. Connect via rental tunnel (not mesh)    │
     │═══════════════════════════════════════════════
     │          (isolated from mesh B)             │
     │                                              │
     │  6. Traffic metered, settled periodically   │
     │─────────────────────────────────────────────▶
     │                                              │
     │  7. End rental, final settlement            │
     │─────────────────────────────────────────────▶
```

### Rental Isolation

Cross-mesh rentals use the existing `RentalContext` with mesh awareness:

```rust
/// Extended rental context for cross-mesh rentals.
pub struct CrossMeshRentalContext {
    /// Base rental context
    pub rental: RentalContext,
    /// Consumer's mesh
    pub consumer_mesh: MeshId,
    /// Provider's mesh
    pub provider_mesh: MeshId,
    /// Cross-mesh escrow ID
    pub escrow_id: EscrowId,
    /// Peering agreement used
    pub peering_id: String,
}

impl CrossMeshRentalContext {
    /// Security invariant: Renter cannot access provider's mesh network.
    pub fn allowed_destinations(&self) -> Vec<IpNet> {
        vec![
            // Only internet (exit node usage)
            "0.0.0.0/0".parse().unwrap(),
        ]
    }

    pub fn blocked_destinations(&self) -> Vec<IpNet> {
        vec![
            // Block provider's mesh
            self.provider_mesh_cidr(),
            // Block all private ranges
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
            // Block CGNAT (all meshes)
            "100.64.0.0/10".parse().unwrap(),
        ]
    }
}
```

## Identity Federation

### DID Resolution Across Meshes

```rust
/// Federated identity resolver.
pub struct FederatedResolver {
    /// Local mesh's identity store
    local_store: IdentityStore,
    /// Remote mesh resolvers
    remote_resolvers: HashMap<MeshId, RemoteResolver>,
}

impl FederatedResolver {
    /// Resolve a DID, checking local then remote meshes.
    pub async fn resolve(&self, did: &str) -> Result<Identity, ResolveError> {
        // Try local first
        if let Some(identity) = self.local_store.get(did) {
            return Ok(identity);
        }

        // Extract mesh hint from DID if present
        // e.g., did:mesh:acme-corp:node123
        if let Some(mesh_id) = extract_mesh_hint(did) {
            if let Some(resolver) = self.remote_resolvers.get(&mesh_id) {
                return resolver.resolve(did).await;
            }
        }

        // Broadcast to all peered meshes
        for (mesh_id, resolver) in &self.remote_resolvers {
            if let Ok(identity) = resolver.resolve(did).await {
                return Ok(identity);
            }
        }

        Err(ResolveError::NotFound)
    }
}
```

## Events and Synchronization

### Cross-Mesh Events

```rust
/// Events that span mesh boundaries.
pub enum FederationEvent {
    /// A new mesh was discovered
    MeshDiscovered { mesh: MeshInfo },
    /// A mesh went offline
    MeshOffline { mesh_id: MeshId },
    /// Peering agreement established
    PeeringEstablished { agreement: PeeringAgreement },
    /// Peering agreement terminated
    PeeringTerminated { mesh_a: MeshId, mesh_b: MeshId, reason: String },
    /// Gateway connection changed
    GatewayStatusChanged { mesh_id: MeshId, gateway: String, online: bool },
    /// Cross-mesh route changed
    CrossMeshRouteChanged { target: MeshId, available: bool },
    /// Cross-mesh rental started
    CrossMeshRentalStarted {
        consumer_mesh: MeshId,
        provider_mesh: MeshId,
        rental_id: String,
    },
    /// Cross-mesh rental ended
    CrossMeshRentalEnded {
        rental_id: String,
        total_cost: u64,
    },
}
```

## Database Schema Extensions

### Meshes Table

```sql
CREATE TABLE meshes (
    id TEXT PRIMARY KEY,              -- Mesh DID
    name TEXT NOT NULL,
    short_id TEXT NOT NULL UNIQUE,
    cidr TEXT NOT NULL,               -- Allocated CIDR
    pubkey TEXT NOT NULL,             -- Mesh public key
    capabilities TEXT NOT NULL,       -- JSON capabilities
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

### Peerings Table

```sql
CREATE TABLE peerings (
    id TEXT PRIMARY KEY,
    mesh_a TEXT NOT NULL REFERENCES meshes(id),
    mesh_b TEXT NOT NULL REFERENCES meshes(id),
    peering_type TEXT NOT NULL,
    acl TEXT NOT NULL,                -- JSON ACL
    accounting TEXT NOT NULL,         -- JSON accounting
    starts_at INTEGER NOT NULL,
    expires_at INTEGER,
    signatures TEXT NOT NULL,         -- JSON signatures
    created_at INTEGER NOT NULL,
    UNIQUE(mesh_a, mesh_b)
);
```

### Gateways Table

```sql
CREATE TABLE gateways (
    id TEXT PRIMARY KEY,
    mesh_id TEXT NOT NULL REFERENCES meshes(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    endpoints TEXT NOT NULL,          -- JSON endpoints
    capabilities TEXT NOT NULL,       -- JSON
    online BOOLEAN NOT NULL,
    last_seen INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(mesh_id, node_id)
);
```

## API Extensions

### gRPC Service

```protobuf
service Federation {
    // Mesh discovery
    rpc DiscoverMeshes(DiscoverRequest) returns (DiscoverResponse);
    rpc GetMeshInfo(GetMeshInfoRequest) returns (MeshInfo);

    // Peering
    rpc ProposePeering(PeeringProposal) returns (PeeringResponse);
    rpc AcceptPeering(PeeringAcceptance) returns (PeeringAgreement);
    rpc TerminatePeering(TerminateRequest) returns (TerminateResponse);

    // Cross-mesh operations
    rpc RequestCrossMeshRental(CrossMeshRentalRequest) returns (CrossMeshRentalResponse);
    rpc ResolveFederatedIdentity(ResolveRequest) returns (Identity);

    // Gateway operations
    rpc RegisterGateway(GatewayRegistration) returns (GatewayResponse);
    rpc HeartbeatGateway(GatewayHeartbeat) returns (HeartbeatResponse);
}
```

## Security Considerations

### Threat Model

1. **Malicious Mesh**: A federated mesh attempts to:
   - Scan internal resources of peer mesh
   - Exfiltrate data through rentals
   - DoS peer mesh through gateway

2. **Gateway Compromise**: Attacker controls a gateway node

3. **Peering Abuse**: Mesh violates peering agreement terms

### Mitigations

1. **Strict ACLs**: Default-deny with explicit allow rules
2. **Rate Limiting**: Per-mesh and per-node limits at gateways
3. **Traffic Inspection**: Optional deep packet inspection for sensitive meshes
4. **Peering Audit**: Log all cross-mesh traffic for compliance
5. **Automatic Revocation**: Terminate peering on policy violation

### Trust Hierarchy

```
Mesh Root Key
    │
    ├── Gateway Keys (derived)
    │   └── Per-peering session keys
    │
    ├── Node Keys (enrolled)
    │   └── Per-tunnel keys
    │
    └── Service Keys (delegated)
        └── Per-rental context keys
```

## Implementation Phases

### Phase 1: Foundation
- [ ] `MeshId` and `MeshRegistry` types
- [ ] Multi-mesh IP allocation
- [ ] Database schema for meshes

### Phase 2: Peering
- [ ] Peering agreement protocol
- [ ] Gateway node implementation
- [ ] Cross-mesh routing

### Phase 3: Rentals
- [ ] Cross-mesh escrow
- [ ] Federated rental context
- [ ] Cross-mesh metering

### Phase 4: Identity
- [ ] Federated DID resolution
- [ ] Cross-mesh authentication
- [ ] Capability delegation

### Phase 5: Operations
- [ ] Mesh discovery protocol
- [ ] Peering dashboard
- [ ] Cross-mesh monitoring

## Open Questions

1. **Mesh Discovery**: How do meshes discover each other initially?
   - Manual configuration
   - DHT-based discovery
   - Central registry

2. **Dispute Resolution**: What happens when meshes disagree on metering?
   - Third-party arbitration
   - Cryptographic proofs
   - Reputation system

3. **Mesh Hierarchy**: Can meshes have sub-meshes?
   - Organizational units
   - Multi-tenant hosting

4. **Cross-Mesh ACLs**: Who has authority over cross-mesh traffic?
   - Both meshes must agree
   - Provider mesh decides
   - Consumer mesh decides

## References

- [Tailscale ACL Policy](https://tailscale.com/kb/1018/acls/)
- [WireGuard Protocol](https://www.wireguard.com/protocol/)
- [DID Core Specification](https://www.w3.org/TR/did-core/)
- [BGP Peering Concepts](https://www.rfc-editor.org/rfc/rfc4271)
