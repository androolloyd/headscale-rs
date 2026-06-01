package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

type scenario struct {
	Name             string            `json:"name"`
	Policy           json.RawMessage   `json:"policy"`
	Users            []scenarioUser    `json:"users,omitempty"`
	Nodes            []scenarioNode    `json:"nodes,omitempty"`
	FilterNodeChecks []filterNodeCheck `json:"filter_node_checks,omitempty"`
	PeerMapChecks    []peerMapCheck    `json:"peer_map_checks,omitempty"`
	RouteChecks      []routeCheck      `json:"route_checks,omitempty"`
	ViaRouteChecks   []viaRouteCheck   `json:"via_route_checks,omitempty"`
	TagChecks        []tagCheck        `json:"tag_checks,omitempty"`
	NodeAttrChecks   []nodeAttrCheck   `json:"node_attr_checks,omitempty"`
	SSHChecks        []sshCheck        `json:"ssh_checks,omitempty"`
	ExpectPolicyErr  string            `json:"expect_policy_error,omitempty"`
	Wire             *wireScenario     `json:"wire,omitempty"`
}

type scenarioUser struct {
	ID    uint   `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

type scenarioNode struct {
	ID             uint64   `json:"id"`
	UserID         uint     `json:"user_id"`
	Hostname       string   `json:"hostname"`
	IPv4           string   `json:"ipv4"`
	IPv6           string   `json:"ipv6,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Routes         []string `json:"routes,omitempty"`
	ApprovedRoutes []string `json:"approved_routes,omitempty"`
}

type scenarioOutput struct {
	Engine         string             `json:"engine"`
	Name           string             `json:"name"`
	Filter         []filterRuleOut    `json:"filter"`
	PolicyError    string             `json:"policy_error,omitempty"`
	FilterForNodes []filterForNodeOut `json:"filter_for_nodes,omitempty"`
	PeerMaps       []peerMapOut       `json:"peer_maps,omitempty"`
	RouteApprovals []routeApprovalOut `json:"route_approvals,omitempty"`
	ViaRoutes      []viaRouteOut      `json:"via_routes,omitempty"`
	TagChecks      []tagCheckOut      `json:"tag_checks,omitempty"`
	NodeAttrs      []nodeAttrOut      `json:"node_attrs,omitempty"`
	SSHPolicies    []sshPolicyOut     `json:"ssh_policies,omitempty"`
	Wire           *wireOutput        `json:"wire,omitempty"`
}

type filterNodeCheck struct {
	Name   string `json:"name"`
	NodeID uint64 `json:"node_id"`
}

type filterForNodeOut struct {
	Name  string          `json:"name"`
	Rules []filterRuleOut `json:"rules"`
}

type peerMapCheck struct {
	Name   string `json:"name"`
	NodeID uint64 `json:"node_id"`
}

type peerMapOut struct {
	Name  string   `json:"name"`
	Peers []uint64 `json:"peers"`
}

type routeCheck struct {
	Name            string   `json:"name"`
	NodeID          uint64   `json:"node_id"`
	CurrentApproved []string `json:"current_approved,omitempty"`
	AnnouncedRoutes []string `json:"announced_routes,omitempty"`
}

type routeApprovalOut struct {
	Name           string   `json:"name"`
	ApprovedRoutes []string `json:"approved_routes"`
	Changed        bool     `json:"changed"`
}

type viaRouteCheck struct {
	Name     string `json:"name"`
	ViewerID uint64 `json:"viewer_id"`
	PeerID   uint64 `json:"peer_id"`
}

type viaRouteOut struct {
	Name       string   `json:"name"`
	Include    []string `json:"include"`
	Exclude    []string `json:"exclude"`
	UsePrimary []string `json:"use_primary"`
}

type tagCheck struct {
	Name   string `json:"name"`
	NodeID uint64 `json:"node_id"`
	Tag    string `json:"tag"`
}

type tagCheckOut struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

type nodeAttrCheck struct {
	Name   string `json:"name"`
	NodeID uint64 `json:"node_id"`
}

type nodeAttrOut struct {
	Name  string   `json:"name"`
	Attrs []string `json:"attrs"`
}

type sshCheck struct {
	Name   string `json:"name"`
	NodeID uint64 `json:"node_id"`
}

type sshPolicyOut struct {
	Name  string       `json:"name"`
	Rules []sshRuleOut `json:"rules"`
}

type sshRuleOut struct {
	Principals []string          `json:"principals"`
	SSHUsers   map[string]string `json:"ssh_users"`
	Action     sshActionOut      `json:"action"`
	AcceptEnv  []string          `json:"accept_env,omitempty"`
}

type sshActionOut struct {
	Accept                    bool   `json:"accept"`
	Reject                    bool   `json:"reject"`
	SessionDurationNanos      int64  `json:"session_duration_nanos"`
	HoldAndDelegate           string `json:"hold_and_delegate,omitempty"`
	AllowAgentForwarding      bool   `json:"allow_agent_forwarding"`
	AllowLocalPortForwarding  bool   `json:"allow_local_port_forwarding"`
	AllowRemotePortForwarding bool   `json:"allow_remote_port_forwarding"`
}

type wireScenario struct {
	DNSConfig        json.RawMessage `json:"dns_config,omitempty"`
	RuntimeDNSConfig json.RawMessage `json:"runtime_dns_config,omitempty"`
	DERPMap          json.RawMessage `json:"derp_map,omitempty"`
	RegisterRequest  json.RawMessage `json:"register_request,omitempty"`
	RegisterResponse json.RawMessage `json:"register_response,omitempty"`
	MapRequest       json.RawMessage `json:"map_request,omitempty"`
	MapResponse      json.RawMessage `json:"map_response,omitempty"`
}

type wireOutput struct {
	DNSConfig        json.RawMessage          `json:"dns_config,omitempty"`
	RuntimeDNSConfig json.RawMessage          `json:"runtime_dns_config,omitempty"`
	DERPMap          json.RawMessage          `json:"derp_map,omitempty"`
	RegisterRequest  *registerRequestSummary  `json:"register_request,omitempty"`
	RegisterResponse *registerResponseSummary `json:"register_response,omitempty"`
	MapRequest       *mapRequestSummary       `json:"map_request,omitempty"`
	MapResponse      *mapResponseSummary      `json:"map_response,omitempty"`
}

type registerRequestSummary struct {
	Version          int              `json:"version,omitempty"`
	NodeKey          string           `json:"node_key"`
	OldNodeKey       string           `json:"old_node_key,omitempty"`
	NLKey            string           `json:"nl_key,omitempty"`
	AuthKey          string           `json:"auth_key,omitempty"`
	Hostinfo         *hostInfoSummary `json:"hostinfo,omitempty"`
	Followup         string           `json:"followup,omitempty"`
	Tailnet          string           `json:"tailnet,omitempty"`
	Ephemeral        bool             `json:"ephemeral,omitempty"`
	RequestedExpiry  bool             `json:"requested_expiry,omitempty"`
	NodeKeySignature string           `json:"node_key_signature,omitempty"`
	SignatureType    string           `json:"signature_type,omitempty"`
	Timestamp        bool             `json:"timestamp,omitempty"`
	DeviceCert       string           `json:"device_cert,omitempty"`
	Signature        string           `json:"signature,omitempty"`
}

type registerResponseSummary struct {
	User              userSummary  `json:"user"`
	Login             loginSummary `json:"login"`
	NodeKeyExpired    bool         `json:"node_key_expired"`
	AuthURL           string       `json:"auth_url"`
	MachineAuthorized bool         `json:"machine_authorized"`
	NodeKeySignature  string       `json:"node_key_signature,omitempty"`
	Error             string       `json:"error,omitempty"`
}

type mapRequestSummary struct {
	Version                                  int              `json:"version,omitempty"`
	Stream                                   bool             `json:"stream,omitempty"`
	KeepAlive                                bool             `json:"keep_alive,omitempty"`
	Compress                                 string           `json:"compress,omitempty"`
	OmitPeers                                bool             `json:"omit_peers,omitempty"`
	NodeKey                                  string           `json:"node_key,omitempty"`
	MapSessionHandle                         string           `json:"map_session_handle,omitempty"`
	MapSessionSeq                            int64            `json:"map_session_seq,omitempty"`
	DiscoKey                                 string           `json:"disco_key,omitempty"`
	HardwareAttestationKey                   string           `json:"hardware_attestation_key,omitempty"`
	HardwareAttestationKeySignature          string           `json:"hardware_attestation_key_signature,omitempty"`
	HardwareAttestationKeySignatureTimestamp bool             `json:"hardware_attestation_key_signature_timestamp,omitempty"`
	Endpoints                                []string         `json:"endpoints,omitempty"`
	EndpointTypes                            []int            `json:"endpoint_types,omitempty"`
	ReadOnly                                 bool             `json:"read_only,omitempty"`
	TKAHead                                  string           `json:"tka_head,omitempty"`
	DebugFlags                               []string         `json:"debug_flags,omitempty"`
	ConnectionHandleForTest                  string           `json:"connection_handle_for_test,omitempty"`
	Hostinfo                                 *hostInfoSummary `json:"hostinfo,omitempty"`
}

type userSummary struct {
	ID            uint64 `json:"id"`
	DisplayName   string `json:"display_name,omitempty"`
	ProfilePicURL string `json:"profile_pic_url,omitempty"`
	Created       string `json:"created,omitempty"`
}

type loginSummary struct {
	ID            uint64 `json:"id"`
	Provider      string `json:"provider,omitempty"`
	LoginName     string `json:"login_name,omitempty"`
	DisplayName   string `json:"display_name,omitempty"`
	ProfilePicURL string `json:"profile_pic_url,omitempty"`
}

type mapResponseSummary struct {
	MapSessionHandle          string               `json:"map_session_handle,omitempty"`
	Seq                       int64                `json:"seq,omitempty"`
	KeepAlive                 bool                 `json:"keep_alive"`
	PingRequest               json.RawMessage      `json:"ping_request,omitempty"`
	PopBrowserURL             string               `json:"pop_browser_url,omitempty"`
	Domain                    string               `json:"domain,omitempty"`
	CollectServices           *bool                `json:"collect_services,omitempty"`
	Node                      *mapNodeSummary      `json:"node,omitempty"`
	PeerCount                 int                  `json:"peer_count"`
	Peers                     []mapNodeSummary     `json:"peers,omitempty"`
	PeersChanged              []mapNodeSummary     `json:"peers_changed,omitempty"`
	PeersRemoved              []uint64             `json:"peers_removed,omitempty"`
	PeersChangedPatch         json.RawMessage      `json:"peers_changed_patch,omitempty"`
	PeerSeenChange            json.RawMessage      `json:"peer_seen_change,omitempty"`
	OnlineChange              json.RawMessage      `json:"online_change,omitempty"`
	UserProfiles              []userProfileSummary `json:"user_profiles,omitempty"`
	PacketFilter              []filterRuleOut      `json:"packet_filter,omitempty"`
	PacketFilters             json.RawMessage      `json:"packet_filters,omitempty"`
	Health                    *[]string            `json:"health,omitempty"`
	DisplayMessages           json.RawMessage      `json:"display_messages,omitempty"`
	DNSConfig                 json.RawMessage      `json:"dns_config,omitempty"`
	DERPMap                   json.RawMessage      `json:"derp_map,omitempty"`
	SSHPolicy                 []sshRuleOut         `json:"ssh_policy,omitempty"`
	ControlTime               json.RawMessage      `json:"control_time,omitempty"`
	TKAInfo                   json.RawMessage      `json:"tka_info,omitempty"`
	DomainDataPlaneAuditLogID string               `json:"domain_data_plane_audit_log_id,omitempty"`
	Debug                     json.RawMessage      `json:"debug,omitempty"`
	ControlDialPlan           json.RawMessage      `json:"control_dial_plan,omitempty"`
	ClientVersion             json.RawMessage      `json:"client_version,omitempty"`
	DefaultAutoUpdate         *bool                `json:"default_auto_update,omitempty"`
}

type mapNodeSummary struct {
	ID                            uint64           `json:"id"`
	StableID                      string           `json:"stable_id,omitempty"`
	Name                          string           `json:"name,omitempty"`
	User                          uint64           `json:"user"`
	Sharer                        uint64           `json:"sharer,omitempty"`
	Key                           string           `json:"key,omitempty"`
	KeySignature                  string           `json:"key_signature,omitempty"`
	Machine                       string           `json:"machine,omitempty"`
	DiscoKey                      string           `json:"disco_key,omitempty"`
	Addresses                     []string         `json:"addresses,omitempty"`
	AllowedIPs                    []string         `json:"allowed_ips,omitempty"`
	PrimaryRoutes                 []string         `json:"primary_routes,omitempty"`
	Endpoints                     []string         `json:"endpoints,omitempty"`
	LegacyDERPString              string           `json:"legacy_derp_string,omitempty"`
	Hostinfo                      *hostInfoSummary `json:"hostinfo,omitempty"`
	Tags                          []string         `json:"tags,omitempty"`
	Created                       string           `json:"created,omitempty"`
	KeyExpiry                     string           `json:"key_expiry,omitempty"`
	LastSeen                      string           `json:"last_seen,omitempty"`
	Online                        *bool            `json:"online,omitempty"`
	MachineAuthorized             bool             `json:"machine_authorized,omitempty"`
	Cap                           int              `json:"cap,omitempty"`
	Capabilities                  []string         `json:"capabilities,omitempty"`
	CapMap                        json.RawMessage  `json:"cap_map,omitempty"`
	Expired                       bool             `json:"expired,omitempty"`
	HomeDERP                      int              `json:"home_derp,omitempty"`
	UnsignedPeerAPIOnly           bool             `json:"unsigned_peer_api_only,omitempty"`
	ComputedName                  string           `json:"computed_name,omitempty"`
	ComputedNameWithHost          string           `json:"computed_name_with_host,omitempty"`
	DataPlaneAuditLogID           string           `json:"data_plane_audit_log_id,omitempty"`
	SelfNodeV4MasqAddrForThisPeer string           `json:"self_node_v4_masq_addr_for_this_peer,omitempty"`
	SelfNodeV6MasqAddrForThisPeer string           `json:"self_node_v6_masq_addr_for_this_peer,omitempty"`
	IsWireGuardOnly               bool             `json:"is_wire_guard_only,omitempty"`
	IsJailed                      bool             `json:"is_jailed,omitempty"`
	ExitNodeDNSResolvers          json.RawMessage  `json:"exit_node_dns_resolvers,omitempty"`
}

type userProfileSummary struct {
	ID            uint64 `json:"id"`
	LoginName     string `json:"login_name,omitempty"`
	DisplayName   string `json:"display_name,omitempty"`
	ProfilePicURL string `json:"profile_pic_url,omitempty"`
}

type serviceSummary struct {
	Proto       string `json:"proto,omitempty"`
	Port        uint16 `json:"port,omitempty"`
	Description string `json:"description,omitempty"`
}

type locationSummary struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	City        string  `json:"city,omitempty"`
	CityCode    string  `json:"city_code,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Priority    int     `json:"priority,omitempty"`
}

type tpmInfoSummary struct {
	Manufacturer    string `json:"manufacturer,omitempty"`
	Vendor          string `json:"vendor,omitempty"`
	Model           int    `json:"model,omitempty"`
	FirmwareVersion uint64 `json:"firmware_version,omitempty"`
	SpecRevision    int    `json:"spec_revision,omitempty"`
	FamilyIndicator string `json:"family_indicator,omitempty"`
}

type hostInfoSummary struct {
	IPNVersion      string             `json:"ipn_version,omitempty"`
	FrontendLogID   string             `json:"frontend_log_id,omitempty"`
	BackendLogID    string             `json:"backend_log_id,omitempty"`
	Hostname        string             `json:"hostname,omitempty"`
	OS              string             `json:"os,omitempty"`
	OSVersion       string             `json:"os_version,omitempty"`
	Container       *bool              `json:"container,omitempty"`
	Env             string             `json:"env,omitempty"`
	Distro          string             `json:"distro,omitempty"`
	DistroVersion   string             `json:"distro_version,omitempty"`
	DistroCodeName  string             `json:"distro_code_name,omitempty"`
	App             string             `json:"app,omitempty"`
	Desktop         *bool              `json:"desktop,omitempty"`
	Package         string             `json:"package,omitempty"`
	DeviceModel     string             `json:"device_model,omitempty"`
	PushDeviceToken string             `json:"push_device_token,omitempty"`
	ShieldsUp       bool               `json:"shields_up,omitempty"`
	ShareeNode      bool               `json:"sharee_node,omitempty"`
	NoLogsNoSupport bool               `json:"no_logs_no_support,omitempty"`
	WireIngress     bool               `json:"wire_ingress,omitempty"`
	IngressEnabled  bool               `json:"ingress_enabled,omitempty"`
	AllowsUpdate    bool               `json:"allows_update,omitempty"`
	Machine         string             `json:"machine,omitempty"`
	GoArch          string             `json:"go_arch,omitempty"`
	GoArchVar       string             `json:"go_arch_var,omitempty"`
	GoVersion       string             `json:"go_version,omitempty"`
	RoutableIPs     []string           `json:"routable_ips,omitempty"`
	RequestTags     []string           `json:"request_tags,omitempty"`
	WoLMACs         []string           `json:"wol_macs,omitempty"`
	Services        []serviceSummary   `json:"services,omitempty"`
	SSHHostKeys     []string           `json:"ssh_host_keys,omitempty"`
	Cloud           string             `json:"cloud,omitempty"`
	Userspace       *bool              `json:"userspace,omitempty"`
	UserspaceRouter *bool              `json:"userspace_router,omitempty"`
	AppConnector    *bool              `json:"app_connector,omitempty"`
	ServicesHash    string             `json:"services_hash,omitempty"`
	ExitNodeID      string             `json:"exit_node_id,omitempty"`
	Location        *locationSummary   `json:"location,omitempty"`
	TPM             *tpmInfoSummary    `json:"tpm,omitempty"`
	StateEncrypted  *bool              `json:"state_encrypted,omitempty"`
	MappingVaries   *bool              `json:"mapping_varies_by_dest_ip,omitempty"`
	WorkingIPv6     *bool              `json:"working_ipv6,omitempty"`
	OSHasIPv6       *bool              `json:"os_has_ipv6,omitempty"`
	WorkingUDP      *bool              `json:"working_udp,omitempty"`
	WorkingICMPv4   *bool              `json:"working_icmp_v4,omitempty"`
	PreferredDERP   int                `json:"preferred_derp,omitempty"`
	HavePortMap     bool               `json:"have_port_map,omitempty"`
	UPnP            *bool              `json:"upnp,omitempty"`
	PMP             *bool              `json:"pmp,omitempty"`
	PCP             *bool              `json:"pcp,omitempty"`
	LinkType        string             `json:"link_type,omitempty"`
	DERPLatency     map[string]float64 `json:"derp_latency,omitempty"`
	FirewallMode    string             `json:"firewall_mode,omitempty"`
}

type filterRuleOut struct {
	SrcIPs   []string          `json:"SrcIPs"`
	DstPorts []netPortRangeOut `json:"DstPorts"`
	IPProto  []int             `json:"IPProto,omitempty"`
}

type netPortRangeOut struct {
	IP    string       `json:"IP"`
	Ports portRangeOut `json:"Ports"`
}

type portRangeOut struct {
	First uint16 `json:"First"`
	Last  uint16 `json:"Last"`
}

func main() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	flag.Parse()
	paths := flag.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: headscale-go-parity <scenario.json> [scenario.json ...]")
		os.Exit(2)
	}
	sort.Strings(paths)

	out := make([]scenarioOutput, 0, len(paths))
	for _, path := range paths {
		result, err := runScenario(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		out = append(out, result)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encoding output: %v\n", err)
		os.Exit(1)
	}
}

func runScenario(path string) (scenarioOutput, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return scenarioOutput{}, fmt.Errorf("read scenario: %w", err)
	}
	var sc scenario
	if err := json.Unmarshal(raw, &sc); err != nil {
		return scenarioOutput{}, fmt.Errorf("parse scenario: %w", err)
	}

	users, userByID := buildUsers(sc.Users)
	nodes, err := buildNodes(sc.Nodes, userByID)
	if err != nil {
		return scenarioOutput{}, err
	}
	pm, err := policy.NewPolicyManager(sc.Policy, users, nodes.ViewSlice())
	if err != nil {
		if sc.ExpectPolicyErr != "" {
			if !strings.Contains(err.Error(), sc.ExpectPolicyErr) {
				return scenarioOutput{}, fmt.Errorf("headscale-go policy error for %s = %q, want substring %q", sc.Name, err.Error(), sc.ExpectPolicyErr)
			}
			return scenarioOutput{
				Engine:      "headscale-go",
				Name:        sc.Name,
				Filter:      []filterRuleOut{},
				PolicyError: sc.ExpectPolicyErr,
			}, nil
		}
		return scenarioOutput{}, fmt.Errorf("headscale-go parsing policy for %s: %w", sc.Name, err)
	}
	if sc.ExpectPolicyErr != "" {
		return scenarioOutput{}, fmt.Errorf("headscale-go policy for %s parsed successfully, want error containing %q", sc.Name, sc.ExpectPolicyErr)
	}
	rules, _ := pm.Filter()
	filterForNodes, err := runFilterNodeChecks(sc.FilterNodeChecks, pm, nodes)
	if err != nil {
		return scenarioOutput{}, err
	}
	peerMaps, err := runPeerMapChecks(sc.PeerMapChecks, pm, nodes)
	if err != nil {
		return scenarioOutput{}, err
	}
	routeApprovals, err := runRouteChecks(sc.RouteChecks, pm, nodes)
	if err != nil {
		return scenarioOutput{}, err
	}
	viaRoutes, err := runViaRouteChecks(sc.ViaRouteChecks, pm, nodes)
	if err != nil {
		return scenarioOutput{}, err
	}
	tagChecks, err := runTagChecks(sc.TagChecks, pm, nodes)
	if err != nil {
		return scenarioOutput{}, err
	}
	nodeAttrs, err := runNodeAttrChecks(sc.NodeAttrChecks, pm, nodes)
	if err != nil {
		return scenarioOutput{}, err
	}
	sshPolicies, err := runSSHChecks(sc.SSHChecks, pm, nodes)
	if err != nil {
		return scenarioOutput{}, err
	}
	wire, err := normalizeWire(sc.Wire)
	if err != nil {
		return scenarioOutput{}, err
	}
	return scenarioOutput{
		Engine:         "headscale-go",
		Name:           sc.Name,
		Filter:         normalizeFilterRules(rules),
		FilterForNodes: filterForNodes,
		PeerMaps:       peerMaps,
		RouteApprovals: routeApprovals,
		ViaRoutes:      viaRoutes,
		TagChecks:      tagChecks,
		NodeAttrs:      nodeAttrs,
		SSHPolicies:    sshPolicies,
		Wire:           wire,
	}, nil
}

func buildUsers(in []scenarioUser) (types.Users, map[uint]*types.User) {
	users := make(types.Users, 0, len(in))
	byID := make(map[uint]*types.User, len(in))
	for _, u := range in {
		user := types.User{
			Model: gorm.Model{
				ID: u.ID,
			},
			Name:  u.Name,
			Email: u.Email,
		}
		users = append(users, user)
		byID[u.ID] = &users[len(users)-1]
	}
	return users, byID
}

func buildNodes(in []scenarioNode, users map[uint]*types.User) (types.Nodes, error) {
	nodes := make(types.Nodes, 0, len(in))
	for _, n := range in {
		var ipPtr *netip.Addr
		if n.IPv4 != "" {
			ip, err := netip.ParseAddr(n.IPv4)
			if err != nil {
				return nil, fmt.Errorf("parse node %d IPv4: %w", n.ID, err)
			}
			ipPtr = &ip
		}
		var ip6Ptr *netip.Addr
		if n.IPv6 != "" {
			ip, err := netip.ParseAddr(n.IPv6)
			if err != nil {
				return nil, fmt.Errorf("parse node %d IPv6: %w", n.ID, err)
			}
			ip6Ptr = &ip
		}
		routes, err := parsePrefixes(n.Routes)
		if err != nil {
			return nil, fmt.Errorf("parse node %d routes: %w", n.ID, err)
		}
		approvedRoutes, err := parsePrefixes(n.ApprovedRoutes)
		if err != nil {
			return nil, fmt.Errorf("parse node %d approved_routes: %w", n.ID, err)
		}
		var hostinfo *tailcfg.Hostinfo
		if len(routes) > 0 {
			hostinfo = &tailcfg.Hostinfo{
				RoutableIPs: routes,
			}
		}
		userID := n.UserID
		node := &types.Node{
			ID:             types.NodeID(n.ID),
			Hostname:       n.Hostname,
			GivenName:      n.Hostname,
			UserID:         &userID,
			User:           users[n.UserID],
			IPv4:           ipPtr,
			IPv6:           ip6Ptr,
			Tags:           n.Tags,
			Hostinfo:       hostinfo,
			ApprovedRoutes: approvedRoutes,
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func normalizeFilterRules(rules []tailcfg.FilterRule) []filterRuleOut {
	out := make([]filterRuleOut, 0, len(rules))
	for _, rule := range rules {
		src := append([]string(nil), rule.SrcIPs...)
		sort.Strings(src)
		dst := make([]netPortRangeOut, 0, len(rule.DstPorts))
		for _, p := range rule.DstPorts {
			dst = append(dst, netPortRangeOut{
				IP: p.IP,
				Ports: portRangeOut{
					First: p.Ports.First,
					Last:  p.Ports.Last,
				},
			})
		}
		sort.Slice(dst, func(i, j int) bool {
			if dst[i].IP != dst[j].IP {
				return dst[i].IP < dst[j].IP
			}
			if dst[i].Ports.First != dst[j].Ports.First {
				return dst[i].Ports.First < dst[j].Ports.First
			}
			return dst[i].Ports.Last < dst[j].Ports.Last
		})
		ipProto := append([]int(nil), rule.IPProto...)
		sort.Ints(ipProto)
		out = append(out, filterRuleOut{
			SrcIPs:   src,
			DstPorts: dst,
			IPProto:  ipProto,
		})
	}
	return out
}

func runFilterNodeChecks(checks []filterNodeCheck, pm policy.PolicyManager, nodes types.Nodes) ([]filterForNodeOut, error) {
	if len(checks) == 0 {
		return nil, nil
	}
	out := make([]filterForNodeOut, 0, len(checks))
	for _, check := range checks {
		node := findNode(nodes, check.NodeID)
		if node == nil {
			return nil, fmt.Errorf("filter node check %q references unknown node %d", check.Name, check.NodeID)
		}
		rules, err := pm.FilterForNode(node.View())
		if err != nil {
			return nil, fmt.Errorf("filter node check %q: %w", check.Name, err)
		}
		out = append(out, filterForNodeOut{
			Name:  check.Name,
			Rules: normalizeFilterRules(rules),
		})
	}
	return out, nil
}

func runPeerMapChecks(checks []peerMapCheck, pm policy.PolicyManager, nodes types.Nodes) ([]peerMapOut, error) {
	if len(checks) == 0 {
		return nil, nil
	}
	peerMap := pm.BuildPeerMap(nodes.ViewSlice())
	out := make([]peerMapOut, 0, len(checks))
	for _, check := range checks {
		if findNode(nodes, check.NodeID) == nil {
			return nil, fmt.Errorf("peer map check %q references unknown node %d", check.Name, check.NodeID)
		}
		peers := peerMap[types.NodeID(check.NodeID)]
		ids := make([]uint64, 0, len(peers))
		for _, peer := range peers {
			ids = append(ids, peer.ID().Uint64())
		}
		sort.Slice(ids, func(i, j int) bool {
			return ids[i] < ids[j]
		})
		out = append(out, peerMapOut{
			Name:  check.Name,
			Peers: ids,
		})
	}
	return out, nil
}

func runRouteChecks(checks []routeCheck, pm policy.PolicyManager, nodes types.Nodes) ([]routeApprovalOut, error) {
	if len(checks) == 0 {
		return nil, nil
	}
	out := make([]routeApprovalOut, 0, len(checks))
	for _, check := range checks {
		node := findNode(nodes, check.NodeID)
		if node == nil {
			return nil, fmt.Errorf("route check %q references unknown node %d", check.Name, check.NodeID)
		}
		current, err := parsePrefixes(check.CurrentApproved)
		if err != nil {
			return nil, fmt.Errorf("route check %q current_approved: %w", check.Name, err)
		}
		announced, err := parsePrefixes(check.AnnouncedRoutes)
		if err != nil {
			return nil, fmt.Errorf("route check %q announced_routes: %w", check.Name, err)
		}
		approved, changed := policy.ApproveRoutesWithPolicy(pm, node.View(), current, announced)
		out = append(out, routeApprovalOut{
			Name:           check.Name,
			ApprovedRoutes: prefixStrings(approved),
			Changed:        changed,
		})
	}
	return out, nil
}

func runViaRouteChecks(checks []viaRouteCheck, pm policy.PolicyManager, nodes types.Nodes) ([]viaRouteOut, error) {
	if len(checks) == 0 {
		return nil, nil
	}
	out := make([]viaRouteOut, 0, len(checks))
	for _, check := range checks {
		viewer := findNode(nodes, check.ViewerID)
		if viewer == nil {
			return nil, fmt.Errorf("via route check %q references unknown viewer node %d", check.Name, check.ViewerID)
		}
		peer := findNode(nodes, check.PeerID)
		if peer == nil {
			return nil, fmt.Errorf("via route check %q references unknown peer node %d", check.Name, check.PeerID)
		}
		result := pm.ViaRoutesForPeer(viewer.View(), peer.View())
		out = append(out, viaRouteOut{
			Name:       check.Name,
			Include:    prefixStrings(result.Include),
			Exclude:    prefixStrings(result.Exclude),
			UsePrimary: prefixStrings(result.UsePrimary),
		})
	}
	return out, nil
}

func runTagChecks(checks []tagCheck, pm policy.PolicyManager, nodes types.Nodes) ([]tagCheckOut, error) {
	if len(checks) == 0 {
		return nil, nil
	}
	out := make([]tagCheckOut, 0, len(checks))
	for _, check := range checks {
		node := findNode(nodes, check.NodeID)
		if node == nil {
			return nil, fmt.Errorf("tag check %q references unknown node %d", check.Name, check.NodeID)
		}
		out = append(out, tagCheckOut{
			Name:    check.Name,
			Allowed: pm.NodeCanHaveTag(node.View(), check.Tag),
		})
	}
	return out, nil
}

func runNodeAttrChecks(checks []nodeAttrCheck, pm policy.PolicyManager, nodes types.Nodes) ([]nodeAttrOut, error) {
	if len(checks) == 0 {
		return nil, nil
	}
	out := make([]nodeAttrOut, 0, len(checks))
	for _, check := range checks {
		if findNode(nodes, check.NodeID) == nil {
			return nil, fmt.Errorf("node attr check %q references unknown node %d", check.Name, check.NodeID)
		}
		capMap := pm.NodeCapMap(types.NodeID(check.NodeID))
		attrs := make([]string, 0, len(capMap))
		for attr := range capMap {
			attrs = append(attrs, string(attr))
		}
		sort.Strings(attrs)
		out = append(out, nodeAttrOut{
			Name:  check.Name,
			Attrs: attrs,
		})
	}
	return out, nil
}

func runSSHChecks(checks []sshCheck, pm policy.PolicyManager, nodes types.Nodes) ([]sshPolicyOut, error) {
	if len(checks) == 0 {
		return nil, nil
	}
	out := make([]sshPolicyOut, 0, len(checks))
	for _, check := range checks {
		node := findNode(nodes, check.NodeID)
		if node == nil {
			return nil, fmt.Errorf("ssh check %q references unknown node %d", check.Name, check.NodeID)
		}
		sshPolicy, err := pm.SSHPolicy("https://control.example", node.View())
		if err != nil {
			return nil, fmt.Errorf("ssh check %q: %w", check.Name, err)
		}
		out = append(out, sshPolicyOut{
			Name:  check.Name,
			Rules: normalizeSSHPolicy(sshPolicy),
		})
	}
	return out, nil
}

func normalizeSSHPolicy(policy *tailcfg.SSHPolicy) []sshRuleOut {
	if policy == nil {
		return []sshRuleOut{}
	}
	out := make([]sshRuleOut, 0, len(policy.Rules))
	for _, rule := range policy.Rules {
		if rule == nil {
			continue
		}
		principals := make([]string, 0, len(rule.Principals))
		for _, principal := range rule.Principals {
			if principal == nil || principal.NodeIP == "" {
				continue
			}
			principals = append(principals, principal.NodeIP)
		}
		sort.Strings(principals)

		action := sshActionOut{}
		if rule.Action != nil {
			action = sshActionOut{
				Accept:                    rule.Action.Accept,
				Reject:                    rule.Action.Reject,
				SessionDurationNanos:      int64(rule.Action.SessionDuration),
				HoldAndDelegate:           rule.Action.HoldAndDelegate,
				AllowAgentForwarding:      rule.Action.AllowAgentForwarding,
				AllowLocalPortForwarding:  rule.Action.AllowLocalPortForwarding,
				AllowRemotePortForwarding: rule.Action.AllowRemotePortForwarding,
			}
		}

		out = append(out, sshRuleOut{
			Principals: principals,
			SSHUsers:   rule.SSHUsers,
			Action:     action,
			AcceptEnv:  rule.AcceptEnv,
		})
	}
	return out
}

func findNode(nodes types.Nodes, id uint64) *types.Node {
	for _, node := range nodes {
		if uint64(node.ID) == id {
			return node
		}
	}
	return nil
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, raw := range in {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", raw, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}

func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	sort.Strings(out)
	return out
}

func normalizeWire(in *wireScenario) (*wireOutput, error) {
	if in == nil {
		return nil, nil
	}
	out := &wireOutput{}
	if len(in.DNSConfig) > 0 {
		var v tailcfg.DNSConfig
		if err := json.Unmarshal(in.DNSConfig, &v); err != nil {
			return nil, fmt.Errorf("wire dns_config: %w", err)
		}
		raw, err := marshalRaw(v)
		if err != nil {
			return nil, fmt.Errorf("wire dns_config marshal: %w", err)
		}
		out.DNSConfig = raw
	}
	if len(in.RuntimeDNSConfig) > 0 {
		raw, err := normalizeRuntimeDNSConfig(in.RuntimeDNSConfig)
		if err != nil {
			return nil, err
		}
		out.RuntimeDNSConfig = raw
	}
	if len(in.DERPMap) > 0 {
		var v tailcfg.DERPMap
		if err := json.Unmarshal(in.DERPMap, &v); err != nil {
			return nil, fmt.Errorf("wire derp_map: %w", err)
		}
		raw, err := marshalRaw(v)
		if err != nil {
			return nil, fmt.Errorf("wire derp_map marshal: %w", err)
		}
		out.DERPMap = raw
	}
	if len(in.RegisterRequest) > 0 {
		var v tailcfg.RegisterRequest
		if err := json.Unmarshal(in.RegisterRequest, &v); err != nil {
			return nil, fmt.Errorf("wire register_request: %w", err)
		}
		out.RegisterRequest = summarizeRegisterRequest(&v)
	}
	if len(in.RegisterResponse) > 0 {
		var v tailcfg.RegisterResponse
		if err := json.Unmarshal(in.RegisterResponse, &v); err != nil {
			return nil, fmt.Errorf("wire register_response: %w", err)
		}
		out.RegisterResponse = summarizeRegisterResponse(&v)
	}
	if len(in.MapRequest) > 0 {
		var v tailcfg.MapRequest
		if err := json.Unmarshal(in.MapRequest, &v); err != nil {
			return nil, fmt.Errorf("wire map_request: %w", err)
		}
		out.MapRequest = summarizeMapRequest(&v)
	}
	if len(in.MapResponse) > 0 {
		var v tailcfg.MapResponse
		if err := json.Unmarshal(in.MapResponse, &v); err != nil {
			return nil, fmt.Errorf("wire map_response: %w", err)
		}
		summary, err := summarizeMapResponse(&v)
		if err != nil {
			return nil, err
		}
		out.MapResponse = summary
	}
	return out, nil
}

func normalizeRuntimeDNSConfig(raw json.RawMessage) (json.RawMessage, error) {
	var dnsConfig map[string]any
	if err := json.Unmarshal(raw, &dnsConfig); err != nil {
		return nil, fmt.Errorf("wire runtime_dns_config: %w", err)
	}

	config := map[string]any{
		"server_url": "https://derp.no",
		"noise": map[string]any{
			"private_key_path": "private_key.pem",
		},
		"prefixes": map[string]any{
			"v4":         "100.64.0.0/10",
			"v6":         "fd7a:115c:a1e0::/48",
			"allocation": "sequential",
		},
		"database": map[string]any{
			"type": "sqlite3",
		},
		"dns": dnsConfig,
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("wire runtime_dns_config config marshal: %w", err)
	}

	tmp, err := os.CreateTemp("", "headscale-parity-dns-*.json")
	if err != nil {
		return nil, fmt.Errorf("wire runtime_dns_config temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(configJSON); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("wire runtime_dns_config temp write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("wire runtime_dns_config temp close: %w", err)
	}

	viper.Reset()
	defer viper.Reset()
	if err := types.LoadConfig(tmp.Name(), true); err != nil {
		return nil, fmt.Errorf("wire runtime_dns_config load config: %w", err)
	}
	cfg, err := types.LoadServerConfig()
	if err != nil {
		return nil, fmt.Errorf("wire runtime_dns_config server config: %w", err)
	}
	return marshalRaw(cfg.TailcfgDNSConfig)
}

func marshalRaw(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if string(raw) == "null" {
		return nil, nil
	}
	return raw, nil
}

func summarizeRegisterRequest(req *tailcfg.RegisterRequest) *registerRequestSummary {
	out := &registerRequestSummary{
		Version:          int(req.Version),
		NodeKey:          req.NodeKey.String(),
		Followup:         req.Followup,
		Tailnet:          req.Tailnet,
		Ephemeral:        req.Ephemeral,
		RequestedExpiry:  !req.Expiry.IsZero(),
		NodeKeySignature: base64.StdEncoding.EncodeToString(req.NodeKeySignature),
		Timestamp:        req.Timestamp != nil,
		DeviceCert:       base64.StdEncoding.EncodeToString(req.DeviceCert),
		Signature:        base64.StdEncoding.EncodeToString(req.Signature),
	}
	if req.SignatureType != tailcfg.SignatureNone {
		out.SignatureType = req.SignatureType.String()
	}
	if !req.OldNodeKey.IsZero() {
		out.OldNodeKey = req.OldNodeKey.String()
	}
	if !req.NLKey.IsZero() {
		nlKey, err := req.NLKey.MarshalText()
		if err == nil {
			out.NLKey = string(nlKey)
		}
	}
	if req.Auth != nil {
		out.AuthKey = req.Auth.AuthKey
	}
	if req.Hostinfo != nil {
		out.Hostinfo = summarizeHostInfo(req.Hostinfo.View())
	}
	return out
}

func summarizeRegisterResponse(resp *tailcfg.RegisterResponse) *registerResponseSummary {
	var userCreated string
	if !resp.User.Created.IsZero() {
		userCreated = resp.User.Created.UTC().Format(time.RFC3339Nano)
	}
	return &registerResponseSummary{
		User: userSummary{
			ID:            uint64(resp.User.ID),
			DisplayName:   resp.User.DisplayName,
			ProfilePicURL: resp.User.ProfilePicURL,
			Created:       userCreated,
		},
		Login: loginSummary{
			ID:            uint64(resp.Login.ID),
			Provider:      resp.Login.Provider,
			LoginName:     resp.Login.LoginName,
			DisplayName:   resp.Login.DisplayName,
			ProfilePicURL: resp.Login.ProfilePicURL,
		},
		NodeKeyExpired:    resp.NodeKeyExpired,
		AuthURL:           resp.AuthURL,
		MachineAuthorized: resp.MachineAuthorized,
		NodeKeySignature:  base64.StdEncoding.EncodeToString(resp.NodeKeySignature),
		Error:             resp.Error,
	}
}

func summarizeMapRequest(req *tailcfg.MapRequest) *mapRequestSummary {
	endpointTypes := make([]int, 0, len(req.EndpointTypes))
	for _, endpointType := range req.EndpointTypes {
		endpointTypes = append(endpointTypes, int(endpointType))
	}
	out := &mapRequestSummary{
		Version:                                  int(req.Version),
		Stream:                                   req.Stream,
		KeepAlive:                                req.KeepAlive,
		Compress:                                 req.Compress,
		OmitPeers:                                req.OmitPeers,
		MapSessionHandle:                         req.MapSessionHandle,
		MapSessionSeq:                            req.MapSessionSeq,
		HardwareAttestationKeySignature:          base64.StdEncoding.EncodeToString(req.HardwareAttestationKeySignature),
		HardwareAttestationKeySignatureTimestamp: !req.HardwareAttestationKeySignatureTimestamp.IsZero(),
		Endpoints:                                addrPortStrings(req.Endpoints),
		EndpointTypes:                            endpointTypes,
		ReadOnly:                                 req.ReadOnly,
		TKAHead:                                  req.TKAHead,
		DebugFlags:                               append([]string(nil), req.DebugFlags...),
		ConnectionHandleForTest:                  req.ConnectionHandleForTest,
	}
	if !req.NodeKey.IsZero() {
		out.NodeKey = req.NodeKey.String()
	}
	if !req.DiscoKey.IsZero() {
		out.DiscoKey = req.DiscoKey.String()
	}
	if !req.HardwareAttestationKey.IsZero() {
		out.HardwareAttestationKey = req.HardwareAttestationKey.String()
	}
	sort.Strings(out.DebugFlags)
	if req.Hostinfo != nil {
		out.Hostinfo = summarizeHostInfo(req.Hostinfo.View())
	}
	return out
}

func summarizeMapResponse(resp *tailcfg.MapResponse) (*mapResponseSummary, error) {
	out := &mapResponseSummary{
		MapSessionHandle:          resp.MapSessionHandle,
		Seq:                       resp.Seq,
		KeepAlive:                 resp.KeepAlive,
		PopBrowserURL:             resp.PopBrowserURL,
		Domain:                    resp.Domain,
		CollectServices:           optBoolPtr(resp.CollectServices),
		PeerCount:                 len(resp.Peers),
		PacketFilter:              normalizeFilterRules(resp.PacketFilter),
		Health:                    stringSlicePtr(resp.Health),
		SSHPolicy:                 normalizeSSHPolicy(resp.SSHPolicy),
		DomainDataPlaneAuditLogID: resp.DomainDataPlaneAuditLogID,
		DefaultAutoUpdate:         optBoolPtr(resp.DeprecatedDefaultAutoUpdate),
	}
	var err error
	if resp.PingRequest != nil {
		out.PingRequest, err = marshalRaw(resp.PingRequest)
		if err != nil {
			return nil, fmt.Errorf("wire map_response ping_request marshal: %w", err)
		}
	}
	if resp.Node != nil {
		out.Node = summarizeMapNode(resp.Node)
	}
	if len(resp.Peers) > 0 {
		out.Peers = make([]mapNodeSummary, 0, len(resp.Peers))
		for _, peer := range resp.Peers {
			out.Peers = append(out.Peers, *summarizeMapNode(peer))
		}
		sort.Slice(out.Peers, func(i, j int) bool {
			return out.Peers[i].ID < out.Peers[j].ID
		})
	}
	if len(resp.PeersChanged) > 0 {
		out.PeersChanged = make([]mapNodeSummary, 0, len(resp.PeersChanged))
		for _, peer := range resp.PeersChanged {
			out.PeersChanged = append(out.PeersChanged, *summarizeMapNode(peer))
		}
		sort.Slice(out.PeersChanged, func(i, j int) bool {
			return out.PeersChanged[i].ID < out.PeersChanged[j].ID
		})
	}
	if len(resp.PeersRemoved) > 0 {
		out.PeersRemoved = make([]uint64, 0, len(resp.PeersRemoved))
		for _, id := range resp.PeersRemoved {
			out.PeersRemoved = append(out.PeersRemoved, uint64(id))
		}
		sort.Slice(out.PeersRemoved, func(i, j int) bool {
			return out.PeersRemoved[i] < out.PeersRemoved[j]
		})
	}
	if len(resp.PeersChangedPatch) > 0 {
		out.PeersChangedPatch, err = marshalRaw(resp.PeersChangedPatch)
		if err != nil {
			return nil, fmt.Errorf("wire map_response peers_changed_patch marshal: %w", err)
		}
	}
	if len(resp.PeerSeenChange) > 0 {
		out.PeerSeenChange, err = marshalRaw(resp.PeerSeenChange)
		if err != nil {
			return nil, fmt.Errorf("wire map_response peer_seen_change marshal: %w", err)
		}
	}
	if len(resp.OnlineChange) > 0 {
		out.OnlineChange, err = marshalRaw(resp.OnlineChange)
		if err != nil {
			return nil, fmt.Errorf("wire map_response online_change marshal: %w", err)
		}
	}
	if len(resp.UserProfiles) > 0 {
		out.UserProfiles = make([]userProfileSummary, 0, len(resp.UserProfiles))
		for _, profile := range resp.UserProfiles {
			out.UserProfiles = append(out.UserProfiles, userProfileSummary{
				ID:            uint64(profile.ID),
				LoginName:     profile.LoginName,
				DisplayName:   profile.DisplayName,
				ProfilePicURL: profile.ProfilePicURL,
			})
		}
		sort.Slice(out.UserProfiles, func(i, j int) bool {
			return out.UserProfiles[i].ID < out.UserProfiles[j].ID
		})
	}
	if len(resp.PacketFilters) > 0 {
		out.PacketFilters, err = marshalRaw(resp.PacketFilters)
		if err != nil {
			return nil, fmt.Errorf("wire map_response packet_filters marshal: %w", err)
		}
	}
	if len(resp.DisplayMessages) > 0 {
		out.DisplayMessages, err = marshalRaw(resp.DisplayMessages)
		if err != nil {
			return nil, fmt.Errorf("wire map_response display_messages marshal: %w", err)
		}
	}
	if resp.DNSConfig != nil {
		raw, err := marshalRaw(resp.DNSConfig)
		if err != nil {
			return nil, fmt.Errorf("wire map_response dns_config marshal: %w", err)
		}
		out.DNSConfig = raw
	}
	if resp.DERPMap != nil {
		raw, err := marshalRaw(resp.DERPMap)
		if err != nil {
			return nil, fmt.Errorf("wire map_response derp_map marshal: %w", err)
		}
		out.DERPMap = raw
	}
	if resp.ControlTime != nil {
		out.ControlTime, err = marshalRaw(resp.ControlTime)
		if err != nil {
			return nil, fmt.Errorf("wire map_response control_time marshal: %w", err)
		}
	}
	if resp.TKAInfo != nil {
		out.TKAInfo, err = marshalRaw(resp.TKAInfo)
		if err != nil {
			return nil, fmt.Errorf("wire map_response tka_info marshal: %w", err)
		}
	}
	if resp.Debug != nil {
		out.Debug, err = marshalRaw(resp.Debug)
		if err != nil {
			return nil, fmt.Errorf("wire map_response debug marshal: %w", err)
		}
	}
	if resp.ControlDialPlan != nil {
		out.ControlDialPlan, err = marshalRaw(resp.ControlDialPlan)
		if err != nil {
			return nil, fmt.Errorf("wire map_response control_dial_plan marshal: %w", err)
		}
	}
	if resp.ClientVersion != nil {
		out.ClientVersion, err = marshalRaw(resp.ClientVersion)
		if err != nil {
			return nil, fmt.Errorf("wire map_response client_version marshal: %w", err)
		}
	}
	return out, nil
}

func summarizeMapNode(node *tailcfg.Node) *mapNodeSummary {
	var online *bool
	if node.Online != nil {
		v := *node.Online
		online = &v
	}
	var capMap json.RawMessage
	if len(node.CapMap) > 0 {
		capMap, _ = marshalRaw(node.CapMap)
	}
	var exitNodeDNSResolvers json.RawMessage
	if len(node.ExitNodeDNSResolvers) > 0 {
		exitNodeDNSResolvers, _ = marshalRaw(node.ExitNodeDNSResolvers)
	}
	var selfNodeV4MasqAddrForThisPeer string
	if node.SelfNodeV4MasqAddrForThisPeer != nil {
		selfNodeV4MasqAddrForThisPeer = node.SelfNodeV4MasqAddrForThisPeer.String()
	}
	var selfNodeV6MasqAddrForThisPeer string
	if node.SelfNodeV6MasqAddrForThisPeer != nil {
		selfNodeV6MasqAddrForThisPeer = node.SelfNodeV6MasqAddrForThisPeer.String()
	}
	var created string
	if !node.Created.IsZero() {
		created = node.Created.UTC().Format(time.RFC3339Nano)
	}
	var keyExpiry string
	if !node.KeyExpiry.IsZero() {
		keyExpiry = node.KeyExpiry.UTC().Format(time.RFC3339Nano)
	}
	var lastSeen string
	if node.LastSeen != nil {
		lastSeen = node.LastSeen.UTC().Format(time.RFC3339Nano)
	}
	capabilities := make([]string, 0, len(node.Capabilities))
	for _, capability := range node.Capabilities {
		capabilities = append(capabilities, string(capability))
	}
	sort.Strings(capabilities)
	tags := append([]string(nil), node.Tags...)
	sort.Strings(tags)
	return &mapNodeSummary{
		ID:                            uint64(node.ID),
		StableID:                      string(node.StableID),
		Name:                          node.Name,
		User:                          uint64(node.User),
		Sharer:                        uint64(node.Sharer),
		Key:                           node.Key.String(),
		KeySignature:                  base64.StdEncoding.EncodeToString(node.KeySignature),
		Machine:                       node.Machine.String(),
		DiscoKey:                      node.DiscoKey.String(),
		Addresses:                     prefixStrings(node.Addresses),
		AllowedIPs:                    prefixStrings(node.AllowedIPs),
		PrimaryRoutes:                 prefixStrings(node.PrimaryRoutes),
		Endpoints:                     addrPortStrings(node.Endpoints),
		LegacyDERPString:              node.LegacyDERPString,
		Hostinfo:                      summarizeHostInfo(node.Hostinfo),
		Tags:                          tags,
		Created:                       created,
		KeyExpiry:                     keyExpiry,
		LastSeen:                      lastSeen,
		Online:                        online,
		MachineAuthorized:             node.MachineAuthorized,
		Cap:                           int(node.Cap),
		Capabilities:                  capabilities,
		CapMap:                        capMap,
		Expired:                       node.Expired,
		HomeDERP:                      node.HomeDERP,
		UnsignedPeerAPIOnly:           node.UnsignedPeerAPIOnly,
		ComputedName:                  node.ComputedName,
		ComputedNameWithHost:          node.ComputedNameWithHost,
		DataPlaneAuditLogID:           node.DataPlaneAuditLogID,
		SelfNodeV4MasqAddrForThisPeer: selfNodeV4MasqAddrForThisPeer,
		SelfNodeV6MasqAddrForThisPeer: selfNodeV6MasqAddrForThisPeer,
		IsWireGuardOnly:               node.IsWireGuardOnly,
		IsJailed:                      node.IsJailed,
		ExitNodeDNSResolvers:          exitNodeDNSResolvers,
	}
}

func optBoolPtr(v interface{ Get() (bool, bool) }) *bool {
	if b, ok := v.Get(); ok {
		out := b
		return &out
	}
	return nil
}

func stringSlicePtr(in []string) *[]string {
	if in == nil {
		return nil
	}
	out := append([]string(nil), in...)
	return &out
}

func summarizeServices(in []tailcfg.Service) []serviceSummary {
	out := make([]serviceSummary, 0, len(in))
	for _, service := range in {
		out = append(out, serviceSummary{
			Proto:       string(service.Proto),
			Port:        service.Port,
			Description: service.Description,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Description < out[j].Description
	})
	return out
}

func summarizeLocation(location *tailcfg.Location) *locationSummary {
	if location == nil {
		return nil
	}
	return &locationSummary{
		Country:     location.Country,
		CountryCode: location.CountryCode,
		City:        location.City,
		CityCode:    location.CityCode,
		Latitude:    location.Latitude,
		Longitude:   location.Longitude,
		Priority:    location.Priority,
	}
}

func summarizeTPM(tpm tailcfg.TPMInfo, ok bool) *tpmInfoSummary {
	if !ok {
		return nil
	}
	return &tpmInfoSummary{
		Manufacturer:    tpm.Manufacturer,
		Vendor:          tpm.Vendor,
		Model:           tpm.Model,
		FirmwareVersion: tpm.FirmwareVersion,
		SpecRevision:    tpm.SpecRevision,
		FamilyIndicator: tpm.FamilyIndicator,
	}
}

func summarizeHostInfo(hostinfo tailcfg.HostinfoView) *hostInfoSummary {
	if !hostinfo.Valid() {
		return nil
	}
	var preferredDERP int
	var havePortMap bool
	var linkType string
	var firewallMode string
	var mappingVaries *bool
	var workingIPv6 *bool
	var osHasIPv6 *bool
	var workingUDP *bool
	var workingICMPv4 *bool
	var upnp *bool
	var pmp *bool
	var pcp *bool
	var derpLatency map[string]float64
	if netInfo := hostinfo.NetInfo(); netInfo.Valid() {
		preferredDERP = netInfo.PreferredDERP()
		havePortMap = netInfo.HavePortMap()
		linkType = netInfo.LinkType()
		firewallMode = netInfo.FirewallMode()
		mappingVaries = optBoolPtr(netInfo.MappingVariesByDestIP())
		workingIPv6 = optBoolPtr(netInfo.WorkingIPv6())
		osHasIPv6 = optBoolPtr(netInfo.OSHasIPv6())
		workingUDP = optBoolPtr(netInfo.WorkingUDP())
		workingICMPv4 = optBoolPtr(netInfo.WorkingICMPv4())
		upnp = optBoolPtr(netInfo.UPnP())
		pmp = optBoolPtr(netInfo.PMP())
		pcp = optBoolPtr(netInfo.PCP())
		derpLatency = netInfo.DERPLatency().AsMap()
	}
	tpm, tpmOK := hostinfo.TPM().GetOk()
	return &hostInfoSummary{
		IPNVersion:      hostinfo.IPNVersion(),
		FrontendLogID:   hostinfo.FrontendLogID(),
		BackendLogID:    hostinfo.BackendLogID(),
		Hostname:        hostinfo.Hostname(),
		OS:              hostinfo.OS(),
		OSVersion:       hostinfo.OSVersion(),
		Container:       optBoolPtr(hostinfo.Container()),
		Env:             hostinfo.Env(),
		Distro:          hostinfo.Distro(),
		DistroVersion:   hostinfo.DistroVersion(),
		DistroCodeName:  hostinfo.DistroCodeName(),
		App:             hostinfo.App(),
		Desktop:         optBoolPtr(hostinfo.Desktop()),
		Package:         hostinfo.Package(),
		DeviceModel:     hostinfo.DeviceModel(),
		PushDeviceToken: hostinfo.PushDeviceToken(),
		ShieldsUp:       hostinfo.ShieldsUp(),
		ShareeNode:      hostinfo.ShareeNode(),
		NoLogsNoSupport: hostinfo.NoLogsNoSupport(),
		WireIngress:     hostinfo.WireIngress(),
		IngressEnabled:  hostinfo.IngressEnabled(),
		AllowsUpdate:    hostinfo.AllowsUpdate(),
		Machine:         hostinfo.Machine(),
		GoArch:          hostinfo.GoArch(),
		GoArchVar:       hostinfo.GoArchVar(),
		GoVersion:       hostinfo.GoVersion(),
		RoutableIPs:     prefixStrings(hostinfo.RoutableIPs().AsSlice()),
		RequestTags:     hostinfo.RequestTags().AsSlice(),
		WoLMACs:         hostinfo.WoLMACs().AsSlice(),
		Services:        summarizeServices(hostinfo.Services().AsSlice()),
		SSHHostKeys:     hostinfo.SSH_HostKeys().AsSlice(),
		Cloud:           hostinfo.Cloud(),
		Userspace:       optBoolPtr(hostinfo.Userspace()),
		UserspaceRouter: optBoolPtr(hostinfo.UserspaceRouter()),
		AppConnector:    optBoolPtr(hostinfo.AppConnector()),
		ServicesHash:    hostinfo.ServicesHash(),
		ExitNodeID:      string(hostinfo.ExitNodeID()),
		Location:        summarizeLocation(hostinfo.Location().AsStruct()),
		TPM:             summarizeTPM(tpm, tpmOK),
		StateEncrypted:  optBoolPtr(hostinfo.StateEncrypted()),
		MappingVaries:   mappingVaries,
		WorkingIPv6:     workingIPv6,
		OSHasIPv6:       osHasIPv6,
		WorkingUDP:      workingUDP,
		WorkingICMPv4:   workingICMPv4,
		PreferredDERP:   preferredDERP,
		HavePortMap:     havePortMap,
		UPnP:            upnp,
		PMP:             pmp,
		PCP:             pcp,
		LinkType:        linkType,
		DERPLatency:     derpLatency,
		FirewallMode:    firewallMode,
	}
}

func addrPortStrings(in []netip.AddrPort) []string {
	out := make([]string, 0, len(in))
	for _, addr := range in {
		out = append(out, addr.String())
	}
	sort.Strings(out)
	return out
}
