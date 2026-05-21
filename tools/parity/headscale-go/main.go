package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

type scenario struct {
	Name        string          `json:"name"`
	Policy      json.RawMessage `json:"policy"`
	Users       []scenarioUser  `json:"users,omitempty"`
	Nodes       []scenarioNode  `json:"nodes,omitempty"`
	RouteChecks []routeCheck    `json:"route_checks,omitempty"`
	Wire        *wireScenario   `json:"wire,omitempty"`
}

type scenarioUser struct {
	ID    uint   `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

type scenarioNode struct {
	ID       uint64   `json:"id"`
	UserID   uint     `json:"user_id"`
	Hostname string   `json:"hostname"`
	IPv4     string   `json:"ipv4"`
	Tags     []string `json:"tags,omitempty"`
}

type scenarioOutput struct {
	Engine         string             `json:"engine"`
	Name           string             `json:"name"`
	Filter         []filterRuleOut    `json:"filter"`
	RouteApprovals []routeApprovalOut `json:"route_approvals,omitempty"`
	Wire           *wireOutput        `json:"wire,omitempty"`
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

type wireScenario struct {
	DNSConfig        json.RawMessage `json:"dns_config,omitempty"`
	DERPMap          json.RawMessage `json:"derp_map,omitempty"`
	RegisterRequest  json.RawMessage `json:"register_request,omitempty"`
	RegisterResponse json.RawMessage `json:"register_response,omitempty"`
	MapResponse      json.RawMessage `json:"map_response,omitempty"`
}

type wireOutput struct {
	DNSConfig        json.RawMessage          `json:"dns_config,omitempty"`
	DERPMap          json.RawMessage          `json:"derp_map,omitempty"`
	RegisterRequest  *registerRequestSummary  `json:"register_request,omitempty"`
	RegisterResponse *registerResponseSummary `json:"register_response,omitempty"`
	MapResponse      *mapResponseSummary      `json:"map_response,omitempty"`
}

type registerRequestSummary struct {
	NodeKey         string           `json:"node_key"`
	AuthKey         string           `json:"auth_key,omitempty"`
	Hostinfo        *hostInfoSummary `json:"hostinfo,omitempty"`
	Followup        string           `json:"followup,omitempty"`
	Ephemeral       bool             `json:"ephemeral,omitempty"`
	RequestedExpiry bool             `json:"requested_expiry,omitempty"`
}

type registerResponseSummary struct {
	User              userSummary  `json:"user"`
	Login             loginSummary `json:"login"`
	NodeKeyExpired    bool         `json:"node_key_expired"`
	AuthURL           string       `json:"auth_url"`
	MachineAuthorized bool         `json:"machine_authorized"`
	Error             string       `json:"error,omitempty"`
}

type userSummary struct {
	ID          uint64 `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
}

type loginSummary struct {
	ID          uint64 `json:"id"`
	Provider    string `json:"provider,omitempty"`
	LoginName   string `json:"login_name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type mapResponseSummary struct {
	KeepAlive    bool            `json:"keep_alive"`
	Domain       string          `json:"domain,omitempty"`
	Node         *mapNodeSummary `json:"node,omitempty"`
	PeerCount    int             `json:"peer_count"`
	PacketFilter []filterRuleOut `json:"packet_filter,omitempty"`
	DNSConfig    json.RawMessage `json:"dns_config,omitempty"`
	DERPMap      json.RawMessage `json:"derp_map,omitempty"`
}

type mapNodeSummary struct {
	ID                uint64           `json:"id"`
	StableID          string           `json:"stable_id,omitempty"`
	Name              string           `json:"name,omitempty"`
	User              uint64           `json:"user"`
	Key               string           `json:"key,omitempty"`
	Machine           string           `json:"machine,omitempty"`
	DiscoKey          string           `json:"disco_key,omitempty"`
	Addresses         []string         `json:"addresses,omitempty"`
	AllowedIPs        []string         `json:"allowed_ips,omitempty"`
	Endpoints         []string         `json:"endpoints,omitempty"`
	Hostinfo          *hostInfoSummary `json:"hostinfo,omitempty"`
	MachineAuthorized bool             `json:"machine_authorized,omitempty"`
}

type hostInfoSummary struct {
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
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
		return scenarioOutput{}, fmt.Errorf("headscale-go parsing policy for %s: %w", sc.Name, err)
	}
	rules, _ := pm.Filter()
	routeApprovals, err := runRouteChecks(sc.RouteChecks, pm, nodes)
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
		RouteApprovals: routeApprovals,
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
		userID := n.UserID
		node := &types.Node{
			ID:        types.NodeID(n.ID),
			Hostname:  n.Hostname,
			GivenName: n.Hostname,
			UserID:    &userID,
			User:      users[n.UserID],
			IPv4:      ipPtr,
			Tags:      n.Tags,
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func normalizeFilterRules(rules []tailcfg.FilterRule) []filterRuleOut {
	out := make([]filterRuleOut, 0, len(rules))
	for _, rule := range rules {
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
		out = append(out, filterRuleOut{
			SrcIPs:   append([]string(nil), rule.SrcIPs...),
			DstPorts: dst,
			IPProto:  append([]int(nil), rule.IPProto...),
		})
	}
	return out
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
		NodeKey:         req.NodeKey.String(),
		Followup:        req.Followup,
		Ephemeral:       req.Ephemeral,
		RequestedExpiry: !req.Expiry.IsZero(),
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
	return &registerResponseSummary{
		User: userSummary{
			ID:          uint64(resp.User.ID),
			DisplayName: resp.User.DisplayName,
		},
		Login: loginSummary{
			ID:          uint64(resp.Login.ID),
			Provider:    resp.Login.Provider,
			LoginName:   resp.Login.LoginName,
			DisplayName: resp.Login.DisplayName,
		},
		NodeKeyExpired:    resp.NodeKeyExpired,
		AuthURL:           resp.AuthURL,
		MachineAuthorized: resp.MachineAuthorized,
		Error:             resp.Error,
	}
}

func summarizeMapResponse(resp *tailcfg.MapResponse) (*mapResponseSummary, error) {
	out := &mapResponseSummary{
		KeepAlive:    resp.KeepAlive,
		Domain:       resp.Domain,
		PeerCount:    len(resp.Peers),
		PacketFilter: normalizeFilterRules(resp.PacketFilter),
	}
	if resp.Node != nil {
		out.Node = summarizeMapNode(resp.Node)
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
	return out, nil
}

func summarizeMapNode(node *tailcfg.Node) *mapNodeSummary {
	return &mapNodeSummary{
		ID:                uint64(node.ID),
		StableID:          string(node.StableID),
		Name:              node.Name,
		User:              uint64(node.User),
		Key:               node.Key.String(),
		Machine:           node.Machine.String(),
		DiscoKey:          node.DiscoKey.String(),
		Addresses:         prefixStrings(node.Addresses),
		AllowedIPs:        prefixStrings(node.AllowedIPs),
		Endpoints:         addrPortStrings(node.Endpoints),
		Hostinfo:          summarizeHostInfo(node.Hostinfo),
		MachineAuthorized: node.MachineAuthorized,
	}
}

func summarizeHostInfo(hostinfo tailcfg.HostinfoView) *hostInfoSummary {
	if !hostinfo.Valid() {
		return nil
	}
	return &hostInfoSummary{
		Hostname:  hostinfo.Hostname(),
		OS:        hostinfo.OS(),
		OSVersion: hostinfo.OSVersion(),
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
