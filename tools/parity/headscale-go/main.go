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
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

type scenario struct {
	Name   string          `json:"name"`
	Policy json.RawMessage `json:"policy"`
	Users  []scenarioUser  `json:"users,omitempty"`
	Nodes  []scenarioNode  `json:"nodes,omitempty"`
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
	Engine string          `json:"engine"`
	Name   string          `json:"name"`
	Filter []filterRuleOut `json:"filter"`
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
	return scenarioOutput{
		Engine: "headscale-go",
		Name:   sc.Name,
		Filter: normalizeFilterRules(rules),
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
