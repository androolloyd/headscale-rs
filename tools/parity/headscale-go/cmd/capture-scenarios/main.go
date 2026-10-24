// capture-scenarios converts the pinned upstream Tailscale compatibility
// captures into the JSON input shared by the Go and Rust parity harnesses.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tailscale/hujson"
)

var categories = []string{
	"acl_results",
	"grant_results",
	"nodeattrs_results",
	"routes_results",
	"ssh_results",
	"policytest_results",
	"sshtest_results",
}

type capture struct {
	TestID string `json:"test_id"`
	Input  struct {
		FullPolicy      json.RawMessage `json:"full_policy"`
		APIResponseCode int             `json:"api_response_code"`
	} `json:"input"`
	Topology struct {
		Users []struct {
			ID    uint64 `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"users"`
		Nodes map[string]struct {
			User           string   `json:"user"`
			IPv4           string   `json:"ipv4"`
			IPv6           string   `json:"ipv6"`
			Tags           []string `json:"tags"`
			RoutableIPs    []string `json:"routable_ips"`
			ApprovedRoutes []string `json:"approved_routes"`
		} `json:"nodes"`
	} `json:"topology"`
}

type user struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

type node struct {
	ID             uint64   `json:"id"`
	UserID         uint64   `json:"user_id"`
	Hostname       string   `json:"hostname"`
	IPv4           string   `json:"ipv4"`
	IPv6           string   `json:"ipv6,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Routes         []string `json:"routes,omitempty"`
	ApprovedRoutes []string `json:"approved_routes,omitempty"`
}

type namedNodeCheck struct {
	Name   string `json:"name"`
	NodeID uint64 `json:"node_id"`
}

type scenario struct {
	Name              string           `json:"name"`
	SourceCapture     string           `json:"source_capture"`
	SourceSHA256      string           `json:"source_sha256"`
	SourceAPICode     int              `json:"source_api_response_code"`
	AuditTestVerdicts bool             `json:"audit_test_verdicts"`
	Policy            json.RawMessage  `json:"policy"`
	Users             []user           `json:"users"`
	Nodes             []node           `json:"nodes"`
	FilterNodeChecks  []namedNodeCheck `json:"filter_node_checks"`
	NodeAttrChecks    []namedNodeCheck `json:"node_attr_checks,omitempty"`
	SSHChecks         []namedNodeCheck `json:"ssh_checks,omitempty"`
}

type manifestEntry struct {
	Source  string `json:"source"`
	SHA256  string `json:"sha256"`
	TestID  string `json:"test_id,omitempty"`
	APICode int    `json:"source_api_response_code"`
	Output  string `json:"output,omitempty"`
	Skip    string `json:"skip,omitempty"`
}

type manifest struct {
	UpstreamVersion string          `json:"upstream_version"`
	Total           int             `json:"total"`
	Converted       int             `json:"converted"`
	Skipped         int             `json:"skipped"`
	Entries         []manifestEntry `json:"entries"`
}

func main() {
	root := flag.String("upstream-root", "", "pinned headscale-go module directory")
	out := flag.String("out", "", "output directory for generated JSON scenarios")
	flag.Parse()
	if *root == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: capture-scenarios --upstream-root DIR --out DIR")
		os.Exit(2)
	}
	if err := convert(*root, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func convert(root, out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	base := filepath.Join(root, "hscontrol", "policy", "v2", "testdata")
	result := manifest{UpstreamVersion: "v0.29.5", Entries: []manifestEntry{}}
	seenOutputs := map[string]string{}
	for _, category := range categories {
		paths, err := filepath.Glob(filepath.Join(base, category, "*.hujson"))
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			return fmt.Errorf("no captures for %s in %s", category, base)
		}
		sort.Strings(paths)
		for _, path := range paths {
			entry, err := convertOne(path, base, category, out)
			if err != nil {
				return err
			}
			if previous, exists := seenOutputs[entry.Output]; entry.Output != "" && exists {
				return fmt.Errorf("duplicate output %s from %s and %s", entry.Output, previous, entry.Source)
			}
			if entry.Output != "" {
				seenOutputs[entry.Output] = entry.Source
			}
			result.Entries = append(result.Entries, entry)
			result.Total++
			if entry.Skip == "" {
				result.Converted++
			} else {
				result.Skipped++
			}
		}
	}
	if err := writeJSON(filepath.Join(out, "manifest.json"), result); err != nil {
		return err
	}
	fmt.Printf("pinned capture corpus: %d converted, %d skipped, %d total; manifest %s\n",
		result.Converted, result.Skipped, result.Total, filepath.Join(out, "manifest.json"))
	return nil
}

func convertOne(path, base, category, out string) (manifestEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifestEntry{}, err
	}
	sum := sha256.Sum256(raw)
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return manifestEntry{}, err
	}
	entry := manifestEntry{Source: filepath.ToSlash(rel), SHA256: hex.EncodeToString(sum[:])}
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return entry, fmt.Errorf("standardize %s: %w", path, err)
	}
	var source capture
	if err := json.Unmarshal(standard, &source); err != nil {
		return entry, fmt.Errorf("decode %s: %w", path, err)
	}
	entry.TestID = source.TestID
	entry.APICode = source.Input.APIResponseCode
	if source.TestID == "" || len(source.Input.FullPolicy) == 0 {
		entry.Skip = "missing test_id or full_policy"
		return entry, nil
	}
	policyInput := source.Input.FullPolicy
	if policyInput[0] == '"' {
		var encodedPolicy string
		if err := json.Unmarshal(policyInput, &encodedPolicy); err != nil {
			return entry, fmt.Errorf("decode full_policy string in %s: %w", path, err)
		}
		policyInput = []byte(encodedPolicy)
	}
	policy, err := hujson.Standardize(policyInput)
	if err != nil {
		return entry, fmt.Errorf("standardize policy in %s: %w", path, err)
	}
	if !json.Valid(policy) {
		return entry, errors.New("standardized policy is not JSON: " + path)
	}
	users := make([]user, 0, len(source.Topology.Users))
	userIDs := make(map[string]uint64, len(source.Topology.Users))
	for _, sourceUser := range source.Topology.Users {
		users = append(users, user{ID: sourceUser.ID, Name: sourceUser.Name, Email: sourceUser.Email})
		userIDs[sourceUser.Name] = sourceUser.ID
	}
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	if len(users) == 0 || len(source.Topology.Nodes) == 0 {
		entry.Skip = "missing topology users or nodes"
		return entry, nil
	}
	names := make([]string, 0, len(source.Topology.Nodes))
	for name := range source.Topology.Nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	generated := scenario{
		Name:              "capture-" + source.TestID,
		SourceCapture:     entry.Source,
		SourceSHA256:      entry.SHA256,
		SourceAPICode:     source.Input.APIResponseCode,
		AuditTestVerdicts: true,
		Policy:            policy,
		Users:             users,
		Nodes:             make([]node, 0, len(names)),
		FilterNodeChecks:  make([]namedNodeCheck, 0, len(names)),
	}
	for _, name := range names {
		definition := source.Topology.Nodes[name]
		id := uint64(len(generated.Nodes) + 1)
		owner := uint64(0)
		if len(definition.Tags) == 0 {
			ownerName := definition.User
			if ownerName == "" {
				ownerName = users[0].Name
			}
			var ok bool
			owner, ok = userIDs[ownerName]
			if !ok {
				return entry, fmt.Errorf("unknown topology user %q in %s", ownerName, path)
			}
		}
		generated.Nodes = append(generated.Nodes, node{
			ID: id, UserID: owner, Hostname: name,
			IPv4: definition.IPv4, IPv6: definition.IPv6,
			Tags: definition.Tags, Routes: definition.RoutableIPs,
			ApprovedRoutes: definition.ApprovedRoutes,
		})
		check := namedNodeCheck{Name: name, NodeID: id}
		generated.FilterNodeChecks = append(generated.FilterNodeChecks, check)
		if category == "nodeattrs_results" {
			generated.NodeAttrChecks = append(generated.NodeAttrChecks, check)
		}
		if category == "ssh_results" {
			generated.SSHChecks = append(generated.SSHChecks, check)
		}
	}
	filename := "capture-" + source.TestID + ".json"
	if strings.ContainsAny(filename, `/\\`) {
		return entry, fmt.Errorf("invalid test_id %q in %s", source.TestID, path)
	}
	entry.Output = filename
	if err := writeJSON(filepath.Join(out, filename), generated); err != nil {
		return entry, err
	}
	return entry, nil
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
