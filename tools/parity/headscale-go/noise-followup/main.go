// A small process-level TS2021 register client for the paired follow-up smoke.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/control/ts2021"
	"tailscale.com/net/wsconn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type savedState struct {
	MachinePrivate string `json:"machine_private"`
	NodeKey        string `json:"node_key"`
	AuthURL        string `json:"auth_url"`
}

type outcome struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func main() {
	mode := flag.String("mode", "", "initial, followup, stream, map-once, expired, authkey-initial, authkey-retag, or interactive-reauth")
	serverURL := flag.String("url", "", "headscale HTTP URL")
	statePath := flag.String("state", "", "initial state JSON file")
	outputPath := flag.String("output", "", "result JSON file")
	attacker := flag.Bool("attacker", false, "use a different Noise machine and node key")
	websocketTransport := flag.Bool("websocket", false, "use the browser/WASM WebSocket transport")
	caCert := flag.String("ca-cert", "", "trusted CA certificate for HTTPS and WSS")
	authKey := flag.String("authkey", "", "preauth key for authkey-initial or authkey-retag")
	requestTags := flag.String("request-tags", "", "comma-separated Hostinfo.RequestTags")
	flag.Parse()
	if err := run(*mode, *serverURL, *statePath, *outputPath, *attacker, *websocketTransport, *caCert, *authKey, *requestTags); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(mode, serverURL, statePath, outputPath string, attacker, websocketTransport bool, caCert, authKey, requestTags string) error {
	if serverURL == "" || statePath == "" || outputPath == "" {
		return errors.New("-url, -state, and -output are required")
	}
	var state savedState
	var machine key.MachinePrivate
	var nodeKey string
	var followup string
	switch mode {
	case "initial", "authkey-initial":
		machine = key.NewMachine()
		nodeKey = key.NewNode().Public().String()
	case "followup", "stream", "map-once", "expired", "authkey-retag", "interactive-reauth":
		raw, err := os.ReadFile(statePath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &state); err != nil {
			return err
		}
		if err := machine.UnmarshalText([]byte(state.MachinePrivate)); err != nil {
			return err
		}
		nodeKey = state.NodeKey
		followup = state.AuthURL
		if mode == "authkey-retag" || mode == "interactive-reauth" {
			nodeKey = key.NewNode().Public().String()
			followup = ""
		}
		if attacker {
			machine = key.NewMachine()
		}
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	if (mode == "authkey-initial" || mode == "authkey-retag") && authKey == "" {
		return errors.New("-authkey is required for authkey registration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	result, err := register(ctx, serverURL, machine, nodeKey, followup, websocketTransport, caCert, mode, outputPath, authKey, requestTags)
	if err != nil {
		return err
	}
	if mode == "authkey-initial" || mode == "authkey-retag" {
		if result.Status != http.StatusOK {
			return fmt.Errorf("authkey registration returned status=%d body=%s", result.Status, result.Body)
		}
		privateText, err := machine.MarshalText()
		if err != nil {
			return err
		}
		state = savedState{MachinePrivate: string(privateText), NodeKey: nodeKey}
		if err := writeJSON(statePath, state); err != nil {
			return err
		}
	}
	if mode == "initial" || mode == "interactive-reauth" {
		var response struct {
			AuthURL string `json:"AuthURL"`
		}
		if result.Status != http.StatusOK || json.Unmarshal([]byte(result.Body), &response) != nil || response.AuthURL == "" {
			return fmt.Errorf("interactive registration did not return AuthURL: status=%d body=%s", result.Status, result.Body)
		}
		privateText, err := machine.MarshalText()
		if err != nil {
			return err
		}
		state = savedState{MachinePrivate: string(privateText), NodeKey: nodeKey, AuthURL: response.AuthURL}
		return writeJSON(statePath, state)
	}
	return writeJSON(outputPath, result)
}

func register(ctx context.Context, serverURL string, machine key.MachinePrivate, nodeKey, followup string, websocketTransport bool, caCert, mode, outputPath, authKey, requestTags string) (outcome, error) {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return outcome{}, err
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.Port() == "" {
		return outcome{}, errors.New("-url must be an explicit HTTP or HTTPS host:port URL")
	}
	client := http.DefaultClient
	var roots *x509.CertPool
	if parsed.Scheme == "https" {
		if caCert == "" {
			return outcome{}, errors.New("-ca-cert is required for HTTPS and WSS")
		}
		certificate, err := os.ReadFile(caCert)
		if err != nil {
			return outcome{}, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			return outcome{}, errors.New("-ca-cert does not contain a PEM certificate")
		}
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	}
	keyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/key?v=138", nil)
	if err != nil {
		return outcome{}, err
	}
	keyResp, err := client.Do(keyReq)
	if err != nil {
		return outcome{}, err
	}
	defer keyResp.Body.Close()
	if keyResp.StatusCode != http.StatusOK {
		return outcome{}, fmt.Errorf("server key returned HTTP %d", keyResp.StatusCode)
	}
	var keys struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(keyResp.Body).Decode(&keys); err != nil {
		return outcome{}, err
	}
	var controlKey key.MachinePublic
	if err := controlKey.UnmarshalText([]byte(keys.PublicKey)); err != nil {
		return outcome{}, err
	}
	var raw *controlbase.Conn
	if websocketTransport {
		initial, continueHandshake, err := controlbase.ClientDeferred(machine, controlKey, uint16(tailcfg.CurrentCapabilityVersion))
		if err != nil {
			return outcome{}, err
		}
		websocketURL := url.URL{
			Scheme: "ws", Host: parsed.Host, Path: "/ts2021",
			RawQuery: url.Values{controlhttpcommon.HandshakeHeaderName: {base64.StdEncoding.EncodeToString(initial)}}.Encode(),
		}
		if parsed.Scheme == "https" {
			websocketURL.Scheme = "wss"
		}
		ws, _, err := websocket.Dial(ctx, websocketURL.String(), &websocket.DialOptions{
			Subprotocols: []string{controlhttpcommon.UpgradeHeaderValue},
			HTTPClient:   client,
		})
		if err != nil {
			return outcome{}, err
		}
		transport := wsconn.NetConn(context.Background(), ws, websocket.MessageBinary, websocketURL.String())
		raw, err = continueHandshake(ctx, transport)
		if err != nil {
			transport.Close()
			return outcome{}, err
		}
	} else {
		dialer := &controlhttp.Dialer{
			Hostname: parsed.Hostname(), HTTPPort: parsed.Port(), HTTPSPort: controlhttp.NoPort,
			MachineKey: machine, ControlKey: controlKey,
			ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
			ExtraRootCAs:    roots,
		}
		if parsed.Scheme == "https" {
			dialer.HTTPPort = controlhttp.NoPort
			dialer.HTTPSPort = parsed.Port()
		}
		base, err := dialer.Dial(ctx)
		if err != nil {
			return outcome{}, err
		}
		raw = base.Conn
	}
	conn := ts2021.NewConn(raw, func() {})
	defer conn.Close()
	h2conn, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		return outcome{}, err
	}
	if mode == "stream" || mode == "map-once" || mode == "expired" {
		return readMapStream(ctx, h2conn, parsed.Host, nodeKey, mode, outputPath)
	}
	registerRequest := map[string]any{
		"Version":  tailcfg.CurrentCapabilityVersion,
		"NodeKey":  nodeKey,
		"Followup": followup,
		"Hostinfo": map[string]any{"Hostname": "followup-process-node"},
	}
	if requestTags != "" {
		registerRequest["Hostinfo"].(map[string]any)["RequestTags"] = strings.Split(requestTags, ",")
	}
	if authKey != "" {
		registerRequest["Auth"] = map[string]string{"AuthKey": authKey}
	}
	requestBody, err := json.Marshal(registerRequest)
	if err != nil {
		return outcome{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+parsed.Host+"/machine/register", bytes.NewReader(requestBody))
	if err != nil {
		return outcome{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h2conn.RoundTrip(req)
	if err != nil {
		return outcome{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return outcome{}, err
	}
	return outcome{Status: resp.StatusCode, Body: string(body)}, nil
}

func readMapStream(ctx context.Context, h2conn *http2.ClientConn, host, nodeKey, mode, outputPath string) (outcome, error) {
	requestBody, err := json.Marshal(map[string]any{
		"Version": tailcfg.CurrentCapabilityVersion,
		"NodeKey": nodeKey,
		"Stream":  true,
	})
	if err != nil {
		return outcome{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/machine/map", bytes.NewReader(requestBody))
	if err != nil {
		return outcome{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h2conn.RoundTrip(req)
	if err != nil {
		return outcome{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return outcome{Status: resp.StatusCode, Body: string(body)}, nil
	}
	var header [4]byte
	if _, err := io.ReadFull(resp.Body, header[:]); err != nil {
		return outcome{}, fmt.Errorf("read initial map frame length: %w", err)
	}
	frameSize := binary.LittleEndian.Uint32(header[:])
	if frameSize == 0 || frameSize > 1<<20 {
		return outcome{}, fmt.Errorf("invalid initial map frame size %d", frameSize)
	}
	frame := make([]byte, frameSize)
	if _, err := io.ReadFull(resp.Body, frame); err != nil {
		return outcome{}, fmt.Errorf("read initial map frame: %w", err)
	}
	if mode == "expired" {
		return outcome{Status: resp.StatusCode, Body: string(frame)}, nil
	}
	var first struct {
		Node struct {
			Key string `json:"Key"`
		} `json:"Node"`
	}
	if err := json.Unmarshal(frame, &first); err != nil {
		return outcome{}, err
	}
	if first.Node.Key != nodeKey {
		return outcome{}, fmt.Errorf("initial map self key %q, want %q", first.Node.Key, nodeKey)
	}
	if mode == "map-once" {
		return outcome{Status: resp.StatusCode, Body: string(frame)}, nil
	}
	if err := os.WriteFile(outputPath+".ready", []byte("ready\n"), 0o600); err != nil {
		return outcome{}, err
	}
	_, closeErr := io.Copy(io.Discard, resp.Body)
	if ctx.Err() != nil {
		return outcome{}, fmt.Errorf("deleted node map stream did not close before deadline: %w", ctx.Err())
	}
	closeError := ""
	if closeErr != nil {
		closeError = closeErr.Error()
	}
	closed, err := json.Marshal(map[string]any{"closed": true, "close_error": closeError})
	if err != nil {
		return outcome{}, err
	}
	return outcome{Status: resp.StatusCode, Body: string(closed)}, nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}
