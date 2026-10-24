// cli-fixture provides deterministic upstream protobuf responses for comparing
// CLI serialization and request construction. It is not a control server.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	_ "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

func main() {
	socket := flag.String("socket", "", "Unix socket to listen on")
	fixturePath := flag.String("fixture", "", "JSON response fixture")
	auditPath := flag.String("audit", "", "JSONL request capture")
	flag.Parse()
	if err := serve(*socket, *fixturePath, *auditPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(socket, fixturePath, auditPath string) error {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		return err
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(data, &fixtures); err != nil {
		return err
	}
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName("headscale.v1.HeadscaleService")
	if err != nil {
		return err
	}
	service := desc.(protoreflect.ServiceDescriptor)
	audit, err := os.Create(auditPath)
	if err != nil {
		return err
	}
	defer audit.Close()
	var auditMu sync.Mutex
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		path, _ := grpc.MethodFromServerStream(stream)
		method := strings.TrimPrefix(path, "/headscale.v1.HeadscaleService/")
		methodDesc := service.Methods().ByName(protoreflect.Name(method))
		if methodDesc == nil {
			return status.Error(codes.Unimplemented, "unknown fixture method")
		}
		request := dynamicpb.NewMessage(methodDesc.Input())
		if err := stream.RecvMsg(request); err != nil {
			return err
		}
		requestJSON, err := protojson.Marshal(request)
		if err != nil {
			return err
		}
		auditMu.Lock()
		err = json.NewEncoder(audit).Encode(map[string]any{"method": method, "request": json.RawMessage(requestJSON)})
		auditMu.Unlock()
		if err != nil {
			return err
		}
		responseJSON, ok := fixtures[method]
		if !ok {
			return status.Error(codes.Unimplemented, "missing fixture for "+method)
		}
		// Filtering reproduces the lookup preceding users rename/destroy, while
		// leaving the full multi-user response available to list commands.
		if method == "ListUsers" {
			var response map[string][]map[string]any
			var filter map[string]any
			if err := json.Unmarshal(responseJSON, &response); err != nil {
				return err
			}
			if err := json.Unmarshal(requestJSON, &filter); err != nil {
				return err
			}
			users := make([]map[string]any, 0)
			for _, user := range response["users"] {
				matches := true
				for _, key := range []string{"id", "name", "email"} {
					if value, exists := filter[key]; exists && fmt.Sprint(user[key]) != fmt.Sprint(value) {
						matches = false
					}
				}
				if matches {
					users = append(users, user)
				}
			}
			responseJSON, err = json.Marshal(map[string]any{"users": users})
			if err != nil {
				return err
			}
		}
		response := dynamicpb.NewMessage(methodDesc.Output())
		if err := protojson.Unmarshal(responseJSON, response); err != nil {
			return status.Errorf(codes.Internal, "%s fixture: %v", method, err)
		}
		return stream.SendMsg(response)
	}))
	return server.Serve(listener)
}
