// A small UDP DNS responder used by the stock-client live resolver fixtures.
// It runs on port 53 in a Docker sidecar, giving Tailscale a routable resolver
// address instead of Docker Desktop's synthetic host.docker.internal address.
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"strings"
)

func main() {
	name := flag.String("name", "", "record name")
	ipv4 := flag.String("ipv4", "", "A record")
	ipv6Name := flag.String("ipv6-name", "", "AAAA record name")
	ipv6 := flag.String("ipv6", "", "AAAA record")
	rcode := flag.Int("rcode", 0, "response code for every query")
	flag.Parse()

	records := make(map[string]map[uint16]net.IP)
	add := func(host string, kind uint16, value string) {
		if host == "" || value == "" {
			return
		}
		ip := net.ParseIP(value)
		if ip == nil {
			log.Fatalf("invalid DNS fixture IP %q", value)
		}
		if kind == 1 {
			ip = ip.To4()
		} else {
			ip = ip.To16()
		}
		if ip == nil {
			log.Fatalf("invalid DNS fixture address family %q", value)
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if records[host] == nil {
			records[host] = make(map[uint16]net.IP)
		}
		records[host][kind] = ip
	}
	add(*name, 1, *ipv4)
	add(*ipv6Name, 28, *ipv6)
	if *rcode < 0 || *rcode > 15 {
		log.Fatalf("invalid DNS response code %d", *rcode)
	}

	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	tcp, err := net.Listen("tcp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			client, err := tcp.Accept()
			if err != nil {
				log.Printf("DNS TCP accept: %v", err)
				return
			}
			go serveTCP(client, records, uint16(*rcode))
		}
	}()
	log.Print("dns-live-responder listening on UDP/TCP :53")
	packet := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(packet)
		if err != nil {
			log.Fatal(err)
		}
		response := respond(packet[:n], records, uint16(*rcode))
		if response != nil {
			if _, err := conn.WriteTo(response, peer); err != nil {
				log.Printf("DNS reply: %v", err)
			}
		}
	}
}

func serveTCP(client net.Conn, records map[string]map[uint16]net.IP, rcode uint16) {
	defer client.Close()
	var length [2]byte
	for {
		if _, err := io.ReadFull(client, length[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(client, query); err != nil {
			return
		}
		response := respond(query, records, rcode)
		if response == nil {
			return
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		if _, err := client.Write(append(length[:], response...)); err != nil {
			return
		}
	}
}

func respond(query []byte, records map[string]map[uint16]net.IP, rcode uint16) []byte {
	if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	var labels []string
	offset := 12
	for {
		if offset >= len(query) {
			return nil
		}
		size := int(query[offset])
		offset++
		if size == 0 {
			break
		}
		if size > 63 || offset+size > len(query) {
			return nil
		}
		labels = append(labels, string(query[offset:offset+size]))
		offset += size
	}
	if offset+4 > len(query) {
		return nil
	}
	kind := binary.BigEndian.Uint16(query[offset : offset+2])
	class := binary.BigEndian.Uint16(query[offset+2 : offset+4])
	name := strings.ToLower(strings.Join(labels, "."))
	questionEnd := offset + 4
	record := records[name][kind]
	if rcode == 0 && class == 1 && len(record) == 0 {
		if _, known := records[name]; !known {
			rcode = 3
		}
	}
	response := make([]byte, questionEnd, questionEnd+16+len(record))
	copy(response, query[:questionEnd])
	binary.BigEndian.PutUint16(response[2:4], 0x8180|rcode)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	if rcode == 0 && class == 1 && len(record) > 0 {
		binary.BigEndian.PutUint16(response[6:8], 1)
		answer := make([]byte, 12+len(record))
		binary.BigEndian.PutUint16(answer[0:2], 0xc00c)
		binary.BigEndian.PutUint16(answer[2:4], kind)
		binary.BigEndian.PutUint16(answer[4:6], 1)
		binary.BigEndian.PutUint32(answer[6:10], 30)
		binary.BigEndian.PutUint16(answer[10:12], uint16(len(record)))
		copy(answer[12:], record)
		response = append(response, answer...)
	}
	return response
}
