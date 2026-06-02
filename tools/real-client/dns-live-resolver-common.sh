#!/usr/bin/env bash

dns_live_resolver_pid=""
dns_live_resolver_pids=()

dns_live_resolver_free_udp_port() {
  ruby -rsocket -e 's=UDPSocket.new; s.bind("0.0.0.0", 0); puts s.addr[1]; s.close'
}

dns_live_resolver_host_gateway_ip() {
  local image="$1"
  docker run --rm \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh \
    "${image}" \
    -ceu "awk '\$2 == \"host.docker.internal\" { print \$1; exit }' /etc/hosts" |
    sed -n '1p'
}

dns_live_resolver_ready() {
  local port="$1"
  local name="$2"
  local expected_ip="$3"
  local qtype="${4:-1}"
  ruby -rsocket -ripaddr -e '
    def encode_name(name)
      name.sub(/\.\z/, "").split(".").map { |label| [label.bytesize].pack("C") + label.b }.join.b + "\0".b
    end

    port = Integer(ARGV.fetch(0))
    name = ARGV.fetch(1)
    expected = IPAddr.new(ARGV.fetch(2)).hton
    qtype = Integer(ARGV.fetch(3))
    sock = nil
    begin
      sock = UDPSocket.new
      sock.connect("127.0.0.1", port)
      query = "hs".b + [0x0100, 1, 0, 0, 0].pack("nnnnn") + encode_name(name) + [qtype, 1].pack("nn")
      sock.send(query, 0)
      ready = IO.select([sock], nil, nil, 2)
      exit 1 unless ready
      response = sock.recv(1500)
      exit(response.include?(expected) ? 0 : 1)
    rescue SystemCallError
      exit 1
    ensure
      sock&.close
    end
  ' "${port}" "${name}" "${expected_ip}" "${qtype}"
}

dns_live_resolver_rcode_ready() {
  local port="$1"
  local name="$2"
  local expected_rcode="$3"
  ruby -rsocket -e '
    def encode_name(name)
      name.sub(/\.\z/, "").split(".").map { |label| [label.bytesize].pack("C") + label.b }.join.b + "\0".b
    end

    port = Integer(ARGV.fetch(0))
    name = ARGV.fetch(1)
    expected_rcode = Integer(ARGV.fetch(2))
    sock = nil
    begin
      sock = UDPSocket.new
      sock.connect("127.0.0.1", port)
      query = "hf".b + [0x0100, 1, 0, 0, 0].pack("nnnnn") + encode_name(name) + [1, 1].pack("nn")
      sock.send(query, 0)
      ready = IO.select([sock], nil, nil, 2)
      exit 1 unless ready
      response = sock.recv(1500)
      exit 1 if response.bytesize < 4
      flags = response.byteslice(2, 2).unpack1("n")
      exit((flags & 0x000f) == expected_rcode ? 0 : 1)
    rescue SystemCallError
      exit 1
    ensure
      sock&.close
    end
  ' "${port}" "${name}" "${expected_rcode}"
}

dns_live_resolver_track_pid() {
  local pid="$1"
  dns_live_resolver_pid="${pid}"
  dns_live_resolver_pids+=("${pid}")
}

dns_live_resolver_split_nameservers_json() {
  local suffix="$1"
  shift
  ruby -rjson -e '
    suffix = ARGV.shift.to_s.sub(/\.\z/, "")
    abort("missing DNS split suffix") if suffix.empty?
    resolvers = ARGV.map(&:to_s)
    abort("missing DNS resolver list for #{suffix}") if resolvers.empty? || resolvers.any?(&:empty?)
    puts JSON.generate({suffix => resolvers})
  ' "${suffix}" "$@"
}

dns_live_resolver_search_domains_json() {
  ruby -rjson -e '
    domains = ARGV.map { |domain| domain.to_s.sub(/\.\z/, "") }
    abort("missing DNS search domain list") if domains.empty? || domains.any?(&:empty?)
    puts JSON.generate(domains)
  ' "$@"
}

dns_live_resolver_plan_search_row() {
  local base_domain="$1"
  local search_suffix="$2"
  local resolver_addr="$3"
  local resolve_expectation="$4"

  base_domain="${base_domain%.}"
  search_suffix="${search_suffix%.}"
  if [[ -z "${base_domain}" || -z "${search_suffix}" || -z "${resolver_addr}" || -z "${resolve_expectation}" ]]; then
    echo "dns_live_resolver_plan_search_row requires base domain, search suffix, resolver address, and resolve expectation" >&2
    return 2
  fi
  if [[ "${resolve_expectation}" != *=* ]]; then
    echo "DNS live search resolve expectation must be name=ip4:value or name=ip6:value, got ${resolve_expectation}" >&2
    return 2
  fi

  DNS_LIVE_SEARCH_SPLIT_NAMESERVERS_JSON="$(dns_live_resolver_split_nameservers_json "${search_suffix}" "${resolver_addr}")"
  DNS_LIVE_SEARCH_DOMAINS_JSON="$(dns_live_resolver_search_domains_json "${search_suffix}")"
  DNS_LIVE_SEARCH_EXPECT_DNS_DOMAINS="${base_domain},${search_suffix}"
  DNS_LIVE_SEARCH_EXPECT_DNS_ROUTES="${search_suffix}=${resolver_addr}"
  DNS_LIVE_SEARCH_EXPECT_DNS_DEBUG_RESOLVES="${resolve_expectation}"
  export DNS_LIVE_SEARCH_SPLIT_NAMESERVERS_JSON
  export DNS_LIVE_SEARCH_DOMAINS_JSON
  export DNS_LIVE_SEARCH_EXPECT_DNS_DOMAINS
  export DNS_LIVE_SEARCH_EXPECT_DNS_ROUTES
  export DNS_LIVE_SEARCH_EXPECT_DNS_DEBUG_RESOLVES
}

dns_live_resolver_plan_multi_fallback_row() {
  local split_suffix="$1"
  local failure_resolver_addr="$2"
  local answer_resolver_addr="$3"
  local resolve_expectation="$4"

  split_suffix="${split_suffix%.}"
  if [[ -z "${split_suffix}" || -z "${failure_resolver_addr}" || -z "${answer_resolver_addr}" || -z "${resolve_expectation}" ]]; then
    echo "dns_live_resolver_plan_multi_fallback_row requires split suffix, failure resolver, answer resolver, and resolve expectation" >&2
    return 2
  fi
  if [[ "${failure_resolver_addr}" == "${answer_resolver_addr}" ]]; then
    echo "DNS live multi-resolver fallback requires distinct failure and answer resolvers" >&2
    return 2
  fi
  if [[ "${resolve_expectation}" != *=* ]]; then
    echo "DNS live multi-resolver resolve expectation must be name=ip4:value or name=ip6:value, got ${resolve_expectation}" >&2
    return 2
  fi

  DNS_LIVE_MULTI_SPLIT_NAMESERVERS_JSON="$(dns_live_resolver_split_nameservers_json "${split_suffix}" "${failure_resolver_addr}" "${answer_resolver_addr}")"
  DNS_LIVE_MULTI_EXPECT_DNS_ROUTES="${split_suffix}=${failure_resolver_addr}|${answer_resolver_addr}"
  DNS_LIVE_MULTI_EXPECT_DNS_DEBUG_RESOLVES="${resolve_expectation}"
  DNS_LIVE_MULTI_FAILURE_RESOLVER_ADDR="${failure_resolver_addr}"
  DNS_LIVE_MULTI_ANSWER_RESOLVER_ADDR="${answer_resolver_addr}"
  export DNS_LIVE_MULTI_SPLIT_NAMESERVERS_JSON
  export DNS_LIVE_MULTI_EXPECT_DNS_ROUTES
  export DNS_LIVE_MULTI_EXPECT_DNS_DEBUG_RESOLVES
  export DNS_LIVE_MULTI_FAILURE_RESOLVER_ADDR
  export DNS_LIVE_MULTI_ANSWER_RESOLVER_ADDR
}

start_dns_live_split_resolver() {
  local image="$1"
  local work_dir="$2"
  local base_domain="$3"
  local suffix="${REAL_CLIENT_DNS_LIVE_SPLIT_SUFFIX:-corp.${base_domain}}"
  local name="${REAL_CLIENT_DNS_LIVE_SPLIT_NAME:-split.${suffix}}"
  local expected_ip="${REAL_CLIENT_DNS_LIVE_SPLIT_IPV4:-203.0.113.53}"
  local ipv6_name="${REAL_CLIENT_DNS_LIVE_SPLIT_IPV6_NAME:-}"
  local expected_ipv6="${REAL_CLIENT_DNS_LIVE_SPLIT_IPV6:-}"
  local host_gateway_ip
  local port
  local records_json

  mkdir -p "${work_dir}"
  host_gateway_ip="$(dns_live_resolver_host_gateway_ip "${image}")"
  if [[ -z "${host_gateway_ip}" ]]; then
    echo "could not discover Docker host gateway IP for live DNS resolver fixture" >&2
    return 1
  fi

  port="$(dns_live_resolver_free_udp_port)"
  records_json="$(ruby -rjson -e '
    records = [{"name" => ARGV.fetch(0), "type" => 1, "value" => ARGV.fetch(1)}]
    ipv6_name = ARGV.fetch(2)
    ipv6_value = ARGV.fetch(3)
    if !ipv6_name.empty? || !ipv6_value.empty?
      abort("REAL_CLIENT_DNS_LIVE_SPLIT_IPV6_NAME and REAL_CLIENT_DNS_LIVE_SPLIT_IPV6 must be set together") if ipv6_name.empty? || ipv6_value.empty?
      records << {"name" => ipv6_name, "type" => 28, "value" => ipv6_value}
    end
    puts JSON.generate(records)
  ' "${name}" "${expected_ip}" "${ipv6_name}" "${expected_ipv6}")"
  ruby -rjson -rsocket -ripaddr -e '
    def parse_name(data, offset)
      labels = []
      loop do
        length = data.getbyte(offset)
        return nil if length.nil?
        offset += 1
        return [labels.join("."), offset] if length.zero?
        return nil if (length & 0xc0) != 0
        label = data.byteslice(offset, length)
        return nil if label.nil? || label.bytesize != length
        labels << label
        offset += length
      end
    end

    port = Integer(ARGV.fetch(0))
    records = JSON.parse(ARGV.fetch(1)).each_with_object({}) do |record, acc|
      name = record.fetch("name").downcase.sub(/\.\z/, "")
      qtype = Integer(record.fetch("type"))
      acc[[name, qtype]] = IPAddr.new(record.fetch("value")).hton
    end
    socket = UDPSocket.new
    socket.bind("0.0.0.0", port)
    $stdout.sync = true
    puts "dns-live-resolver listening on 0.0.0.0:#{port} for #{records.keys.map { |key| key.join("/") }.join(",")}"

    loop do
      data, remote = socket.recvfrom(1500)
      next if data.bytesize < 12
      parsed = parse_name(data, 12)
      next if parsed.nil?
      qname, offset = parsed
      type_class = data.byteslice(offset, 4)
      next if type_class.nil? || type_class.bytesize != 4
      qtype, qclass = type_class.unpack("nn")
      question = data.byteslice(12, offset + 4 - 12)
      record = qclass == 1 ? records[[qname.downcase.sub(/\.\z/, ""), qtype]] : nil
      matches = !record.nil?
      flags = matches ? 0x8180 : 0x8183
      answers = matches ? 1 : 0
      response = data.byteslice(0, 2) + [flags, 1, answers, 0, 0].pack("nnnnn") + question
      if matches
        response += "\xc0\x0c".b + [qtype, 1, 30, record.bytesize].pack("nnNn") + record
      end
      socket.send(response, 0, remote.fetch(3), remote.fetch(1))
    end
  ' "${port}" "${records_json}" \
    >"${work_dir}/dns-live-resolver.stdout" \
    2>"${work_dir}/dns-live-resolver.stderr" &
  dns_live_resolver_track_pid "$!"

  local deadline=$((SECONDS + 5))
  until dns_live_resolver_ready "${port}" "${name}" "${expected_ip}" 1 &&
    { [[ -z "${ipv6_name}" ]] || dns_live_resolver_ready "${port}" "${ipv6_name}" "${expected_ipv6}" 28; }; do
    if ! kill -0 "${dns_live_resolver_pid}" >/dev/null 2>&1; then
      echo "live DNS resolver fixture exited before answering ${name}" >&2
      stop_dns_live_resolver
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for live DNS resolver fixture to answer ${name}" >&2
      stop_dns_live_resolver
      return 1
    fi
    sleep 0.2
  done

  if ! kill -0 "${dns_live_resolver_pid}" >/dev/null 2>&1; then
    echo "live DNS resolver fixture did not answer ${name}" >&2
    stop_dns_live_resolver
    return 1
  fi

  DNS_LIVE_SPLIT_SUFFIX="${suffix}"
  DNS_LIVE_SPLIT_NAME="${name}"
  DNS_LIVE_SPLIT_IPV4="${expected_ip}"
  DNS_LIVE_SPLIT_RESOLVER_ADDR="${host_gateway_ip}:${port}"
  DNS_LIVE_SPLIT_ROUTE_EXPECTATION="${suffix}=${DNS_LIVE_SPLIT_RESOLVER_ADDR}"
  DNS_LIVE_SPLIT_RESOLVE_EXPECTATION="${name}=ip4:${expected_ip}"
  DNS_LIVE_SPLIT_RESOLVE_EXPECTATIONS="${DNS_LIVE_SPLIT_RESOLVE_EXPECTATION}"
  if [[ -n "${ipv6_name}" ]]; then
    DNS_LIVE_SPLIT_IPV6_NAME="${ipv6_name}"
    DNS_LIVE_SPLIT_IPV6="${expected_ipv6}"
    DNS_LIVE_SPLIT_IPV6_RESOLVE_EXPECTATION="${ipv6_name}=ip6:${expected_ipv6}"
    DNS_LIVE_SPLIT_RESOLVE_EXPECTATIONS="${DNS_LIVE_SPLIT_RESOLVE_EXPECTATIONS},${DNS_LIVE_SPLIT_IPV6_RESOLVE_EXPECTATION}"
    export DNS_LIVE_SPLIT_IPV6_NAME
    export DNS_LIVE_SPLIT_IPV6
    export DNS_LIVE_SPLIT_IPV6_RESOLVE_EXPECTATION
  fi
  export DNS_LIVE_SPLIT_SUFFIX
  export DNS_LIVE_SPLIT_NAME
  export DNS_LIVE_SPLIT_IPV4
  export DNS_LIVE_SPLIT_RESOLVER_ADDR
  export DNS_LIVE_SPLIT_ROUTE_EXPECTATION
  export DNS_LIVE_SPLIT_RESOLVE_EXPECTATION
  export DNS_LIVE_SPLIT_RESOLVE_EXPECTATIONS
}

start_dns_live_failure_resolver() {
  local image="$1"
  local work_dir="$2"
  local name="${3:-fallback-probe.test}"
  local mode="${REAL_CLIENT_DNS_LIVE_FAILURE_MODE:-servfail}"
  local host_gateway_ip
  local port
  local rcode

  case "${mode}" in
    servfail) rcode=2 ;;
    nxdomain) rcode=3 ;;
    refused) rcode=5 ;;
    *)
      echo "REAL_CLIENT_DNS_LIVE_FAILURE_MODE must be servfail, nxdomain, or refused" >&2
      return 2
      ;;
  esac

  mkdir -p "${work_dir}"
  host_gateway_ip="$(dns_live_resolver_host_gateway_ip "${image}")"
  if [[ -z "${host_gateway_ip}" ]]; then
    echo "could not discover Docker host gateway IP for live DNS failure resolver fixture" >&2
    return 1
  fi

  port="$(dns_live_resolver_free_udp_port)"
  ruby -rsocket -e '
    def parse_name(data, offset)
      labels = []
      loop do
        length = data.getbyte(offset)
        return nil if length.nil?
        offset += 1
        return [labels.join("."), offset] if length.zero?
        return nil if (length & 0xc0) != 0
        label = data.byteslice(offset, length)
        return nil if label.nil? || label.bytesize != length
        labels << label
        offset += length
      end
    end

    port = Integer(ARGV.fetch(0))
    rcode = Integer(ARGV.fetch(1))
    socket = UDPSocket.new
    socket.bind("0.0.0.0", port)
    $stdout.sync = true
    puts "dns-live-failure-resolver listening on 0.0.0.0:#{port} with rcode #{rcode}"

    loop do
      data, remote = socket.recvfrom(1500)
      next if data.bytesize < 12
      parsed = parse_name(data, 12)
      next if parsed.nil?
      _qname, offset = parsed
      question = data.byteslice(12, offset + 4 - 12)
      next if question.nil?
      flags = 0x8180 | rcode
      response = data.byteslice(0, 2) + [flags, 1, 0, 0, 0].pack("nnnnn") + question
      socket.send(response, 0, remote.fetch(3), remote.fetch(1))
    end
  ' "${port}" "${rcode}" \
    >"${work_dir}/dns-live-failure-resolver.stdout" \
    2>"${work_dir}/dns-live-failure-resolver.stderr" &
  dns_live_resolver_track_pid "$!"

  local deadline=$((SECONDS + 5))
  until dns_live_resolver_rcode_ready "${port}" "${name}" "${rcode}"; do
    if ! kill -0 "${dns_live_resolver_pid}" >/dev/null 2>&1; then
      echo "live DNS failure resolver fixture exited before answering ${name}" >&2
      stop_dns_live_resolver
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for live DNS failure resolver fixture to answer ${name}" >&2
      stop_dns_live_resolver
      return 1
    fi
    sleep 0.2
  done

  DNS_LIVE_FAILURE_RESOLVER_ADDR="${host_gateway_ip}:${port}"
  DNS_LIVE_FAILURE_RESOLVER_RCODE="${rcode}"
  export DNS_LIVE_FAILURE_RESOLVER_ADDR
  export DNS_LIVE_FAILURE_RESOLVER_RCODE
}

stop_dns_live_resolver() {
  local pids=("${dns_live_resolver_pids[@]}")
  local pid
  local seen=false
  if [[ -n "${dns_live_resolver_pid}" ]]; then
    for pid in "${pids[@]}"; do
      [[ "${pid}" == "${dns_live_resolver_pid}" ]] && seen=true
    done
    if [[ "${seen}" != true ]]; then
      pids+=("${dns_live_resolver_pid}")
    fi
  fi
  for pid in "${pids[@]}"; do
    [[ -n "${pid}" ]] || continue
    kill "${pid}" >/dev/null 2>&1 || true
  done
  for pid in "${pids[@]}"; do
    [[ -n "${pid}" ]] || continue
    wait "${pid}" >/dev/null 2>&1 || true
  done
  dns_live_resolver_pid=""
  dns_live_resolver_pids=()
}
