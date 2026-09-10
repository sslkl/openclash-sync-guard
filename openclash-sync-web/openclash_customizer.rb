#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "yaml"

module OpenClashCustomizer
  VERSION = "OPENCLASH_SYNC_CUSTOM_V1"
  RULE_TYPES = %w[DOMAIN DOMAIN-SUFFIX IP-CIDR IP-CIDR6].freeze
  MAX_ITEMS = 256
  MAX_SUPPLEMENT_ITEMS = 10_000
  MAX_EXACT_BYTES = 8192
  DOMAIN = /\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\z/i.freeze
  MAYING_GROUPS = %w[Maying-HK-Auto Maying-JP-Auto Maying-SG-Auto Maying-US-Auto Maying-TW-Auto Maying-Others-Auto].freeze
  HEALTH_URL = "http://www.gstatic.com/generate_204"

  Model = Struct.new(:rules, :filters, :supplemental_rules, :supplemental_filters,
                     :owned_rules, :owned_filters, :owned_supplemental_rules, :owned_supplemental_filters,
                     :chains, :owned_chains, :chain_explicit)
  Result = Struct.new(:config, :state, :rule_count, :filter_count, :sha256)

  class StrictJson
    class ParseError < StandardError; end
    NUMBER = /\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.freeze
    WHITESPACE = [0x20, 0x09, 0x0a, 0x0d].freeze
    ESCAPES = {0x22 => 0x22, 0x5c => 0x5c, 0x2f => 0x2f, 0x62 => 0x08,
               0x66 => 0x0c, 0x6e => 0x0a, 0x72 => 0x0d, 0x74 => 0x09}.freeze

    def initialize(text)
      raise ParseError unless text.is_a?(String) && text.bytesize <= 2 * 1024 * 1024
      @text = text.b
      @index = 0
    end

    def parse
      value = parse_value
      whitespace
      raise ParseError unless @index == @text.bytesize
      value
    end

    private

    def parse_value
      @nodes = (@nodes || 0) + 1
      @depth = (@depth || 0) + 1
      raise ParseError if @nodes > 100_000 || @depth > 32
      whitespace
      case @text.getbyte(@index)
      when 0x7b then parse_object
      when 0x5b then parse_array
      when 0x22 then parse_string
      when 0x74 then literal("true", true)
      when 0x66 then literal("false", false)
      when 0x6e then literal("null", nil)
      else parse_number
      end
    ensure
      @depth -= 1 if @depth
    end

    def parse_object
      @index += 1
      result = {}
      whitespace
      return (@index += 1; result) if @text.getbyte(@index) == 0x7d
      loop do
        whitespace
        raise ParseError unless @text.getbyte(@index) == 0x22
        key = parse_string
        raise ParseError if result.key?(key)
        whitespace
        raise ParseError unless @text.getbyte(@index) == 0x3a
        @index += 1
        result[key] = parse_value
        whitespace
        byte = @text.getbyte(@index)
        @index += 1
        break if byte == 0x7d
        raise ParseError unless byte == 0x2c
      end
      result
    end

    def parse_array
      @index += 1
      result = []
      whitespace
      return (@index += 1; result) if @text.getbyte(@index) == 0x5d
      loop do
        result << parse_value
        whitespace
        byte = @text.getbyte(@index)
        @index += 1
        break if byte == 0x5d
        raise ParseError unless byte == 0x2c
      end
      result
    end

    def parse_string
      raise ParseError unless @text.getbyte(@index) == 0x22
      @index += 1
      output = +"".b
      loop do
        byte = @text.getbyte(@index)
        raise ParseError unless byte
        @index += 1
        break if byte == 0x22
        raise ParseError if byte < 0x20
        unless byte == 0x5c
          output << byte
          next
        end
        escaped = @text.getbyte(@index)
        raise ParseError unless escaped
        @index += 1
        mapped = ESCAPES[escaped]
        if mapped
          output << mapped
        elsif escaped == 0x75
          codepoint = unicode_escape
          if codepoint.between?(0xd800, 0xdbff)
            raise ParseError unless @text.byteslice(@index, 2) == "\\u"
            @index += 2
            low = unicode_escape
            raise ParseError unless low.between?(0xdc00, 0xdfff)
            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + low - 0xdc00
          elsif codepoint.between?(0xdc00, 0xdfff)
            raise ParseError
          end
          output << [codepoint].pack("U")
        else
          raise ParseError
        end
      end
      output.force_encoding(Encoding::UTF_8)
      raise ParseError unless output.valid_encoding?
      output
    end

    def unicode_escape
      hex = @text.byteslice(@index, 4)
      raise ParseError unless hex&.match?(/\A[0-9A-Fa-f]{4}\z/)
      @index += 4
      hex.to_i(16)
    end

    def parse_number
      match = NUMBER.match(@text, @index)
      raise ParseError unless match
      token = match[0]
      @index += token.bytesize
      value = token.match?(/[.eE]/) ? Float(token) : Integer(token, 10)
      raise ParseError if value.is_a?(Float) && !value.finite?
      value
    rescue ArgumentError
      raise ParseError
    end

    def literal(token, value)
      raise ParseError unless @text.byteslice(@index, token.bytesize) == token
      @index += token.bytesize
      value
    end

    def whitespace
      @index += 1 while WHITESPACE.include?(@text.getbyte(@index))
    end
  end

  module_function

  def audit_yaml_tree(value)
    stack = [[value, 1]]
    seen = {}
    nodes = 0
    until stack.empty?
      node, depth = stack.pop
      nodes += 1
      raise "YAML_BUDGET" if nodes > 100_000 || depth > 64
      case node
      when Hash
        raise "YAML_ALIAS" if seen[node.object_id]
        seen[node.object_id] = true
        raise "YAML_BUDGET" if node.length > 50_000
        node.each do |key, child|
          raise "YAML_BUDGET" unless key.is_a?(String) && key.valid_encoding? && key.bytesize <= 512 && !key.include?("\0")
          stack << [child, depth + 1]
        end
      when Array
        raise "YAML_ALIAS" if seen[node.object_id]
        seen[node.object_id] = true
        raise "YAML_BUDGET" if node.length > 50_000
        node.each { |child| stack << [child, depth + 1] }
      when String
        raise "YAML_BUDGET" unless node.valid_encoding? && node.bytesize <= 1024 * 1024 && !node.include?("\0")
      when Symbol
        text = node.to_s
        raise "YAML_BUDGET" unless text.valid_encoding? && text.bytesize.between?(1, 1024) && !text.include?("\0")
      when Integer, TrueClass, FalseClass, NilClass
        nil
      when Float
        raise "YAML_BUDGET" unless node.finite?
      else
        raise "YAML_BUDGET"
      end
    end
    value
  end

  def safe_yaml(bytes)
    raise "YAML_SIZE" if bytes.bytesize > 2 * 1024 * 1024
    audit_yaml_tree(YAML.safe_load(bytes, permitted_classes: [Symbol], aliases: false))
  rescue ArgumentError
    audit_yaml_tree(YAML.safe_load(bytes, [Symbol], [], false))
  end

  def clean_field(value, label, max = 253)
    raise label unless value.is_a?(String) && !value.empty? && value.bytesize <= max
    raise label if value.include?("\t") || value.include?("\r") || value.include?("\n")
    value
  end

  def domain(value)
    normalized = clean_field(value, "DOMAIN").downcase.sub(/\.\z/, "")
    raise "DOMAIN" unless DOMAIN.match?(normalized)
    normalized
  end

  def fake_filter(value)
    normalized = clean_field(value, "FAKE_FILTER").downcase.sub(/\.\z/, "")
    prefix = normalized.start_with?("*.", "+.") ? normalized.slice!(0, 2) : ""
    prefix + domain(normalized)
  end

  def network(kind, value)
    raw = clean_field(value, "IP", 64)
    address, prefix_text, extra = raw.split("/", -1)
    raise "IP" if extra || address.nil? || address.empty?
    if kind == "IP-CIDR"
      prefix = prefix_text.nil? ? 32 : decimal(prefix_text, 32)
      octets = address.split(".", -1)
      raise "IP" unless octets.length == 4
      values = octets.map { |part| decimal(part, 255) }
      number = values.inject(0) { |memo, part| (memo << 8) | part }
      network = prefix.zero? ? 0 : (number >> (32 - prefix)) << (32 - prefix)
      normalized = [24, 16, 8, 0].map { |shift| (network >> shift) & 255 }.join(".")
      "#{normalized}/#{prefix}"
    elsif kind == "IP-CIDR6"
      prefix = prefix_text.nil? ? 128 : decimal(prefix_text, 128)
      number = parse_ipv6(address)
      network = prefix.zero? ? 0 : (number >> (128 - prefix)) << (128 - prefix)
      "#{format_ipv6(network)}/#{prefix}"
    else
      raise "IP_VERSION"
    end
  rescue ArgumentError
    raise "IP"
  end

  def decimal(value, maximum)
    raise ArgumentError unless value.is_a?(String) && value.match?(/\A(?:0|[1-9][0-9]*)\z/)
    number = value.to_i
    raise ArgumentError if number > maximum
    number
  end

  def parse_ipv4(value)
    octets = value.split(".", -1)
    raise ArgumentError unless octets.length == 4
    octets.map { |part| decimal(part, 255) }.inject(0) { |memo, part| (memo << 8) | part }
  end

  def ip_address(value, label = "IP")
    raw = clean_field(value, label, 64)
    raise label if raw.include?("/")
    if raw.include?(".")
      [:ipv4, parse_ipv4(raw)]
    elsif raw.include?(":")
      [:ipv6, parse_ipv6(raw)]
    else
      raise label
    end
  rescue ArgumentError
    raise label
  end

  def cidr_include?(spec, address, kind = nil)
    raise "ROUTE_RULES" unless address.is_a?(Array) && address.length == 2
    family = if kind == "IP-CIDR"
               :ipv4
             elsif kind == "IP-CIDR6"
               :ipv6
             elsif spec.is_a?(String) && spec.include?(":")
               :ipv6
             else
               :ipv4
             end
    return false unless address[0] == family
    bits = family == :ipv4 ? 32 : 128
    normalized = network(family == :ipv4 ? "IP-CIDR" : "IP-CIDR6", spec)
    network_text, prefix_text = normalized.split("/", 2)
    prefix = decimal(prefix_text, bits)
    base = ip_address(network_text, "ROUTE_RULES")[1]
    prefix.zero? || (address[1] >> (bits - prefix)) == (base >> (bits - prefix))
  rescue RuntimeError, ArgumentError
    raise "ROUTE_RULES"
  end

  def parse_ipv6(value)
    raise ArgumentError unless value.is_a?(String) && value.match?(/\A[0-9a-f:]+\z/i)
    raise ArgumentError if value.include?(":::") || value.scan("::").length > 1
    compressed = value.include?("::")
    left_text, right_text = compressed ? value.split("::", -1) : [value, ""]
    left = left_text.empty? ? [] : left_text.split(":", -1)
    right = right_text.empty? ? [] : right_text.split(":", -1)
    raise ArgumentError if (left + right).any? { |part| !part.match?(/\A[0-9a-f]{1,4}\z/i) }
    if compressed
      missing = 8 - left.length - right.length
      raise ArgumentError if missing < 1
      parts = left + Array.new(missing, "0") + right
    else
      raise ArgumentError unless left.length == 8
      parts = left
    end
    raise ArgumentError unless parts.length == 8
    parts.inject(0) { |memo, part| (memo << 16) | part.to_i(16) }
  end

  def format_ipv6(number)
    parts = 8.times.map { |index| (number >> ((7 - index) * 16)) & 0xffff }
    best_start = nil
    best_length = 0
    index = 0
    while index < parts.length
      if parts[index].zero?
        finish = index
        finish += 1 while finish < parts.length && parts[finish].zero?
        length = finish - index
        if length >= 2 && length > best_length
          best_start = index
          best_length = length
        end
        index = finish
      else
        index += 1
      end
    end
    return parts.map { |part| part.to_s(16) }.join(":") unless best_start
    before = parts[0...best_start].map { |part| part.to_s(16) }.join(":")
    after = parts[(best_start + best_length)..-1].map { |part| part.to_s(16) }.join(":")
    return "::" if before.empty? && after.empty?
    return "::#{after}" if before.empty?
    return "#{before}::" if after.empty?
    "#{before}::#{after}"
  end

  def normalize_rule(fields)
    raise "RULE_FIELDS" unless fields.length == 3
    kind = clean_field(fields[0], "RULE_TYPE", 16).upcase
    raise "RULE_TYPE" unless RULE_TYPES.include?(kind)
    value = kind.start_with?("IP-") ? network(kind, fields[1]) : domain(fields[1])
    policy = clean_field(fields[2], "POLICY", 128).dup.force_encoding(Encoding::UTF_8)
    raise "POLICY" unless policy.valid_encoding? && !policy.match?(/[\x00-\x1f\x7f-\u009f,]/)
    [kind, value, policy]
  end

  def exact_item(value, label)
    clean_field(value, label, MAX_EXACT_BYTES).tap do |text|
      raise label if text.include?("\0")
    end
  end

  def supplemental_rule(value)
    text = exact_item(value, "SUPPLEMENT_RULE")
    fields = text.split(",", -1)
    raise "SUPPLEMENT_RULE" unless fields.length >= 3 && RULE_TYPES.include?(fields[0].upcase)
    normalized = normalize_rule(fields.first(3))
    raise "SUPPLEMENT_RULE" unless normalized.first == fields[0].upcase
    text
  end

  def supplemental_filter(value)
    exact_item(value, "SUPPLEMENT_FAKE")
  end

  CHAIN_PREFIX = "__OCS_UP_"
  CHAIN_MAX = 32
  CHAIN_CIPHERS = %w[aes-128-gcm aes-256-gcm chacha20-ietf-poly1305].freeze
  CHAIN_KEYS = %w[node type server port username password tls sni cipher keep_password].freeze

  def chain_name(value)
    raise "CHAIN_NODE" unless value.is_a?(String) && value.valid_encoding? && value.bytesize.between?(1, 512) &&
                              !value.match?(/[\x00-\x1f\x7f]/) && !value.start_with?(CHAIN_PREFIX) &&
                              !%w[DIRECT REJECT GLOBAL COMPATIBLE PASS].include?(value)
    value
  end

  def chain_server(value)
    raise "CHAIN_SERVER" unless value.is_a?(String) && value.bytesize.between?(1, 253)
    if value.include?(":")
      number = parse_ipv6(value)
      raise "CHAIN_SERVER" if number <= 1 || (number >> 120) == 255 || (number >> 118) == 0x3fa ||
                              ((number >> 32) == 0xffff || (number >> 32).zero?)
      format_ipv6(number)
    elsif value.match?(/\A[0-9.]+\z/)
      number = parse_ipv4(value)
      raise "CHAIN_SERVER" if (number >> 24) == 0 || (number >> 24) == 127 ||
                              (number >> 16) == 0xa9fe || (number >> 28) >= 14
      value
    else
      host = domain(value)
      raise "CHAIN_SERVER" unless host.include?(".") && host != "localhost" && !host.end_with?(".localhost")
      host
    end
  rescue ArgumentError
    raise "CHAIN_SERVER"
  end

  def chain_profile(value, old: nil)
    raise "CHAIN_FIELDS" unless value.is_a?(Hash) && (value.keys - CHAIN_KEYS).empty?
    profile = {"node" => chain_name(value["node"]), "type" => value["type"],
               "server" => chain_server(value["server"]), "port" => value["port"]}
    raise "CHAIN_TYPE" unless %w[socks5 http ss].include?(profile["type"])
    raise "CHAIN_PORT" unless profile["port"].is_a?(Integer) && profile["port"].between?(1, 65_535)
    %w[username password sni cipher].each do |key|
      next unless value.key?(key)
      text = value[key]
      limit = key == "password" ? 1024 : 253
      raise "CHAIN_FIELD" unless text.is_a?(String) && text.valid_encoding? && text.bytesize <= limit && !text.match?(/[\x00-\x1f\x7f]/)
      profile[key] = text unless text.empty?
    end
    if value.key?("tls")
      raise "CHAIN_TLS" unless value["tls"] == true || value["tls"] == false
      profile["tls"] = value["tls"]
    end
    profile["sni"] = domain(profile["sni"]) if profile["sni"]
    if profile["type"] == "ss"
      raise "CHAIN_FIELDS" if profile.key?("username") || profile.key?("tls") || profile.key?("sni")
      raise "CHAIN_CIPHER" unless CHAIN_CIPHERS.include?(profile["cipher"])
    else
      raise "CHAIN_FIELDS" if profile.key?("cipher")
      profile["tls"] ||= false
      raise "CHAIN_SNI" if profile["sni"] && (profile["type"] != "http" || !profile["tls"])
    end
    if value.key?("keep_password")
      raise "CHAIN_PASSWORD" unless [true, false].include?(value["keep_password"])
      if value["keep_password"]
        raise "CHAIN_PASSWORD" if profile.key?("password") || !old || !old["password"]
        identity = %w[node type server port username tls sni cipher]
        raise "CHAIN_PASSWORD_IDENTITY" unless identity.all? { |key| profile[key] == old[key] }
        profile["password"] = old["password"]
      end
    end
    if profile["type"] == "ss"
      raise "CHAIN_PASSWORD" unless profile["password"]
    else
      raise "CHAIN_AUTH" unless !!profile["username"] == !!profile["password"]
      # RFC 1929 encodes SOCKS credentials in one byte.
      if profile["type"] == "socks5"
        raise "CHAIN_AUTH" if %w[username password].any? { |key| profile[key] && profile[key].bytesize > 255 }
      end
    end
    profile
  end

  def chain_record(text)
    raise "CHAIN_RECORD" unless text.is_a?(String) && text.bytesize <= 128 * 1024 && text.match?(/\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/)
    value = safe_yaml(text.unpack1("m0"))
    raise "CHAIN_RECORD" unless value.is_a?(Hash)
    value
  end

  def chain_encoded(value)
    [YAML.dump(value)].pack("m0")
  end

  def chain_source(node, original)
    raise "CHAIN_ORIGINAL" unless original.is_a?(Hash) && original["name"] == chain_name(node) &&
                                  original["type"].is_a?(String) && original["server"].is_a?(String) &&
                                  !original.key?("dialer-proxy") && !%w[direct reject pass dns compatible].include?(original["type"])
    original
  end

  def chain_original(record)
    raise "CHAIN_OWNERSHIP" unless record.is_a?(Hash) && record.keys.sort == %w[node original revision] &&
                                  record["revision"].is_a?(String) && record["revision"].match?(/\A[0-9a-f]{32}\z/)
    chain_source(record["node"], record["original"])
  end

  def chain_revision
    bytes = File.open("/dev/urandom", "rb") { |file| file.read(16) }
    raise "CHAIN_RANDOM" unless bytes && bytes.bytesize == 16
    bytes.unpack1("H*")
  end

  def chain_proxies(config)
    proxies = config["proxies"]
    raise "CHAIN_PROXIES" unless proxies.is_a?(Array) && proxies.all? { |item| item.is_a?(Hash) && item["name"].is_a?(String) }
    raise "CHAIN_DUPLICATE" unless proxies.map { |item| item["name"] }.uniq.length == proxies.length
    proxies
  end

  def chain_pair(profile, record)
    original = chain_original(record)
    # An opaque per-version identity proves live linkage without exposing a
    # deterministic password verifier in a publicly visible proxy name.
    upstream_name = CHAIN_PREFIX + record.fetch("revision")
    upstream = original.merge("name" => upstream_name)
    endpoint = profile.reject { |key, _| key == "node" }.merge("name" => profile["node"], "dialer-proxy" => upstream_name)
    # TCP-only is deliberate: the fixed probe cannot certify UDP relay.
    endpoint["udp"] = false
    [upstream, endpoint]
  end

  def verify_chains(config, model, runtime: false)
    return true if model.chains.empty? && model.owned_chains.empty?
    proxies = chain_proxies(config).each_with_object({}) { |item, index| index[item["name"]] = item }
    raise "CHAIN_OWNERSHIP" unless model.chains.map { |item| item["node"] }.sort == model.owned_chains.map { |item| item["node"] }.sort
    originals = model.owned_chains.each_with_object({}) { |item, result| result[item["node"]] = item }
    model.chains.each do |profile|
      record = originals.fetch(profile["node"])
      pair = chain_pair(profile, record)
      upstream_name = pair.first["name"]
      raise "CHAIN_REFERENCE" if config.fetch("proxy-groups", []).any? do |group|
        group["include-all"] || group["include-all-proxies"] || Array(group["proxies"]).include?(upstream_name)
      end
      raise "CHAIN_REFERENCE" if proxies.values.any? do |proxy|
        proxy["name"] != profile["node"] && proxy["dialer-proxy"] == upstream_name
      end
      pair.each do |expected|
        actual = proxies[expected["name"]]
        valid = if runtime
                  actual.is_a?(Hash) && expected.all? { |key, value| actual[key] == value } &&
                    actual["dialer-proxy"] == expected["dialer-proxy"] &&
                    !(expected["tls"] == true && expected["skip-cert-verify"] != true && actual["skip-cert-verify"] == true)
                else
                  actual == expected
                end
        raise "CHAIN_DRIFT" unless valid
      end
    end
    true
  end

  def render_chains(config, old, desired, remove_owned:)
    return false if old.chains.empty? && desired.chains.empty?
    proxies = chain_proxies(config)
    if remove_owned
      verify_chains(config, old)
      old.chains.each do |profile|
        record = old.owned_chains.find { |item| item["node"] == profile["node"] }
        original = chain_original(record)
        upstream, = chain_pair(profile, record)
        proxies[proxies.index { |item| item["name"] == profile["node"] }] = original
        proxies.delete_if { |item| item["name"] == upstream["name"] }
      end
    end
    raise "CHAIN_RESERVED" if proxies.any? { |item| item["name"].start_with?(CHAIN_PREFIX) }
    if !desired.chains.empty? && config.fetch("proxy-groups", []).any? { |item| item["include-all"] || item["include-all-proxies"] }
      raise "CHAIN_INCLUDE_ALL"
    end
    names = proxies.map { |item| item["name"] } + config.fetch("proxy-groups", []).map { |item| item["name"] }
    desired.owned_chains = desired.chains.map do |profile|
      index = proxies.index { |item| item["name"] == profile["node"] }
      raise "CHAIN_NODE_MISSING" unless index
      original = chain_source(profile["node"], proxies[index])
      previous = old.owned_chains.find { |item| item["node"] == profile["node"] }
      same_version = previous && previous["original"] == original && old.chains.include?(profile)
      record = {"node" => profile["node"], "original" => original,
                "revision" => same_version ? previous["revision"] : chain_revision}
      upstream, endpoint = chain_pair(profile, record)
      raise "CHAIN_COLLISION" if names.include?(upstream["name"]) || names.count(profile["node"]) != 1
      proxies[index] = endpoint
      proxies << upstream
      record
    end
    true
  end

  def chain_request(state_value, patch)
    raise "CHAIN_REQUEST" unless patch.is_a?(Hash)
    model = parse_state(state_value)
    case patch["operation"]
    when "remove"
      raise "CHAIN_REQUEST" unless patch.keys.sort == %w[node operation]
      node = chain_name(patch["node"])
      raise "CHAIN_NOT_FOUND" unless model.chains.any? { |item| item["node"] == node }
      model.chains = model.chains.reject { |item| item["node"] == node }
    when "upsert"
      raise "CHAIN_REQUEST" unless patch.keys.sort == %w[chain operation] && patch["chain"].is_a?(Hash)
      previous = model.chains.find { |item| item["node"] == patch["chain"]["node"] }
      profile = chain_profile(patch["chain"], old: previous)
      model.chains = model.chains.reject { |item| item["node"] == profile["node"] } + [profile]
    else raise "CHAIN_OPERATION"
    end
    raise "CHAIN_COUNT" if model.chains.length > CHAIN_MAX
    model.chain_explicit = true
    model.owned_chains = []
    state_bytes(model, [], [], [], [])
  end

  def chain_view(config_bytes, state_value)
    config = safe_yaml(config_bytes)
    model = parse_state(state_value)
    verify_chains(config, model)
    owned = model.owned_chains.each_with_object({}) { |item, map| map[item["node"]] = item["original"] }
    nodes = chain_proxies(config).each_with_object([]) do |item, entries|
      next if item["name"].start_with?(CHAIN_PREFIX)
      original = owned.fetch(item["name"], item)
      begin
        chain_source(item["name"], original)
        entries << {"name" => item["name"], "type" => original["type"]}
      rescue StandardError
        nil
      end
    end
    profiles = model.chains.map { |item| item.reject { |key, _| key == "password" }.merge("has_password" => !!item["password"]) }
    {"ok" => true, "nodes" => nodes, "chains" => profiles,
     "config_sha256" => Digest::SHA256.hexdigest(config_bytes), "state_sha256" => Digest::SHA256.hexdigest(state_value)}
  end

  def chain_test(config_bytes, runtime_bytes, state_value, node)
    chain_name(node)
    model = parse_state(state_value)
    profile = model.chains.find { |item| item["node"] == node }
    raise "CHAIN_NOT_FOUND" unless profile
    result = {"ok" => true, "node" => node, "configuration" => "FAIL", "runtime" => "UNKNOWN",
              "upstream" => "UNKNOWN", "chain" => "UNKNOWN", "verdict" => "UNKNOWN"}
    begin
      verify_chains(safe_yaml(config_bytes), model)
      result["configuration"] = "PASS"
    rescue StandardError
      return result.merge("verdict" => "FAIL")
    end
    runtime = safe_yaml(runtime_bytes)
    begin
      verify_chains(runtime, model, runtime: true)
    rescue StandardError
      return result.merge("runtime" => "FAIL", "verdict" => "FAIL")
    end
    record = model.owned_chains.find { |item| item["node"] == node }
    upstream, = chain_pair(profile, record)
    upstream_name = upstream["name"]
    begin
      before = controller_proxies(runtime)
      live = before[node]
      if !live.is_a?(Hash) || !before[upstream_name].is_a?(Hash)
        return result.merge("runtime" => "FAIL", "verdict" => "FAIL")
      end
      linkage = live["dialer-proxy"]
      upstream_linkage = before[upstream_name]["dialer-proxy"]
      result["runtime"] = if linkage.nil? || upstream_linkage.nil?
                            "UNKNOWN"
                          elsif linkage == upstream_name && upstream_linkage == ""
                            "PASS"
                          else "FAIL"
                          end
      return result.merge("verdict" => "FAIL") if result["runtime"] == "FAIL"
      threads = [["upstream", upstream_name], ["chain", node]].map do |label, name|
        Thread.new do
          reachable = controller_delay(runtime, name)
          [label, reachable.nil? ? "UNKNOWN" : (reachable ? "REACHABLE" : "UNREACHABLE")]
        end
      end
      threads.each { |thread| label, value = thread.value; result[label] = value }
      after = controller_proxies(runtime)
      stable = [node, upstream_name].all? do |name|
        before[name].is_a?(Hash) && after[name].is_a?(Hash) && before[name]["id"].is_a?(String) &&
          !before[name]["id"].empty? && before[name]["id"] == after[name]["id"] &&
          before[name]["dialer-proxy"] == after[name]["dialer-proxy"]
      end
      result["runtime"] = "UNKNOWN" unless stable
      result["verdict"] = if result["chain"] == "UNREACHABLE"
                            "FAIL"
                          elsif result["runtime"] == "PASS" && result["upstream"] == "REACHABLE" && result["chain"] == "REACHABLE"
                            "PASS"
                          else "UNKNOWN"
                          end
    rescue StandardError
      result["runtime"] = "UNKNOWN"
    end
    result
  end

  # Router Ruby installations do not necessarily ship the json extension.
  def chain_json(value)
    case value
    when Hash then "{" + value.map { |key, item| chain_json(key.to_s) + ":" + chain_json(item) }.join(",") + "}"
    when Array then "[" + value.map { |item| chain_json(item) }.join(",") + "]"
    when String
      raise "CHAIN_JSON" unless value.valid_encoding?
      '"' + value.gsub(/["\\\x00-\x1f]/) { |char| char == '"' ? '\\"' : (char == "\\" ? '\\\\' : format("\\u%04x", char.ord)) } + '"'
    when Integer then value.to_s
    when TrueClass then "true"
    when FalseClass then "false"
    when NilClass then "null"
    else raise "CHAIN_JSON"
    end
  end

  # Values are validated strings (or arrays of strings); a temporary index keeps
  # membership checks linear without sorting, deduplicating, or mutating state.
  def membership_index(values)
    values.each_with_object({}) { |value, index| index[value] = true }
  end

  def parse_state(bytes, request: false)
    return Model.new([], [], [], [], [], [], [], [], [], [], false) if bytes.nil? || bytes.empty?
    raise "STATE_SIZE" if bytes.bytesize > 1024 * 1024
    # File.binread returns ASCII-8BIT; decode before comparing non-ASCII policy
    # names to YAML strings. Reject malformed UTF-8 rather than repairing it.
    text = bytes.dup.force_encoding(Encoding::UTF_8)
    raise "STATE_ENCODING" unless text.valid_encoding?
    lines = text.lines.map { |line| line.chomp }
    raise "STATE_VERSION" unless lines.shift == VERSION
    rules = []
    filters = []
    supplemental_rules = []
    supplemental_filters = []
    owned_rules = []
    owned_filters = []
    owned_supplemental_rules = []
    owned_supplemental_filters = []
    chains = []
    owned_chains = []
    chain_explicit = false
    lines.each do |line|
      next if line.empty?
      fields = line.split("\t", -1)
      tag = fields.shift
      case tag
      when "CHAIN_SET"
        raise "CHAIN_SET" unless fields.empty? && !chain_explicit
        chain_explicit = true
      when "CHAIN"
        raise "CHAIN_FIELDS" unless fields.length == 1
        chains << chain_profile(chain_record(fields[0]))
      when "OWNED_CHAIN"
        raise "REQUEST_OWNERSHIP" if request
        raise "CHAIN_FIELDS" unless fields.length == 1
        record = chain_record(fields[0])
        chain_original(record)
        owned_chains << record
      when "RULE" then rules << normalize_rule(fields)
      when "FAKE"
        raise "FAKE_FIELDS" unless fields.length == 1
        filters << fake_filter(fields[0])
      when "SUPPLEMENT_RULE"
        raise "SUPPLEMENT_FIELDS" unless fields.length == 1
        supplemental_rules << supplemental_rule(fields[0])
      when "SUPPLEMENT_FAKE"
        raise "SUPPLEMENT_FIELDS" unless fields.length == 1
        supplemental_filters << supplemental_filter(fields[0])
      when "OWNED_RULE"
        raise "REQUEST_OWNERSHIP" if request
        owned_rules << normalize_rule(fields)
      when "OWNED_FAKE"
        raise "REQUEST_OWNERSHIP" if request
        raise "FAKE_FIELDS" unless fields.length == 1
        owned_filters << fake_filter(fields[0])
      when "OWNED_SUPPLEMENT_RULE"
        raise "REQUEST_OWNERSHIP" if request
        raise "SUPPLEMENT_FIELDS" unless fields.length == 1
        owned_supplemental_rules << supplemental_rule(fields[0])
      when "OWNED_SUPPLEMENT_FAKE"
        raise "REQUEST_OWNERSHIP" if request
        raise "SUPPLEMENT_FIELDS" unless fields.length == 1
        owned_supplemental_filters << supplemental_filter(fields[0])
      else raise "STATE_TAG"
      end
    end
    raise "RULE_COUNT" if rules.length > MAX_ITEMS || owned_rules.length > MAX_ITEMS
    raise "FILTER_COUNT" if filters.length > MAX_ITEMS || owned_filters.length > MAX_ITEMS
    raise "SUPPLEMENT_RULE_COUNT" if supplemental_rules.length > MAX_SUPPLEMENT_ITEMS || owned_supplemental_rules.length > MAX_SUPPLEMENT_ITEMS
    raise "SUPPLEMENT_FILTER_COUNT" if supplemental_filters.length > MAX_SUPPLEMENT_ITEMS || owned_supplemental_filters.length > MAX_SUPPLEMENT_ITEMS
    raise "RULE_DUPLICATE" unless rules.map { |rule| rule[0, 2] }.uniq.length == rules.length
    raise "FILTER_DUPLICATE" unless filters.uniq.length == filters.length
    raise "OWNED_RULE_DUPLICATE" unless owned_rules.uniq.length == owned_rules.length
    raise "OWNED_FILTER_DUPLICATE" unless owned_filters.uniq.length == owned_filters.length
    raise "SUPPLEMENT_RULE_DUPLICATE" unless supplemental_rules.uniq.length == supplemental_rules.length
    raise "SUPPLEMENT_FILTER_DUPLICATE" unless supplemental_filters.uniq.length == supplemental_filters.length
    raise "OWNED_SUPPLEMENT_RULE_DUPLICATE" unless owned_supplemental_rules.uniq.length == owned_supplemental_rules.length
    raise "OWNED_SUPPLEMENT_FILTER_DUPLICATE" unless owned_supplemental_filters.uniq.length == owned_supplemental_filters.length
    rule_index = membership_index(rules)
    filter_index = membership_index(filters)
    supplement_rule_index = membership_index(supplemental_rules)
    supplement_filter_index = membership_index(supplemental_filters)
    raise "OWNED_RULE_SCOPE" unless owned_rules.all? { |rule| rule_index.key?(rule) }
    raise "OWNED_FILTER_SCOPE" unless owned_filters.all? { |filter| filter_index.key?(filter) }
    raise "OWNED_SUPPLEMENT_RULE_SCOPE" unless owned_supplemental_rules.all? { |rule| supplement_rule_index.key?(rule) }
    raise "OWNED_SUPPLEMENT_FILTER_SCOPE" unless owned_supplemental_filters.all? { |filter| supplement_filter_index.key?(filter) }
    structured_matchers = rules.map { |rule| rule.first(2) }
    supplement_matchers = supplemental_rules.map { |rule| rule_matcher(rule) }
    raise "SUPPLEMENT_RULE_MATCHER_CONFLICT" unless (structured_matchers + supplement_matchers).uniq.length == structured_matchers.length + supplement_matchers.length
    normalized_supplement_filters = supplemental_filters.each_with_object([]) do |filter, values|
      begin
        values << fake_filter(filter)
      rescue StandardError
        nil
      end
    end
    raise "SUPPLEMENT_FILTER_CONFLICT" unless (filters + normalized_supplement_filters).uniq.length == filters.length + normalized_supplement_filters.length
    raise "CHAIN_COUNT" if chains.length > CHAIN_MAX || owned_chains.length > CHAIN_MAX
    [chains, owned_chains].each do |items|
      raise "CHAIN_DUPLICATE" unless items.map { |item| item["node"] }.uniq.length == items.length
    end
    raise "CHAIN_SET" if !chains.empty? && !chain_explicit
    raise "CHAIN_OWNERSHIP" if !request && chains.map { |item| item["node"] }.sort != owned_chains.map { |item| item["node"] }.sort
    Model.new(rules, filters, supplemental_rules, supplemental_filters, owned_rules, owned_filters,
              owned_supplemental_rules, owned_supplemental_filters, chains, owned_chains, chain_explicit)
  end

  def rule_text(rule)
    rule.join(",")
  end

  def rule_matcher(text)
    fields = text.split(",", -1)
    raise "CONFIG_RULE" unless fields.length >= 3 && RULE_TYPES.include?(fields[0].upcase)
    normalized = normalize_rule(fields.first(3))
    normalized.first(2)
  end

  def remove_once(array, value)
    index = array.index(value)
    array.delete_at(index) if index
  end

  def state_bytes(desired, owned_rules, owned_filters, owned_supplemental_rules, owned_supplemental_filters)
    lines = [VERSION]
    lines << "CHAIN_SET" if desired.chain_explicit || (desired.chains && !desired.chains.empty?)
    (desired.chains || []).each { |item| lines << ["CHAIN", chain_encoded(item)].join("\t") }
    (desired.owned_chains || []).each { |item| lines << ["OWNED_CHAIN", chain_encoded(item)].join("\t") }
    desired.rules.each { |rule| lines << (["RULE"] + rule).join("\t") }
    desired.filters.each { |filter| lines << ["FAKE", filter].join("\t") }
    desired.supplemental_rules.each { |rule| lines << ["SUPPLEMENT_RULE", rule].join("\t") }
    desired.supplemental_filters.each { |filter| lines << ["SUPPLEMENT_FAKE", filter].join("\t") }
    owned_rules.each { |rule| lines << (["OWNED_RULE"] + rule).join("\t") }
    owned_filters.each { |filter| lines << ["OWNED_FAKE", filter].join("\t") }
    owned_supplemental_rules.each { |rule| lines << ["OWNED_SUPPLEMENT_RULE", rule].join("\t") }
    owned_supplemental_filters.each { |filter| lines << ["OWNED_SUPPLEMENT_FAKE", filter].join("\t") }
    bytes = lines.join("\n") + "\n"
    raise "STATE_SIZE" if bytes.bytesize > 1024 * 1024
    bytes
  end

  def render(config_bytes, old_state_bytes, request_bytes, remove_owned: true)
    config = safe_yaml(config_bytes)
    raise "CONFIG_ROOT" unless config.is_a?(Hash)
    groups = config["proxy-groups"]
    rules = config["rules"]
    dns = config["dns"]
    raise "CONFIG_GROUPS" unless groups.is_a?(Array) && groups.all? { |item| item.is_a?(Hash) && item["name"].is_a?(String) && !item["name"].empty? && !item["name"].match?(/[\t\r\n,]/) }
    raise "CONFIG_RULES" unless rules.is_a?(Array) && rules.all? { |item| item.is_a?(String) }
    raise "CONFIG_DNS" unless dns.is_a?(Hash) && dns["fake-ip-filter"].is_a?(Array) && dns["fake-ip-filter"].all? { |item| item.is_a?(String) }
    group_names = groups.map { |item| item["name"] }
    raise "GROUP_DUPLICATE" unless group_names.uniq.length == group_names.length
    old = parse_state(old_state_bytes)
    desired = parse_state(request_bytes, request: true)
    unless desired.chain_explicit
      desired.chains = old.chains
      desired.chain_explicit = old.chain_explicit
    end
    desired.rules.each { |rule| raise "POLICY_UNKNOWN" unless rule[2] == "DIRECT" || group_names.include?(rule[2]) }
    desired.supplemental_rules.each do |rule|
      policy = rule.split(",", -1)[2]
      raise "POLICY_UNKNOWN" unless policy == "DIRECT" || group_names.include?(policy)
    end
    if remove_owned && desired.rules == old.rules && desired.filters == old.filters &&
       desired.supplemental_rules == old.supplemental_rules && desired.supplemental_filters == old.supplemental_filters && desired.chains == old.chains
      begin
        verify(config_bytes, old_state_bytes)
        desired.owned_chains = old.owned_chains
        output_state = state_bytes(desired, old.owned_rules, old.owned_filters,
                                   old.owned_supplemental_rules, old.owned_supplemental_filters)
        return Result.new(config_bytes, output_state, desired.rules.length + desired.supplemental_rules.length,
                          desired.filters.length + desired.supplemental_filters.length,
                          Digest::SHA256.hexdigest(config_bytes))
      rescue StandardError => error
        # A desired item that was previously supplied by the subscription is
        # intentionally unowned.  If that baseline item later disappears,
        # fall through and take ownership instead of trapping the user in an
        # unreadable/unrepairable state.  Owned drift remains fail closed.
        raise unless %w[VERIFY_RULE VERIFY_FILTER VERIFY_SUPPLEMENT_RULE VERIFY_SUPPLEMENT_FILTER].include?(error.message)
      end
    end
    changed = render_chains(config, old, desired, remove_owned: remove_owned)
    if remove_owned
      owned_text = old.owned_rules.map { |rule| rule_text(rule) } + old.owned_supplemental_rules
      unless owned_text.empty?
        raise "OWNED_RULE_DRIFT" unless rules.first(owned_text.length) == owned_text
        rules.shift(owned_text.length)
        changed = true
      end
      old.owned_filters.each do |filter|
        raise "OWNED_FAKE_DRIFT" unless remove_once(dns["fake-ip-filter"], filter)
        changed = true
      end
      old.owned_supplemental_filters.each do |filter|
        raise "OWNED_SUPPLEMENT_FAKE_DRIFT" unless remove_once(dns["fake-ip-filter"], filter)
        changed = true
      end
    end
    # 已由订阅/主配置提供的同字节规则只记录为“期望存在”，不重复插入、
    # 不取得所有权；这样双子网取并集时能多不删少补，也能避免重复规则。
    baseline_rule_forms = Hash.new { |hash, key| hash[key] = [] }
    rules.each do |existing|
      next unless existing.is_a?(String)
      begin
        matcher = rule_matcher(existing)
        baseline_rule_forms[matcher] << existing
      rescue StandardError
        nil
      end
    end
    owned_rules = desired.rules.reject do |rule|
      text = rule_text(rule)
      matching = baseline_rule_forms[rule.first(2)]
      raise "BASELINE_MATCHER_CONFLICT" if matching.any? { |existing| existing != text }
      next true if matching.include?(text)
      false
    end.map(&:dup)
    owned_supplemental_rules = desired.supplemental_rules.reject do |rule|
      matching = baseline_rule_forms[rule_matcher(rule)]
      raise "BASELINE_MATCHER_CONFLICT" if matching.any? { |existing| existing != rule }
      matching.include?(rule)
    end
    custom_rules = owned_rules.map { |rule| rule_text(rule) } + owned_supplemental_rules
    changed = true unless custom_rules.empty?
    config["rules"] = custom_rules + rules
    owned_filters = []
    baseline_filter_forms = Hash.new { |hash, key| hash[key] = [] }
    dns["fake-ip-filter"].each do |existing|
      begin
        baseline_filter_forms[fake_filter(existing)] << existing if existing.is_a?(String)
      rescue StandardError
        nil
      end
    end
    desired.filters.each do |filter|
      matching = baseline_filter_forms[filter]
      raise "BASELINE_FILTER_CONFLICT" if matching.any? { |existing| existing != filter }
      next if matching.include?(filter)
      dns["fake-ip-filter"] << filter
      owned_filters << filter
      changed = true
    end
    owned_supplemental_filters = []
    desired.supplemental_filters.each do |filter|
      next if dns["fake-ip-filter"].include?(filter)
      dns["fake-ip-filter"] << filter
      owned_supplemental_filters << filter
      changed = true
    end
    output = changed ? YAML.dump(config) : config_bytes
    Result.new(output, state_bytes(desired, owned_rules, owned_filters, owned_supplemental_rules,
                                   owned_supplemental_filters),
               desired.rules.length + desired.supplemental_rules.length,
               desired.filters.length + desired.supplemental_filters.length, Digest::SHA256.hexdigest(output))
  end

  def inspect_state(config_bytes, state_bytes_value)
    config = safe_yaml(config_bytes)
    raise "CONFIG_ROOT" unless config.is_a?(Hash) && config["proxy-groups"].is_a?(Array) &&
                               config["rules"].is_a?(Array) && config.dig("dns", "fake-ip-filter").is_a?(Array)
    model = parse_state(state_bytes_value)
    verify_ownership(config_bytes, state_bytes_value)
    groups = config["proxy-groups"].map { |item| item.is_a?(Hash) ? item["name"] : nil }
    raise "CONFIG_GROUPS" unless groups.all? { |name| name.is_a?(String) && !name.empty? && !name.match?(/[\t\r\n,]/) }
    raise "GROUP_DUPLICATE" unless groups.uniq.length == groups.length
    raise "POLICY_UNKNOWN" unless model.rules.all? { |rule| rule[2] == "DIRECT" || groups.include?(rule[2]) }
    raise "POLICY_UNKNOWN" unless model.supplemental_rules.all? do |rule|
      policy = rule.split(",", -1)[2]
      policy == "DIRECT" || groups.include?(policy)
    end
    lines = groups.map { |name| ["GROUP", name].join("\t") }
    model.rules.each { |rule| lines << (["RULE"] + rule).join("\t") }
    model.filters.each { |filter| lines << ["FAKE", filter].join("\t") }
    model.supplemental_rules.each { |rule| lines << ["SUPPLEMENT_RULE", rule].join("\t") }
    model.supplemental_filters.each { |filter| lines << ["SUPPLEMENT_FAKE", filter].join("\t") }
    model.owned_rules.each { |rule| lines << (["OWNED_RULE"] + rule).join("\t") }
    model.owned_filters.each { |filter| lines << ["OWNED_FAKE", filter].join("\t") }
    model.owned_supplemental_rules.each { |rule| lines << ["OWNED_SUPPLEMENT_RULE", rule].join("\t") }
    model.owned_supplemental_filters.each { |filter| lines << ["OWNED_SUPPLEMENT_FAKE", filter].join("\t") }
    config["rules"].each do |rule|
      raise "CONFIG_RULE" unless rule.is_a?(String) && !rule.match?(/[\t\r\n\0]/)
      lines << ["CONFIG_RULE", rule].join("\t")
    end
    config.dig("dns", "fake-ip-filter").each do |filter|
      raise "CONFIG_FAKE" unless filter.is_a?(String) && !filter.match?(/[\t\r\n\0]/)
      lines << ["CONFIG_FAKE", filter].join("\t")
    end
    lines.join("\n") + "\n"
  end

  def verify_ownership(config_bytes, state_bytes_value)
    config = safe_yaml(config_bytes)
    raise "CONFIG_ROOT" unless config.is_a?(Hash) && config["rules"].is_a?(Array) && config["dns"].is_a?(Hash) && config["dns"]["fake-ip-filter"].is_a?(Array)
    model = parse_state(state_bytes_value)
    rules = config["rules"]
    filters = config["dns"]["fake-ip-filter"]
    verify_chains(config, model)
    owned_rule_text = model.owned_rules.map { |rule| rule_text(rule) } + model.owned_supplemental_rules
    raise "VERIFY_OWNED_RULE" unless rules.first(owned_rule_text.length) == owned_rule_text
    filter_index = membership_index(filters)
    raise "VERIFY_OWNED_FILTER" unless model.owned_filters.all? { |filter| filter_index.key?(filter) }
    raise "VERIFY_OWNED_SUPPLEMENT_FILTER" unless model.owned_supplemental_filters.all? { |filter| filter_index.key?(filter) }
    true
  end

  def verify(config_bytes, state_bytes_value)
    verify_ownership(config_bytes, state_bytes_value)
    config = safe_yaml(config_bytes)
    model = parse_state(state_bytes_value)
    rules = config["rules"]
    filters = config["dns"]["fake-ip-filter"]
    rule_index = membership_index(rules)
    filter_index = membership_index(filters)
    raise "VERIFY_RULE" unless model.rules.all? { |rule| rule_index.key?(rule_text(rule)) }
    raise "VERIFY_FILTER" unless model.filters.all? { |filter| filter_index.key?(filter) }
    raise "VERIFY_SUPPLEMENT_RULE" unless model.supplemental_rules.all? { |rule| rule_index.key?(rule) }
    raise "VERIFY_SUPPLEMENT_FILTER" unless model.supplemental_filters.all? { |filter| filter_index.key?(filter) }
    true
  end

  def find_block(array, block)
    return 0 if block.empty?
    maximum = array.length - block.length
    return nil if maximum.negative?
    0.upto(maximum) { |index| return index if array[index, block.length] == block }
    nil
  end

  def verify_runtime(static_bytes, runtime_bytes, state_bytes_value)
    verify(static_bytes, state_bytes_value)
    static_config = safe_yaml(static_bytes)
    runtime_config = safe_yaml(runtime_bytes)
    model = parse_state(state_bytes_value)
    verify_chains(runtime_config, model, runtime: true)
    runtime_rules = runtime_config["rules"]
    runtime_filters = runtime_config.dig("dns", "fake-ip-filter")
    raise "RUNTIME_RULES" unless runtime_rules.is_a?(Array) && runtime_rules.all? { |item| item.is_a?(String) }
    raise "RUNTIME_FILTERS" unless runtime_filters.is_a?(Array) && runtime_filters.all? { |item| item.is_a?(String) }
    owned_text = model.owned_rules.map { |rule| rule_text(rule) } + model.owned_supplemental_rules
    static_rules = static_config["rules"]
    raise "RUNTIME_BASELINE_RULES" unless static_rules.is_a?(Array) && static_rules.all? { |item| item.is_a?(String) }
    prefix_length = [0, 44, 45].select { |length| length <= runtime_rules.length }.find do |length|
      prefix = runtime_rules.first(length)
      prefix.uniq.length == prefix.length && owned_text.none? { |rule| prefix.include?(rule) } &&
        (prefix + static_rules).uniq == runtime_rules
    end
    raise "RUNTIME_RULE_TRANSFORM" if prefix_length.nil?
    unless owned_text.empty?
      raise "RUNTIME_CUSTOM_BLOCK" unless runtime_rules[prefix_length, owned_text.length] == owned_text
    end
    runtime_filter_index = membership_index(runtime_filters)
    raise "RUNTIME_FILTER" unless model.filters.all? { |filter| runtime_filter_index.key?(filter) }
    raise "RUNTIME_SUPPLEMENT_FILTER" unless model.supplemental_filters.all? { |filter| runtime_filter_index.key?(filter) }
    true
  end

  def proxy_sets(config)
    proxies = config["proxies"]
    groups = config["proxy-groups"]
    raise "HEALTH_PROXIES" unless proxies.is_a?(Array) && groups.is_a?(Array)
    names = proxies.map { |item| item.is_a?(Hash) ? item["name"] : nil }
    raise "HEALTH_PROXY_NAME" unless names.all? { |name| name.is_a?(String) && !name.empty? && !name.match?(/[\r\n\0]/) }
    raise "HEALTH_PROXY_DUPLICATE" unless names.uniq.length == names.length
    names = names.reject { |name| name.start_with?(CHAIN_PREFIX) }
    maying = groups.select { |group| group.is_a?(Hash) && MAYING_GROUPS.include?(group["name"]) }
                   .flat_map { |group| group["proxies"].is_a?(Array) ? group["proxies"] : [] }
                   .select { |name| names.include?(name) }.uniq
    raise "HEALTH_MAYING_GROUPS" unless maying.any?
    {"Maying" => maying, "Nexitally" => names - maying}
  end

  def controller_endpoint(config)
    value = config["external-controller"]
    raise "CONTROLLER" unless value.is_a?(String) && value.bytesize.between?(3, 128) && !value.match?(/[\r\n\0]/)
    host = nil
    port = nil
    if (match = value.match(/\A(?:127\.0\.0\.1|0\.0\.0\.0|\*):([1-9][0-9]{0,4})\z/))
      host = "127.0.0.1"
      port = match[1].to_i
    elsif (match = value.match(/\A\[(?:::1|::)\]:([1-9][0-9]{0,4})\z/))
      host = "[::1]"
      port = match[1].to_i
    end
    raise "CONTROLLER" unless host && port.between?(1, 65_535)
    "http://#{host}:#{port}"
  end

  def controller_delay(config, proxy, timeout_ms: 5_000)
    secret = config["secret"]
    raise "CONTROLLER_SECRET" unless secret.is_a?(String) && secret.bytesize.between?(1, 4096) && !secret.match?(/[\r\n\0]/)
    endpoint = "#{controller_endpoint(config)}/proxies/#{url_encode_component(proxy)}/delay" \
               "?timeout=#{timeout_ms}&url=#{url_encode_component(HEALTH_URL)}"
    command = ["curl", "-q", "-sS", "--max-time", "8", "-w", "\n%{http_code}", "-H", "@-", endpoint]
    output = nil
    status = nil
    IO.popen({"PATH" => "/usr/sbin:/usr/bin:/sbin:/bin"}, command, "r+", unsetenv_others: true) do |pipe|
      pipe.write("Authorization: Bearer #{secret}\n")
      pipe.close_write
      output = pipe.read(65_537)
    end
    status = $?
    return false unless output && output.bytesize <= 65_536
    body, code = output.rpartition("\n").values_at(0, 2)
    delay = body.match(/\A\s*\{\s*"delay"\s*:\s*((?:0|[1-9][0-9]*))\s*\}\s*\z/)
    status&.success? && code == "200" && !delay.nil?
  rescue Errno::EPIPE, IOError, SystemCallError
    false
  rescue RuntimeError => error
    return nil if %w[CONTROLLER CONTROLLER_SECRET].include?(error.message)
    raise
  end

  def selection_name(value, label)
    clean_field(value, label, 512).tap do |name|
      raise label if name.bytes.any? { |byte| byte < 0x20 }
    end
  end

  def curl_config_string(value)
    raise "CONTROLLER_REQUEST" unless value.is_a?(String) && value.valid_encoding?
    # A gsub replacement string interprets backslashes a second time. Use a
    # block so curl receives exactly the escaped bytes, including JSON bodies.
    escapes = {"\\" => "\\\\", '"' => '\\"', "\t" => "\\t", "\r" => "\\r", "\n" => "\\n"}
    escaped = value.gsub(/["\\\t\r\n]/) { |char| escapes.fetch(char) }
    %("#{escaped}")
  end

  def json_string(value)
    selection_name(value, "SELECTION_NAME").each_codepoint.map do |codepoint|
      case codepoint
      when 0x22 then '\\"'
      when 0x5c then "\\\\"
      else codepoint < 0x20 ? format("\\u%04x", codepoint) : codepoint.chr(Encoding::UTF_8)
      end
    end.join.then { |text| %("#{text}") }
  end

  def controller_request(config, method, path, body = nil)
    secret = config["secret"]
    raise "CONTROLLER_SECRET" unless secret.is_a?(String) && secret.bytesize.between?(1, 4096) && !secret.match?(/[\r\n\0]/)
    raise "CONTROLLER_REQUEST" unless %w[GET PUT].include?(method) && path.is_a?(String) && path.start_with?("/") && !path.match?(/[\r\n\0]/)
    endpoint = controller_endpoint(config) + path
    curl_config = [
      "silent", "show-error", "max-time = 10", "request = #{curl_config_string(method)}",
      "header = #{curl_config_string("Authorization: Bearer #{secret}")}"
    ]
    if body
      raise "CONTROLLER_REQUEST" unless method == "PUT" && body.is_a?(String) && body.bytesize <= 4096 && !body.match?(/[\r\n\0]/)
      curl_config << "header = #{curl_config_string("Content-Type: application/json")}" \
                  << "data-binary = #{curl_config_string(body)}"
    end
    output = nil
    IO.popen({"PATH" => "/usr/sbin:/usr/bin:/sbin:/bin"},
             ["curl", "-q", "--config", "-", "-w", "\n%{http_code}", endpoint], "r+", unsetenv_others: true) do |pipe|
      pipe.write(curl_config.join("\n") + "\n")
      pipe.close_write
      output = pipe.read(2 * 1024 * 1024 + 1)
    end
    status = $?
    raise "CONTROLLER_REQUEST" unless status&.success? && output && output.bytesize <= 2 * 1024 * 1024
    response_body, separator, code = output.rpartition("\n")
    raise "CONTROLLER_REQUEST" if separator.empty? || !code.match?(/\A[0-9]{3}\z/)
    [response_body, code]
  rescue Errno::EPIPE, IOError, SystemCallError
    raise "CONTROLLER_REQUEST"
  end

  def controller_proxies(config)
    body, code = controller_request(config, "GET", "/proxies")
    raise "CONTROLLER_RESPONSE" unless code == "200"
    parsed = StrictJson.new(body).parse
    proxies = parsed.is_a?(Hash) ? parsed["proxies"] : nil
    raise "CONTROLLER_RESPONSE" unless proxies.is_a?(Hash) && proxies.length <= 20_000
    proxies
  rescue StrictJson::ParseError
    raise "CONTROLLER_RESPONSE"
  end

  def selectable_groups(config)
    groups = config["proxy-groups"]
    raise "SELECTION_GROUPS" unless groups.is_a?(Array) && groups.length <= 4096
    names = groups.each_with_object([]) do |group, result|
      next unless group.is_a?(Hash) && group["type"] == "select"
      result << selection_name(group["name"], "SELECTION_GROUP")
    end
    raise "SELECTION_GROUPS" unless names.uniq.length == names.length
    names.sort
  end

  def encode_selection(value)
    [selection_name(value, "SELECTION_NAME")].pack("m0")
  end

  def decode_selection(value)
    raise "SELECTION_MANIFEST" unless value.is_a?(String) && value.bytesize.between?(4, 1024) &&
                                            value.match?(/\A[A-Za-z0-9+\/]+={0,2}\z/) && (value.bytesize % 4).zero?
    decoded = value.unpack1("m0")
    raise "SELECTION_MANIFEST" unless [decoded].pack("m0") == value
    decoded.force_encoding(Encoding::UTF_8)
    raise "SELECTION_MANIFEST" unless decoded.valid_encoding?
    selection_name(decoded, "SELECTION_MANIFEST")
  rescue ArgumentError
    raise "SELECTION_MANIFEST"
  end

  def selection_snapshot(config_bytes)
    config = safe_yaml(config_bytes)
    raise "SELECTION_CONFIG" unless config.is_a?(Hash)
    proxies = controller_proxies(config)
    selections = selectable_groups(config).to_h do |group|
      current = proxies[group]
      now = current.is_a?(Hash) ? current["now"] : nil
      all = current.is_a?(Hash) ? current["all"] : nil
      raise "SELECTION_RUNTIME" unless all.is_a?(Array) && all.length <= 20_000 &&
                                               all.all? { |name| name.is_a?(String) } && now.is_a?(String)
      selected = selection_name(now, "SELECTION_RUNTIME")
      members = all.map { |name| selection_name(name, "SELECTION_RUNTIME") }
      raise "SELECTION_RUNTIME" unless members.include?(selected)
      [group, selected]
    end
    lines = ["OPENCLASH_SYNC_SELECTIONS_V1"]
    selections.each { |group, selected| lines << ["SELECT", encode_selection(group), encode_selection(selected)].join("\t") }
    lines.join("\n") + "\n"
  end

  def parse_selection_manifest(bytes)
    raise "SELECTION_MANIFEST" unless bytes.is_a?(String) && bytes.bytesize.between?(30, 1024 * 1024)
    lines = bytes.split("\n", -1)
    raise "SELECTION_MANIFEST" unless lines.shift == "OPENCLASH_SYNC_SELECTIONS_V1" && lines.pop == "" && lines.length <= 4096
    selections = lines.to_h do |line|
      tag, group, selected, extra = line.split("\t", -1)
      raise "SELECTION_MANIFEST" unless tag == "SELECT" && group && selected && extra.nil?
      [decode_selection(group), decode_selection(selected)]
    end
    raise "SELECTION_MANIFEST" unless selections.length == lines.length
    selections
  end

  def selection_plan(config, manifest_bytes)
    desired = parse_selection_manifest(manifest_bytes)
    configured = selectable_groups(config)
    raise "SELECTION_GROUP_REMOVED" unless desired.keys.all? { |group| configured.include?(group) }
    proxies = controller_proxies(config)
    desired.each do |group, selected|
      current = proxies[group]
      all = current.is_a?(Hash) ? current["all"] : nil
      now = current.is_a?(Hash) ? current["now"] : nil
      raise "SELECTION_RUNTIME" unless all.is_a?(Array) && now.is_a?(String) && all.length <= 20_000 &&
                                               all.all? { |name| name.is_a?(String) }
      members = all.map { |name| selection_name(name, "SELECTION_RUNTIME") }
      selection_name(now, "SELECTION_RUNTIME")
      raise "SELECTION_MEMBER_REMOVED" unless members.include?(selected)
    end
    [desired, proxies]
  end

  def restore_selections(config_bytes, manifest_bytes, write: true)
    config = safe_yaml(config_bytes)
    raise "SELECTION_CONFIG" unless config.is_a?(Hash)
    desired, proxies = selection_plan(config, manifest_bytes)
    changed = desired.count do |group, selected|
      current = proxies.fetch(group).fetch("now")
      next false if current == selected
      raise "SELECTION_VERIFY" unless write
      body = "{\"name\":#{json_string(selected)}}"
      _response, code = controller_request(config, "PUT", "/proxies/#{url_encode_component(group)}", body)
      raise "SELECTION_RESTORE" unless code == "204"
      true
    end
    final = controller_proxies(config)
    raise "SELECTION_VERIFY" unless desired.all? do |group, selected|
      value = final[group]
      value.is_a?(Hash) && value["now"] == selected
    end
    [desired.length, changed]
  end


  def url_encode_component(value)
    clean_field(value, "URL_COMPONENT", 4096).bytes.map do |byte|
      if (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) ||
         [45, 46, 95, 126].include?(byte)
        byte.chr
      else
        format("%%%02X", byte)
      end
    end.join
  end

  def node_health(config_bytes, concurrency: 24)
    config = safe_yaml(config_bytes)
    raise "HEALTH_CONFIG" unless config.is_a?(Hash)
    sets = proxy_sets(config)
    names = sets.values.flatten.uniq
    queue = Queue.new
    names.each { |name| queue << name }
    passed = {}
    mutex = Mutex.new
    [concurrency, names.length].min.times.map do
      Thread.new do
        loop do
          name = queue.pop(true)
          result = controller_delay(config, name)
          mutex.synchronize { passed[name] = result }
        rescue ThreadError
          break
        end
      end
    end.each(&:join)
    raise "HEALTH_CONTROLLER" if names.any? { |name| !passed.key?(name) || passed[name].nil? }
    sets.transform_values { |provider_names| [provider_names.count { |name| passed[name] }, provider_names.length] }
  end

  def route_input_context(value)
    text = clean_field(value.strip, "ROUTE_INPUT", 2048)
    port = nil
    host = if (url = text.match(/\A(https?):\/\/([^\/?#]+)(?:[\/?#].*)?\z/i))
             scheme = url[1].downcase
             authority = url[2]
             raise "ROUTE_INPUT" if authority.include?("@")
             authority_match = if authority.start_with?("[")
                                 authority.match(/\A\[([0-9a-f:]+)\](?::([0-9]+))?\z/i)
                               else
                                 authority.match(/\A([^:]+)(?::([0-9]+))?\z/)
                               end
             raise "ROUTE_INPUT" unless authority_match
             port = authority_match[2] ? decimal(authority_match[2], 65_535) : (scheme == "https" ? 443 : 80)
             raise "ROUTE_INPUT" unless port.between?(1, 65_535)
             authority_match[1]
           else
             text
           end
    normalized = host.downcase.sub(/\.\z/, "")
    begin
      [ip_address(normalized, "ROUTE_INPUT"), nil, port]
    rescue RuntimeError
      raise "ROUTE_INPUT" unless DOMAIN.match?(normalized)
      [nil, normalized, port]
    end
  rescue ArgumentError
    raise "ROUTE_INPUT"
  end

  def port_match?(spec, port)
    return false unless port && spec.is_a?(String)
    if spec.match?(/\A[0-9]+\z/)
      spec.to_i == port
    elsif (match = spec.match(/\A([0-9]+)-([0-9]+)\z/))
      first = match[1].to_i
      last = match[2].to_i
      first.between?(1, 65_535) && last.between?(first, 65_535) && port.between?(first, last)
    else
      raise "ROUTE_RULES"
    end
  end

  def route_decision(config_bytes, input, source_ip: nil)
    config = safe_yaml(config_bytes)
    rules = config.is_a?(Hash) ? config["rules"] : nil
    raise "ROUTE_RULES" unless rules.is_a?(Array) && rules.all? { |rule| rule.is_a?(String) }
    address, hostname, destination_port = route_input_context(input)
    source_address = source_ip.nil? ? nil : ip_address(source_ip, "ROUTE_SOURCE")
    uncertain = false
    rules.each do |text|
      fields = text.split(",")
      kind = fields[0]
      case kind
      when "DOMAIN"
        return [clean_field(fields[2], "ROUTE_POLICY", 128), text, uncertain] if hostname && fields.length >= 3 && hostname == fields[1].downcase.sub(/\.\z/, "")
      when "DOMAIN-SUFFIX"
        suffix = fields[1]&.downcase&.sub(/\.\z/, "")
        return [clean_field(fields[2], "ROUTE_POLICY", 128), text, uncertain] if hostname && suffix && (hostname == suffix || hostname.end_with?(".#{suffix}"))
      when "DOMAIN-KEYWORD"
        keyword = fields[1]&.downcase
        return [clean_field(fields[2], "ROUTE_POLICY", 128), text, uncertain] if hostname && fields.length >= 3 && keyword && !keyword.empty? && hostname.include?(keyword)
      when "IP-CIDR", "IP-CIDR6"
        if address && fields.length >= 3
          begin
            return [clean_field(fields[2], "ROUTE_POLICY", 128), text, uncertain] if cidr_include?(fields[1], address, kind)
          rescue RuntimeError
            raise "ROUTE_RULES"
          end
        elsif hostname && !fields.drop(3).include?("no-resolve")
          uncertain = true
        end
      when "SRC-IP-CIDR"
        if source_address && fields.length >= 3
          begin
            return [clean_field(fields[2], "ROUTE_POLICY", 128), text, uncertain] if cidr_include?(fields[1], source_address)
          rescue RuntimeError
            raise "ROUTE_RULES"
          end
        elsif source_address.nil?
          uncertain = true
        end
      when "DST-PORT"
        if destination_port
          return [clean_field(fields[2], "ROUTE_POLICY", 128), text, uncertain] if fields.length >= 3 && port_match?(fields[1], destination_port)
        else
          uncertain = true
        end
      when "SRC-PORT", "PROCESS-NAME", "PROCESS-PATH", "GEOIP", "GEOSITE", "RULE-SET"
        uncertain = true
      when "MATCH"
        return [clean_field(fields[1], "ROUTE_POLICY", 128), text, uncertain] if fields.length == 2
      else
        uncertain = true
      end
    end
    [nil, nil, true]
  end

  def direct_health
    env = {"PATH" => "/usr/sbin:/usr/bin:/sbin:/bin", "HTTP_PROXY" => "", "HTTPS_PROXY" => "", "ALL_PROXY" => ""}
    system(env, "curl", "-q", "--noproxy", "*", "-fsS", "--connect-timeout", "4", "--max-time", "8", "-o", File::NULL,
           "https://www.gstatic.com/generate_204", unsetenv_others: true, out: File::NULL, err: File::NULL) ||
      system(env, "curl", "-q", "--noproxy", "*", "-fsS", "--connect-timeout", "4", "--max-time", "8", "-o", File::NULL,
             "https://cp.cloudflare.com/generate_204", unsetenv_others: true, out: File::NULL, err: File::NULL)
  end

  def prune_backups(root, current = nil, now: Time.now, expected_uid: 0)
    root_info = File.lstat(root)
    raise "BACKUP_ROOT" unless root_info.directory? && !root_info.symlink? && root_info.uid == expected_uid &&
                               (root_info.mode & 0o7777) == 0o700
    root_real = File.realpath(root)
    current_real = current && File.realpath(current)
    raise "BACKUP_CURRENT" if current_real && File.dirname(current_real) != root_real
    allowed = %w[main.yaml customizations.state runtime.before.yaml selections.before COMMITTED RESTART ROLLED_BACK].freeze
    removed = 0
    Dir.children(root).sort.each do |name|
      next unless name.match?(/\A[0-9]{8}T[0-9]{6}Z-[0-9]+-(?:stage-main|manual-write|converter-apply|rollback|custom-apply)\z/)
      path = File.join(root_real, name)
      next if current_real && path == current_real
      info = File.lstat(path)
      next unless info.directory? && !info.symlink? && info.uid == expected_uid && (info.mode & 0o7777) == 0o700
      entries = Dir.children(path)
      next unless entries.include?("COMMITTED") && (entries - allowed).empty?
      trusted = entries.all? do |entry|
        item = File.lstat(File.join(path, entry))
        item.file? && !item.symlink? && item.uid == expected_uid && item.nlink == 1 && (item.mode & 0o7777) == 0o600
      end
      next unless trusted
      marker = File.join(path, "COMMITTED")
      marker_bytes = File.binread(marker, 64 * 1024)
      next unless marker_bytes.lines.any? { |line| %w[STATUS=COMMITTED COMMITTED=PASS].include?(line.chomp) }
      epochs = marker_bytes.lines.map { |line| line.match(/\ACOMMITTED_AT_EPOCH=([0-9]+)\n?\z/)&.[](1) }.compact
      next unless epochs.length == 1 && epochs.first.to_i.positive? && now.to_i - epochs.first.to_i >= 7 * 24 * 60 * 60
      entries.each { |entry| File.unlink(File.join(path, entry)) }
      Dir.rmdir(path)
      removed += 1
    rescue Errno::ENOENT, Errno::ENOTEMPTY
      next
    end
    File.open(root_real) { |directory| directory.fsync }
    removed
  end
end

if $PROGRAM_NAME == __FILE__
  mode = ARGV.shift
  case mode
  when "render"
    raise "ARGS" unless ARGV.length == 6
    config_path, old_state_path, request_path, output_path, output_state_path, ownership_mode = ARGV
    raise "OWNERSHIP_MODE" unless %w[remove overlay].include?(ownership_mode)
    result = OpenClashCustomizer.render(File.binread(config_path), File.exist?(old_state_path) ? File.binread(old_state_path) : "", File.binread(request_path), remove_owned: ownership_mode == "remove")
    raise "OUTPUT_EXISTS" if File.exist?(output_path) || File.exist?(output_state_path)
    File.binwrite(output_path, result.config)
    File.binwrite(output_state_path, result.state)
    puts "CUSTOMIZER=PASS"
    puts "RULE_COUNT=#{result.rule_count}"
    puts "FAKE_FILTER_COUNT=#{result.filter_count}"
    puts "CONFIG_SHA256=#{result.sha256}"
  when "chain-request"
    raise "ARGS" unless ARGV.length == 3
    state = File.exist?(ARGV[0]) ? File.binread(ARGV[0]) : ""
    patch = OpenClashCustomizer::StrictJson.new(File.binread(ARGV[1])).parse
    output = OpenClashCustomizer.chain_request(state, patch)
    File.open(ARGV[2], File::WRONLY | File::CREAT | File::EXCL, 0600) { |file| file.write(output) }
  when "chain-read"
    raise "ARGS" unless ARGV.length == 2
    state = File.exist?(ARGV[1]) ? File.binread(ARGV[1]) : ""
    puts OpenClashCustomizer.chain_json(OpenClashCustomizer.chain_view(File.binread(ARGV[0]), state))
  when "chain-test"
    raise "ARGS" unless ARGV.length == 4
    state = File.exist?(ARGV[2]) ? File.binread(ARGV[2]) : ""
    node = OpenClashCustomizer::StrictJson.new(File.binread(ARGV[3])).parse
    puts OpenClashCustomizer.chain_json(OpenClashCustomizer.chain_test(File.binread(ARGV[0]), File.binread(ARGV[1]), state, node))
  when "inspect"
    raise "ARGS" unless ARGV.length == 2
    puts OpenClashCustomizer.inspect_state(File.binread(ARGV[0]), File.exist?(ARGV[1]) ? File.binread(ARGV[1]) : "")
  when "verify"
    raise "ARGS" unless ARGV.length == 2
    OpenClashCustomizer.verify(File.binread(ARGV[0]), File.binread(ARGV[1]))
    puts "CUSTOM_VERIFY=PASS"
  when "verify-runtime"
    raise "ARGS" unless ARGV.length == 3
    OpenClashCustomizer.verify_runtime(File.binread(ARGV[0]), File.binread(ARGV[1]), File.binread(ARGV[2]))
    puts "CUSTOM_RUNTIME_VERIFY=PASS"
  when "node-health"
    raise "ARGS" unless ARGV.length == 1
    results = OpenClashCustomizer.node_health(File.binread(ARGV[0]))
    %w[Maying Nexitally].each do |provider|
      passed, total = results.fetch(provider)
      puts ["HEALTH", provider.upcase, passed, total].join("\t")
    end
  when "selection-snapshot"
    raise "ARGS" unless ARGV.length == 2
    raise "OUTPUT_EXISTS" if File.exist?(ARGV[1]) || File.symlink?(ARGV[1])
    snapshot = OpenClashCustomizer.selection_snapshot(File.binread(ARGV[0]))
    File.binwrite(ARGV[1], snapshot)
    puts "SELECTION_SNAPSHOT=PASS"
    puts "SELECTION_COUNT=#{OpenClashCustomizer.parse_selection_manifest(snapshot).length}"
  when "selection-restore"
    raise "ARGS" unless ARGV.length == 2
    total, changed = OpenClashCustomizer.restore_selections(File.binread(ARGV[0]), File.binread(ARGV[1]))
    puts "SELECTION_RESTORE=PASS"
    puts "SELECTION_COUNT=#{total}"
    puts "SELECTION_CHANGED=#{changed}"
  when "selection-verify"
    raise "ARGS" unless ARGV.length == 2
    total, changed = OpenClashCustomizer.restore_selections(File.binread(ARGV[0]), File.binread(ARGV[1]), write: false)
    raise "SELECTION_VERIFY" unless changed.zero?
    puts "SELECTION_VERIFY=PASS"
    puts "SELECTION_COUNT=#{total}"
  when "route-check"
    raise "ARGS" unless ARGV.length == 2
    config = OpenClashCustomizer.safe_yaml(File.binread(ARGV[0]))
    request = File.binread(ARGV[1]).split("\n", -1)
    raise "ROUTE_INPUT" unless request.length == 3 && request[2].empty? && !request[0].empty? && !request[1].empty?
    policy, rule, uncertain = OpenClashCustomizer.route_decision(
      File.binread(ARGV[0]), request[0], source_ip: request[1]
    )
    if policy.nil?
      puts ["ROUTE", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"].join("\t")
    else
      mode = if policy == "DIRECT"
               "DIRECT"
             elsif policy.start_with?("REJECT")
               "REJECT"
             else
               "PROXY"
             end
      reachability = if mode == "REJECT"
                       "BLOCKED"
                     else
                       reachable = mode == "DIRECT" ? OpenClashCustomizer.direct_health : OpenClashCustomizer.controller_delay(config, policy)
                       reachable.nil? ? "UNKNOWN" : (reachable ? "REACHABLE" : "UNREACHABLE")
                     end
      rule_type = rule.split(",", 2).first
      certainty = uncertain ? "CONTEXTUAL" : "EXACT"
      puts ["ROUTE", mode, policy, reachability, rule_type, certainty].join("\t")
    end
  when "prune-backups"
    raise "ARGS" unless ARGV.length == 2
    puts "BACKUPS_REMOVED=#{OpenClashCustomizer.prune_backups(ARGV[0], ARGV[1])}"
  when "prune-backups-scheduled"
    raise "ARGS" unless ARGV.length == 1
    puts "BACKUPS_REMOVED=#{OpenClashCustomizer.prune_backups(ARGV[0])}"
  else
    raise "MODE"
  end
end
