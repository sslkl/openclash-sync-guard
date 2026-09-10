#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "yaml"

class RouterStageBuilder
  BUILTINS = %w[DIRECT REJECT REJECT-DROP PASS COMPATIBLE].freeze
  REGIONS = [
    ["Maying-HK-Auto", "HK-Auto"], ["Maying-JP-Auto", "JP-Auto"],
    ["Maying-SG-Auto", "SG-Auto"], ["Maying-US-Auto", "US-Auto"],
    ["Maying-TW-Auto", "TW-Auto"], ["Maying-Others-Auto", "🍀 Others"]
  ].freeze
  BUSINESS_GROUPS = %w[
    Netflix HBO DisneyPlus YouTube Bahamut Bilibili MyTVSuper AI Telegram Crypto
    Steam Epic Xbox PlayStation Microsoft Scholar Apple Google Tiktok ✈️Final
  ].freeze
  MAYING_RESOLVERS = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"].freeze
  REGION_MARKERS = {
    "Maying-HK-Auto" => ["🇭🇰"], "Maying-JP-Auto" => ["🇯🇵"],
    "Maying-SG-Auto" => ["🇸🇬"], "Maying-US-Auto" => ["🇺🇸"],
    "Maying-TW-Auto" => ["🇨🇳", "🇹🇼"]
  }.freeze

  Result = Struct.new(:candidate, :receipt, keyword_init: true)

  def build(base_bytes:, maying_bytes:, runtime_bytes:, expected_maying_count:)
    raise "EXPECTED_COUNT" unless expected_maying_count.is_a?(Integer) && expected_maying_count.between?(1, 2048)
    base = parse(base_bytes, allow_symbols: true)
    maying = parse(maying_bytes, allow_symbols: false)
    runtime = parse(runtime_bytes, allow_symbols: true)
    [base, maying, runtime].each { |value| raise "YAML_ROOT" unless value.is_a?(Hash) }
    %w[proxies proxy-groups rules dns].each { |key| raise "BASE_ROOT" unless base.key?(key) }
    %w[proxies proxy-groups].each { |key| raise "MAYING_ROOT" unless maying.key?(key) }
    %w[proxies proxy-groups].each { |key| raise "RUNTIME_ROOT" unless runtime.key?(key) }
    raise "MAYING_DNS_UNEXPECTED" if maying.key?("dns")
    raise "MAYING_RULES_UNEXPECTED" unless (maying.keys & %w[rules rule-providers proxy-providers]).empty?
    raise "MAYING_DOCUMENT_SHAPE" unless maying.keys.sort == %w[proxies proxy-groups].sort

    base_proxies = exact_array(base, "proxies")
    base_groups = exact_array(base, "proxy-groups")
    rules = exact_array(base, "rules")
    base_dns = base["dns"]
    raise "BASE_DNS" unless base_dns.is_a?(Hash)
    maying_proxies = exact_array(maying, "proxies")
    maying_groups = exact_array(maying, "proxy-groups")
    validate_unique!(base_proxies, "BASE_PROXY")
    validate_unique!(base_groups, "BASE_GROUP")
    validate_unique!(maying_proxies, "MAYING_PROXY")
    validate_unique!(maying_groups, "MAYING_GROUP")
    raise "MAYING_COUNT" unless maying_proxies.length == expected_maying_count
    raise "MAYING_TYPE" unless maying_proxies.all? do |proxy|
      proxy["type"] == "ssr" && proxy["udp"] == true && proxy["tfo"] == false && safe_host?(proxy["server"])
    end

    base_names = base_proxies.map { |proxy| proxy.fetch("name") }
    maying_names = maying_proxies.map { |proxy| proxy.fetch("name") }
    raise "NODE_COLLISION" unless (base_names & maying_names).empty?
    supplemental, placements, rotated_runtime_count = runtime_supplement(base_proxies, base_groups, runtime)
    supplemental_names = supplemental.map { |proxy| proxy.fetch("name") }
    raise "NODE_COLLISION" unless (base_names + maying_names + supplemental_names).uniq.length == base_names.length + maying_names.length + supplemental_names.length

    groups = deep_copy(base_groups)
    group_map = groups.to_h { |group| [group.fetch("name"), group] }
    placements.each { |name, additions| group_map.fetch(name)["proxies"] = Array(group_map.fetch(name)["proxies"]) + additions }
    region_groups = build_regions(maying_groups, maying_names, group_map)
    region_names = region_groups.map { |group| group.fetch("name") }
    BUSINESS_GROUPS.each do |name|
      group = group_map[name]
      raise "BUSINESS_GROUP" unless group
      members = Array(group["proxies"])
      raise "BUSINESS_DUPLICATE" unless (members & region_names).empty?
      group["proxies"] = members + region_names
    end
    groups.concat(region_groups)

    candidate = deep_copy(base)
    candidate["proxies"] = deep_copy(base_proxies) + supplemental + deep_copy(maying_proxies)
    candidate["proxy-groups"] = groups
    candidate["rules"] = deep_copy(rules)
    candidate["dns"], maying_policy_hosts = build_dns(base_dns, maying_proxies)
    validate_candidate!(candidate, base, base_proxies, rules, base_dns, maying_policy_hosts)
    bytes = YAML.dump(candidate)
    raise "CANDIDATE_SIZE" unless bytes.bytesize.between?(1, 16 * 1024 * 1024)
    receipt = {
      "schema" => "publisher-v4-router-stage-build-receipt-v1", "decision" => "PASS",
      "reason" => "NONE", "authorization_effect" => "PREPARE_ONLY",
      "base_proxy_count" => base_proxies.length, "maying_proxy_count" => maying_proxies.length,
      "supplemental_proxy_count" => supplemental.length, "rotated_runtime_proxy_count" => rotated_runtime_count,
      "candidate_proxy_count" => candidate["proxies"].length,
      "candidate_group_count" => groups.length, "candidate_rule_count" => rules.length,
      "region_group_count" => region_groups.length,
      "dns_policy_host_count" => candidate["dns"]["proxy-server-nameserver-policy"].length,
      "base_dns_sha256" => semantic_sha256(base_dns),
      "candidate_dns_sha256" => semantic_sha256(candidate["dns"]),
      "maying_policy_host_count" => maying_policy_hosts.length,
      "maying_policy_resolver_set_sha256" => semantic_sha256(MAYING_RESOLVERS.sort),
      "maying_udp_true_count" => maying_proxies.count { |proxy| proxy["udp"] == true },
      "maying_tfo_false_count" => maying_proxies.count { |proxy| proxy["tfo"] == false },
      "maying_udp_runtime_verified" => false,
      "candidate_sha256" => Digest::SHA256.hexdigest(bytes),
      "active_config_changed" => false, "uci_changed" => false, "service_restarted" => false
    }
    Result.new(candidate: bytes, receipt: receipt)
  end

  private

  def parse(bytes, allow_symbols:)
    raise "YAML_SIZE" unless bytes.is_a?(String) && bytes.bytesize.between?(1, 16 * 1024 * 1024) && !bytes.include?("\0")
    permitted_classes = allow_symbols ? [Symbol] : []
    value = YAML.safe_load(bytes, permitted_classes: permitted_classes, aliases: false) || {}
    audit_yaml_tree(value)
  rescue Psych::BadAlias
    raise "YAML_ALIAS"
  rescue Psych::DisallowedClass
    raise "YAML_CLASS"
  rescue Psych::SyntaxError
    raise "YAML_SYNTAX"
  rescue Psych::Exception
    raise "YAML_PARSE"
  end

  def audit_yaml_tree(value)
    stack = [[value, 0]]
    seen = {}
    nodes = 0
    until stack.empty?
      node, depth = stack.pop
      nodes += 1
      raise "YAML_BUDGET" if nodes > 200_000 || depth > 64
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

  def exact_array(hash, key)
    value = hash[key]
    raise "#{key.upcase}_TYPE" unless value.is_a?(Array)
    value
  end

  def validate_unique!(items, reason)
    raise reason unless items.all? { |item| item.is_a?(Hash) && safe_name?(item["name"]) }
    names = items.map { |item| item["name"] }
    raise reason unless names.uniq.length == names.length
  end

  def safe_name?(value)
    value.is_a?(String) && value.bytesize.between?(1, 512) && value.valid_encoding? && !value.include?("\0")
  end

  def safe_host?(value)
    value.is_a?(String) && value.bytesize.between?(1, 255) && value.valid_encoding? && !value.match?(/[\x00-\x20\x7f]/)
  end

  def runtime_supplement(base_proxies, base_groups, runtime)
    runtime_proxies = exact_array(runtime, "proxies")
    runtime_groups = exact_array(runtime, "proxy-groups")
    validate_unique!(runtime_proxies, "RUNTIME_PROXY")
    validate_unique!(runtime_groups, "RUNTIME_GROUP")
    base_names = base_proxies.map { |proxy| proxy.fetch("name") }
    runtime_names = runtime_proxies.map { |proxy| proxy.fetch("name") }
    runtime_extras = runtime_proxies.reject { |proxy| base_names.include?(proxy["name"]) || proxy["type"] == "ssr" }
    supplemental = runtime_extras.select { |proxy| proxy["type"] == "vless" }
    stale_runtime = runtime_extras.reject { |proxy| proxy["type"] == "vless" }
    missing_base = base_proxies.reject { |proxy| runtime_names.include?(proxy["name"]) }
    raise "SUPPLEMENT_COUNT" unless supplemental.length <= 8
    rotations = runtime_name_rotations(stale_runtime, missing_base)
    supplemental_names = supplemental.map { |proxy| proxy.fetch("name") }
    rotated_old_names = rotations.flat_map { |rotation| rotation.fetch(:old_names) }
    rotated_new_names = rotations.flat_map { |rotation| rotation.fetch(:new_names) }
    runtime_map = runtime_groups.to_h { |group| [group.fetch("name"), group] }
    managed_region_names = REGIONS.map(&:first)
    runtime_ssr_names = runtime_proxies.select { |proxy| proxy["type"] == "ssr" }.map { |proxy| proxy.fetch("name") }
    managed_region_names.each do |name|
      group = runtime_map[name]
      next unless group
      members = Array(group["proxies"])
      raise "RUNTIME_MANAGED_REGION" unless group["type"] == "url-test" && !members.empty? &&
                                                members.all? { |member| runtime_ssr_names.include?(member) }
    end
    placements = {}
    base_groups.each do |group|
      current = runtime_map[group.fetch("name")]
      raise "RUNTIME_GROUP_MISSING" unless current
      before = Array(group["proxies"])
      after = Array(current["proxies"])
      rotations.each do |rotation|
        before_count = before.count { |name| rotation.fetch(:new_names).include?(name) }
        after_count = after.count { |name| rotation.fetch(:old_names).include?(name) }
        raise "RUNTIME_GROUP_ROTATION" unless before_count == after_count
      end
      comparable_before = before.reject { |name| rotated_new_names.include?(name) }
      comparable_after = after.reject { |name| rotated_old_names.include?(name) }
      raise "RUNTIME_GROUP_REMOVAL" unless (comparable_before - comparable_after).empty?
      additions = comparable_after - comparable_before
      raise "RUNTIME_GROUP_ADDITION" unless (additions - supplemental_names - managed_region_names).empty?
      inherited = additions & supplemental_names
      placements[group.fetch("name")] = inherited unless inherited.empty?
    end
    [deep_copy(supplemental), placements, stale_runtime.length]
  end

  def runtime_name_rotations(stale_runtime, missing_base)
    return [] if stale_runtime.empty?
    raise "RUNTIME_PROXY_ROTATION" unless stale_runtime.length <= 8
    missing_by_shape = Hash.new { |hash, key| hash[key] = [] }
    missing_base.each { |proxy| missing_by_shape[proxy_shape_without_name(proxy)] << proxy.fetch("name") }
    stale_by_shape = Hash.new { |hash, key| hash[key] = [] }
    stale_runtime.each { |proxy| stale_by_shape[proxy_shape_without_name(proxy)] << proxy.fetch("name") }
    stale_by_shape.map do |shape, old_names|
      new_names = missing_by_shape.fetch(shape, [])
      raise "RUNTIME_PROXY_ROTATION" unless new_names.length == old_names.length
      {old_names: old_names, new_names: new_names}
    end
  end

  def proxy_shape_without_name(proxy)
    proxy.reject { |key, _| key == "name" }
  end

  def build_regions(maying_groups, maying_names, base_group_map)
    source_map = maying_groups.to_h { |group| [group.fetch("name"), group] }
    present = REGIONS.count { |_, source_name| source_map.key?(source_name) }
    return build_regions_from_names(maying_names, base_group_map) if present.zero?
    raise "REGION_GROUP_SHAPE" unless present == REGIONS.length
    assigned = []
    result = REGIONS.map do |target, source_name|
      raise "REGION_COLLISION" if base_group_map.key?(target)
      source = source_map[source_name]
      raise "REGION_MISSING" unless source
      members = Array(source["proxies"])
      raise "REGION_EMPTY" if members.empty?
      raise "REGION_MEMBER" unless members.all? { |name| maying_names.include?(name) }
      assigned.concat(members)
      { "name" => target, "type" => "url-test", "url" => "https://www.gstatic.com/generate_204", "interval" => 300, "proxies" => members.dup }
    end
    raise "REGION_PARTITION" unless assigned.length == assigned.uniq.length && assigned.sort == maying_names.sort
    result
  end

  def build_regions_from_names(maying_names, base_group_map)
    assignments = Hash.new { |hash, key| hash[key] = [] }
    maying_names.each do |name|
      matches = REGION_MARKERS.select { |_, markers| markers.any? { |marker| name.include?(marker) } }.keys
      raise "REGION_NAME_AMBIGUOUS" if matches.length > 1
      assignments[matches.first || "Maying-Others-Auto"] << name
    end
    REGIONS.map do |target, _|
      raise "REGION_COLLISION" if base_group_map.key?(target)
      members = assignments[target]
      raise "REGION_EMPTY" if members.empty?
      { "name" => target, "type" => "url-test", "url" => "https://www.gstatic.com/generate_204",
        "interval" => 300, "proxies" => members.dup }
    end
  end

  def build_dns(base_dns, maying_proxies)
    dns = deep_copy(base_dns)
    existing = dns["proxy-server-nameserver-policy"]
    raise "DNS_POLICY_COLLISION" unless existing.nil? || existing.is_a?(Hash)
    existing ||= {}
    hosts = maying_proxies.map { |proxy| proxy.fetch("server") }.reject { |host| ip_literal?(host) }.uniq.sort
    policy = deep_copy(existing)
    hosts.each do |host|
      if policy.key?(host)
        raise "DNS_POLICY_COLLISION" unless resolver_set(policy[host]) == MAYING_RESOLVERS.sort
      else
        policy[host] = MAYING_RESOLVERS.dup
      end
    end
    dns["proxy-server-nameserver-policy"] = policy
    [dns, hosts]
  end

  def resolver_set(value)
    values = value.is_a?(Array) ? value : [value]
    return nil unless values.all? { |item| item.is_a?(String) && !item.empty? }
    values.uniq.sort
  end

  def ip_literal?(value)
    candidate = value.start_with?("[") && value.end_with?("]") ? value[1...-1] : value
    ipv4_literal?(candidate) || ipv6_literal?(candidate)
  end

  def ipv4_literal?(value)
    parts = value.split(".", -1)
    parts.length == 4 && parts.all? do |part|
      part.match?(/\A(?:0|[1-9][0-9]{0,2})\z/) && part.to_i <= 255
    end
  end

  def ipv6_literal?(value)
    return false unless value.include?(":")
    halves = value.split("::", -1)
    return false if halves.length > 2
    left = halves[0].empty? ? [] : halves[0].split(":", -1)
    right = halves.length == 2 && !halves[1].empty? ? halves[1].split(":", -1) : []
    tokens = left + right
    return false if tokens.any?(&:empty?)
    ipv4_indexes = tokens.each_index.select { |index| tokens[index].include?(".") }
    return false unless ipv4_indexes.empty? || ipv4_indexes == [tokens.length - 1]
    units = tokens.sum do |token|
      if token.include?(".")
        return false unless ipv4_literal?(token)
        2
      else
        return false unless token.match?(/\A[0-9A-Fa-f]{1,4}\z/)
        1
      end
    end
    halves.length == 2 ? units < 8 : units == 8
  end

  def validate_candidate!(candidate, base, base_proxies, rules, base_dns, maying_policy_hosts)
    proxies = exact_array(candidate, "proxies")
    groups = exact_array(candidate, "proxy-groups")
    validate_unique!(proxies, "CANDIDATE_PROXY")
    validate_unique!(groups, "CANDIDATE_GROUP")
    raise "BASE_PROXY_DRIFT" unless proxies.first(base_proxies.length) == base_proxies
    raise "RULE_DRIFT" unless candidate["rules"] == rules && base["rules"] == rules
    validate_dns_ownership!(base_dns, candidate["dns"], maying_policy_hosts)
    nodes = proxies.to_h { |proxy| [proxy.fetch("name"), true] }
    group_names = groups.to_h { |group| [group.fetch("name"), true] }
    builtins = BUILTINS.to_h { |name| [name, true] }
    groups.each do |group|
      Array(group["proxies"]).each do |member|
        raise "GROUP_REFERENCE" unless member.is_a?(String) && (nodes.key?(member) || group_names.key?(member) || builtins.key?(member))
      end
    end
    edges = groups.to_h { |group| [group.fetch("name"), Array(group["proxies"]).select { |name| group_names.key?(name) }.uniq] }
    states = {}
    group_names.each_key do |start|
      next if states[start] == :done
      states[start] = :visiting
      stack = [[start, 0]]
      until stack.empty?
        name, index = stack[-1]
        children = edges.fetch(name)
        if index >= children.length
          states[name] = :done
          stack.pop
          next
        end
        child = children[index]
        stack[-1][1] = index + 1
        raise "GROUP_CYCLE" if states[child] == :visiting
        next if states[child] == :done
        states[child] = :visiting
        stack << [child, 0]
      end
    end
  end

  def validate_dns_ownership!(base_dns, candidate_dns, maying_policy_hosts)
    raise "DNS_OWNERSHIP_DRIFT" unless candidate_dns.is_a?(Hash)
    base_owned = deep_copy(base_dns)
    candidate_owned = deep_copy(candidate_dns)
    base_policy = base_owned.delete("proxy-server-nameserver-policy") || {}
    candidate_policy = candidate_owned.delete("proxy-server-nameserver-policy")
    raise "DNS_OWNERSHIP_DRIFT" unless base_policy.is_a?(Hash) && candidate_policy.is_a?(Hash)
    raise "DNS_OWNERSHIP_DRIFT" unless base_owned == candidate_owned
    base_policy.each do |host, resolvers|
      raise "DNS_OWNERSHIP_DRIFT" unless candidate_policy.key?(host) && candidate_policy[host] == resolvers
    end
    additions = candidate_policy.keys - base_policy.keys
    expected_additions = maying_policy_hosts.reject { |host| base_policy.key?(host) }
    raise "DNS_OWNERSHIP_DRIFT" unless additions.sort == expected_additions.sort
    additions.each do |host|
      raise "DNS_OWNERSHIP_DRIFT" unless candidate_policy[host] == MAYING_RESOLVERS
    end
  end

  def semantic_sha256(value)
    Digest::SHA256.hexdigest(canonical_bytes(value))
  end

  def canonical_bytes(value)
    case value
    when Hash
      keys = value.keys.sort
      "H#{keys.length}:".b + keys.map { |key| canonical_bytes(key) + canonical_bytes(value.fetch(key)) }.join
    when Array
      "A#{value.length}:".b + value.map { |child| canonical_bytes(child) }.join
    when String then "S#{value.bytesize}:".b + value.b
    when Symbol
      text = value.to_s
      "Y#{text.bytesize}:".b + text.b
    when Integer then "I#{value};".b
    when Float then "D#{value};".b
    when TrueClass then "B1".b
    when FalseClass then "B0".b
    when NilClass then "N".b
    else raise "DNS_HOSTS"
    end
  end

  def deep_copy(value)
    case value
    when Hash then value.to_h { |key, child| [key.dup, deep_copy(child)] }
    when Array then value.map { |child| deep_copy(child) }
    when String then value.dup
    else value
    end
  end
end

if $PROGRAM_NAME == __FILE__
  CLI_REASONS = %w[
    ARGS EXPECTED_COUNT INPUT_PATH OUTPUT_PATH OUTPUT_EXISTS YAML_SIZE YAML_ALIAS YAML_CLASS YAML_SYNTAX YAML_PARSE YAML_BUDGET YAML_ROOT BASE_ROOT MAYING_ROOT
    RUNTIME_ROOT BASE_DNS PROXIES_TYPE PROXY-GROUPS_TYPE RULES_TYPE BASE_PROXY BASE_GROUP MAYING_PROXY
    MAYING_GROUP MAYING_COUNT MAYING_TYPE NODE_COLLISION RUNTIME_PROXY RUNTIME_GROUP SUPPLEMENT_COUNT
    SUPPLEMENT_TYPE RUNTIME_PROXY_ROTATION RUNTIME_GROUP_ROTATION RUNTIME_GROUP_MISSING RUNTIME_GROUP_REMOVAL RUNTIME_GROUP_ADDITION RUNTIME_MANAGED_REGION REGION_COLLISION
    REGION_MISSING REGION_EMPTY REGION_MEMBER REGION_PARTITION REGION_GROUP_SHAPE REGION_NAME_AMBIGUOUS BUSINESS_GROUP BUSINESS_DUPLICATE
    MAYING_DOCUMENT_SHAPE MAYING_DNS_UNEXPECTED MAYING_RULES_UNEXPECTED DNS_POLICY_COLLISION DNS_OWNERSHIP_DRIFT DNS_HOSTS
    CANDIDATE_PROXY CANDIDATE_GROUP BASE_PROXY_DRIFT RULE_DRIFT
    GROUP_REFERENCE GROUP_CYCLE CANDIDATE_SIZE INTERNAL
  ].freeze
  def hold(reason)
    safe = CLI_REASONS.include?(reason.to_s) ? reason.to_s : "INTERNAL"
    warn "ROUTER_STAGE_BUILD=HOLD|REASON=#{safe}"
    exit 1
  end
  begin
    base_path, maying_path, runtime_path, output_path, expected_count = ARGV
    hold("ARGS") unless ARGV.length == 5 && expected_count.match?(/\A[1-9][0-9]{0,3}\z/)
    root = "/etc/openclash/publisher-v4/stage/"
    allowed_fixed = ["/etc/openclash/config/ProviderBase.yaml", "/etc/openclash/ProviderBase-ProviderSource.yaml"]
    hold("INPUT_PATH") unless base_path == allowed_fixed[0] && runtime_path == allowed_fixed[1] &&
                              maying_path.start_with?(root) && File.basename(maying_path) == "Maying-normalized.yaml" &&
                              File.realpath(File.dirname(maying_path)).start_with?(root)
    hold("OUTPUT_PATH") unless output_path.start_with?(root) && File.basename(output_path) == "candidate.yaml" && File.realpath(File.dirname(output_path)).start_with?(root)
    result = RouterStageBuilder.new.build(
      base_bytes: File.binread(base_path), maying_bytes: File.binread(maying_path),
      runtime_bytes: File.binread(runtime_path), expected_maying_count: Integer(expected_count, 10)
    )
    hold("OUTPUT_EXISTS") if File.exist?(output_path)
    temporary = "#{output_path}.tmp-#{Process.pid}"
    File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(result.candidate); file.flush; file.fsync }
    File.chmod(0o600, temporary)
    File.rename(temporary, output_path)
    puts YAML.dump(result.receipt)
  rescue Psych::Exception
    File.delete(temporary) if defined?(temporary) && temporary && File.exist?(temporary)
    hold("YAML_PARSE")
  rescue StandardError => error
    File.delete(temporary) if defined?(temporary) && temporary && File.exist?(temporary)
    hold(error.message)
  end
end
