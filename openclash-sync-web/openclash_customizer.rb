#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "yaml"

module OpenClashCustomizer
  VERSION = "OPENCLASH_SYNC_CUSTOM_V1"
  RULE_TYPES = %w[DOMAIN DOMAIN-SUFFIX IP-CIDR IP-CIDR6].freeze
  MAX_ITEMS = 256
  DOMAIN = /\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\z/i.freeze

  Model = Struct.new(:rules, :filters, :owned_rules, :owned_filters)
  Result = Struct.new(:config, :state, :rule_count, :filter_count, :sha256)

  module_function

  def audit_yaml_tree(value)
    stack = [[value, 1]]
    seen = {}
    nodes = 0
    until stack.empty?
      node, depth = stack.pop
      nodes += 1
      raise "YAML_BUDGET" if nodes > 100_000 || depth > 64
      next unless node.is_a?(Hash) || node.is_a?(Array)
      raise "YAML_ALIAS" if seen[node.object_id]
      seen[node.object_id] = true
      children = node.is_a?(Hash) ? node.values : node
      children.each { |child| stack << [child, depth + 1] }
    end
    value
  end

  def safe_yaml(bytes)
    raise "YAML_SIZE" if bytes.bytesize > 2 * 1024 * 1024
    audit_yaml_tree(YAML.safe_load(bytes, permitted_classes: [], aliases: false))
  rescue ArgumentError
    audit_yaml_tree(YAML.safe_load(bytes, [], [], false))
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
    policy = clean_field(fields[2], "POLICY", 128)
    raise "POLICY" if policy.include?(",")
    [kind, value, policy]
  end

  def parse_state(bytes, request: false)
    return Model.new([], [], [], []) if bytes.nil? || bytes.empty?
    raise "STATE_SIZE" if bytes.bytesize > 256 * 1024
    lines = bytes.lines.map { |line| line.chomp }
    raise "STATE_VERSION" unless lines.shift == VERSION
    rules = []
    filters = []
    owned_rules = []
    owned_filters = []
    lines.each do |line|
      next if line.empty?
      fields = line.split("\t", -1)
      tag = fields.shift
      case tag
      when "RULE" then rules << normalize_rule(fields)
      when "FAKE"
        raise "FAKE_FIELDS" unless fields.length == 1
        filters << fake_filter(fields[0])
      when "OWNED_RULE"
        raise "REQUEST_OWNERSHIP" if request
        owned_rules << normalize_rule(fields)
      when "OWNED_FAKE"
        raise "REQUEST_OWNERSHIP" if request
        raise "FAKE_FIELDS" unless fields.length == 1
        owned_filters << fake_filter(fields[0])
      else raise "STATE_TAG"
      end
    end
    raise "RULE_COUNT" if rules.length > MAX_ITEMS || owned_rules.length > MAX_ITEMS
    raise "FILTER_COUNT" if filters.length > MAX_ITEMS || owned_filters.length > MAX_ITEMS
    raise "RULE_DUPLICATE" unless rules.map { |rule| rule[0, 2] }.uniq.length == rules.length
    raise "FILTER_DUPLICATE" unless filters.uniq.length == filters.length
    raise "OWNED_RULE_DUPLICATE" unless owned_rules.uniq.length == owned_rules.length
    raise "OWNED_FILTER_DUPLICATE" unless owned_filters.uniq.length == owned_filters.length
    raise "OWNED_RULE_SCOPE" unless owned_rules.all? { |rule| rules.include?(rule) }
    raise "OWNED_FILTER_SCOPE" unless owned_filters.all? { |filter| filters.include?(filter) }
    Model.new(rules, filters, owned_rules, owned_filters)
  end

  def rule_text(rule)
    rule.join(",")
  end

  def remove_once(array, value)
    index = array.index(value)
    array.delete_at(index) if index
  end

  def state_bytes(desired, owned_rules, owned_filters)
    lines = [VERSION]
    desired.rules.each { |rule| lines << (["RULE"] + rule).join("\t") }
    desired.filters.each { |filter| lines << ["FAKE", filter].join("\t") }
    owned_rules.each { |rule| lines << (["OWNED_RULE"] + rule).join("\t") }
    owned_filters.each { |filter| lines << ["OWNED_FAKE", filter].join("\t") }
    lines.join("\n") + "\n"
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
    desired.rules.each { |rule| raise "POLICY_UNKNOWN" unless rule[2] == "DIRECT" || group_names.include?(rule[2]) }
    if remove_owned && desired.rules == old.rules && desired.filters == old.filters
      verify(config_bytes, old_state_bytes)
      output_state = state_bytes(desired, old.owned_rules, old.owned_filters)
      return Result.new(config_bytes, output_state, desired.rules.length, desired.filters.length,
                        Digest::SHA256.hexdigest(config_bytes))
    end
    changed = false
    if remove_owned
      owned_text = old.owned_rules.map { |rule| rule_text(rule) }
      unless owned_text.empty?
        raise "OWNED_RULE_DRIFT" unless rules.first(owned_text.length) == owned_text
        rules.shift(owned_text.length)
        changed = true
      end
      old.owned_filters.each do |filter|
        raise "OWNED_FAKE_DRIFT" unless remove_once(dns["fake-ip-filter"], filter)
        changed = true
      end
    end
    owned_rules = desired.rules.map(&:dup)
    custom_rules = owned_rules.map { |rule| rule_text(rule) }
    changed = true unless custom_rules.empty?
    config["rules"] = custom_rules + rules
    owned_filters = []
    desired.filters.each do |filter|
      next if dns["fake-ip-filter"].include?(filter)
      dns["fake-ip-filter"] << filter
      owned_filters << filter
      changed = true
    end
    output = changed ? YAML.dump(config) : config_bytes
    Result.new(output, state_bytes(desired, owned_rules, owned_filters), desired.rules.length,
               desired.filters.length, Digest::SHA256.hexdigest(output))
  end

  def inspect_state(config_bytes, state_bytes_value)
    config = safe_yaml(config_bytes)
    raise "CONFIG_ROOT" unless config.is_a?(Hash) && config["proxy-groups"].is_a?(Array)
    model = parse_state(state_bytes_value)
    groups = config["proxy-groups"].map { |item| item.is_a?(Hash) ? item["name"] : nil }
    raise "CONFIG_GROUPS" unless groups.all? { |name| name.is_a?(String) && !name.empty? && !name.match?(/[\t\r\n,]/) }
    raise "GROUP_DUPLICATE" unless groups.uniq.length == groups.length
    raise "POLICY_UNKNOWN" unless model.rules.all? { |rule| rule[2] == "DIRECT" || groups.include?(rule[2]) }
    lines = groups.map { |name| ["GROUP", name].join("\t") }
    model.rules.each { |rule| lines << (["RULE"] + rule).join("\t") }
    model.filters.each { |filter| lines << ["FAKE", filter].join("\t") }
    lines.join("\n") + "\n"
  end

  def verify(config_bytes, state_bytes_value)
    config = safe_yaml(config_bytes)
    raise "CONFIG_ROOT" unless config.is_a?(Hash) && config["rules"].is_a?(Array) && config["dns"].is_a?(Hash) && config["dns"]["fake-ip-filter"].is_a?(Array)
    model = parse_state(state_bytes_value)
    rules = config["rules"]
    filters = config["dns"]["fake-ip-filter"]
    raise "VERIFY_RULE" unless model.rules.all? { |rule| rules.include?(rule_text(rule)) }
    raise "VERIFY_OWNED_RULE" unless rules.first(model.owned_rules.length) == model.owned_rules.map { |rule| rule_text(rule) }
    raise "VERIFY_FILTER" unless model.filters.all? { |filter| filters.include?(filter) }
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
    runtime_rules = runtime_config["rules"]
    runtime_filters = runtime_config.dig("dns", "fake-ip-filter")
    raise "RUNTIME_RULES" unless runtime_rules.is_a?(Array) && runtime_rules.all? { |item| item.is_a?(String) }
    raise "RUNTIME_FILTERS" unless runtime_filters.is_a?(Array) && runtime_filters.all? { |item| item.is_a?(String) }
    owned_text = model.owned_rules.map { |rule| rule_text(rule) }
    static_rules = static_config["rules"]
    raise "RUNTIME_BASELINE_RULES" unless static_rules.is_a?(Array) && static_rules.all? { |item| item.is_a?(String) }
    static_start = find_block(runtime_rules, static_rules)
    raise "RUNTIME_STATIC_BLOCK" if static_start.nil?
    return true if model.owned_rules.empty? && model.owned_filters.empty?

    unless owned_text.empty?
      custom_start = find_block(runtime_rules, owned_text)
      raise "RUNTIME_CUSTOM_BLOCK" if custom_start.nil?

      # OpenClash 会在运行文件最前面插入自身规则。自定义块不必位于索引 0，
      # 但必须早于至少一个非重复的订阅基线规则，才能证明业务优先级仍在。
      anchor_index = static_start + owned_text.length
      raise "RUNTIME_PRIORITY" unless custom_start < anchor_index
    end
    raise "RUNTIME_FILTER" unless model.filters.all? { |filter| runtime_filters.include?(filter) }
    true
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
  else
    raise "MODE"
  end
end
