#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require_relative "../openclash_customizer"

def config
  {
    "proxies" => [],
    "proxy-groups" => [{"name" => "Proxies", "type" => "select", "proxies" => ["DIRECT"]}, {"name" => "AI", "type" => "select", "proxies" => ["Proxies"]}],
    "dns" => {"fake-ip-filter" => ["*.lan"]},
    "rules" => ["DOMAIN-SUFFIX,base.test,Proxies", "MATCH,Proxies"]
  }
end

def request(*lines)
  ([OpenClashCustomizer::VERSION] + lines).join("\n") + "\n"
end

tests = 0
check = lambda do |name, &block|
  block.call
  tests += 1
  puts "PASS #{name}"
end

check.call("domain ip and fake filter render") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request(
    "RULE\tDOMAIN\tapi.example.com\tDIRECT",
    "RULE\tIP-CIDR\t198.51.100.7\tAI",
    "RULE\tIP-CIDR6\t2001:db8::1\tProxies",
    "FAKE\t+.example.com"
  ))
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  raise unless parsed["rules"][0, 3] == ["DOMAIN,api.example.com,DIRECT", "IP-CIDR,198.51.100.7/32,AI", "IP-CIDR6,2001:db8::1/128,Proxies"]
  raise unless parsed["dns"]["fake-ip-filter"] == ["*.lan", "+.example.com"]
end

check.call("exact supplemental domain ip and fake entries render and persist ownership") do
  manifest = request(
    "SUPPLEMENT_RULE\tIP-CIDR,192.0.2.0/24,DIRECT,no-resolve",
    "SUPPLEMENT_FAKE\tgeosite:private"
  )
  result = OpenClashCustomizer.render(YAML.dump(config), "", manifest)
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  state = OpenClashCustomizer.parse_state(result.state)
  raise unless parsed["rules"].first == "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"
  raise unless parsed.dig("dns", "fake-ip-filter").last == "geosite:private"
  raise unless state.owned_supplemental_rules == ["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"]
  raise unless state.owned_supplemental_filters == ["geosite:private"]
  raise unless OpenClashCustomizer.verify(result.config, result.state)
  output = OpenClashCustomizer.inspect_state(result.config, result.state)
  raise unless output.include?("SUPPLEMENT_RULE\tIP-CIDR,192.0.2.0/24,DIRECT,no-resolve")
  raise unless output.include?("OWNED_SUPPLEMENT_FAKE\tgeosite:private")
end

check.call("missing unowned exact supplemental entries are reclaimed") do
  changed = config
  changed["rules"] = ["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"] + changed["rules"]
  changed["dns"]["fake-ip-filter"] << "geosite:private"
  manifest = request(
    "SUPPLEMENT_RULE\tIP-CIDR,192.0.2.0/24,DIRECT,no-resolve",
    "SUPPLEMENT_FAKE\tgeosite:private"
  )
  first = OpenClashCustomizer.render(YAML.dump(changed), "", manifest)
  state = OpenClashCustomizer.parse_state(first.state)
  raise unless first.config == YAML.dump(changed) && OpenClashCustomizer.verify(first.config, first.state)
  raise unless state.owned_supplemental_rules.empty? && state.owned_supplemental_filters.empty?
  drifted = YAML.safe_load(first.config, permitted_classes: [Symbol], aliases: true)
  drifted["rules"].delete("IP-CIDR,192.0.2.0/24,DIRECT,no-resolve")
  drifted["dns"]["fake-ip-filter"].delete("geosite:private")
  repaired = OpenClashCustomizer.render(YAML.dump(drifted), first.state, manifest)
  repaired_state = OpenClashCustomizer.parse_state(repaired.state)
  raise unless repaired_state.owned_supplemental_rules.length == 1
  raise unless repaired_state.owned_supplemental_filters.length == 1
end

check.call("old owned rules are replaced") do
  first = OpenClashCustomizer.render(YAML.dump(config), "", request("RULE\tDOMAIN\tone.example\tDIRECT"))
  second = OpenClashCustomizer.render(first.config, first.state, request("RULE\tDOMAIN\ttwo.example\tAI"))
  parsed = YAML.safe_load(second.config, permitted_classes: [Symbol], aliases: true)
  raise if parsed["rules"].any? { |rule| rule.include?("one.example") }
  raise unless parsed["rules"].first == "DOMAIN,two.example,AI"
end

check.call("owned prefix drift is rejected") do
  first = OpenClashCustomizer.render(YAML.dump(config), "", request("RULE\tDOMAIN\tone.example\tDIRECT"))
  drifted = YAML.safe_load(first.config, permitted_classes: [Symbol], aliases: true)
  drifted["rules"].shift
  begin
    OpenClashCustomizer.render(YAML.dump(drifted), first.state, request("RULE\tDOMAIN\ttwo.example\tAI"))
  rescue StandardError
    next
  end
  raise "expected owned prefix drift rejection"
end

check.call("baseline fake filter is not owned") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request("FAKE\t*.lan"))
  state = OpenClashCustomizer.parse_state(result.state)
  raise unless state.owned_filters.empty?
end

check.call("baseline identical rule is reused without duplicate ownership") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request("RULE\tDOMAIN-SUFFIX\tbase.test\tProxies"))
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  state = OpenClashCustomizer.parse_state(result.state)
  raise unless parsed["rules"].count("DOMAIN-SUFFIX,base.test,Proxies") == 1
  raise unless state.rules == [["DOMAIN-SUFFIX", "base.test", "Proxies"]] && state.owned_rules.empty?
  cleared = OpenClashCustomizer.render(result.config, result.state, request)
  restored = YAML.safe_load(cleared.config, permitted_classes: [Symbol], aliases: true)
  raise unless restored["rules"].count("DOMAIN-SUFFIX,base.test,Proxies") == 1
end

check.call("missing unowned baseline items are reclaimed without hiding owned drift") do
  desired = request("RULE\tDOMAIN-SUFFIX\tbase.test\tProxies", "FAKE\t*.lan")
  first = OpenClashCustomizer.render(YAML.dump(config), "", desired)
  state = OpenClashCustomizer.parse_state(first.state)
  raise unless state.owned_rules.empty? && state.owned_filters.empty?

  drifted = YAML.safe_load(first.config, permitted_classes: [Symbol], aliases: true)
  drifted["rules"].delete("DOMAIN-SUFFIX,base.test,Proxies")
  drifted["dns"]["fake-ip-filter"].delete("*.lan")
  inspected = OpenClashCustomizer.inspect_state(YAML.dump(drifted), first.state)
  raise unless inspected.include?("RULE\tDOMAIN-SUFFIX\tbase.test\tProxies")

  repaired = OpenClashCustomizer.render(YAML.dump(drifted), first.state, desired)
  repaired_config = YAML.safe_load(repaired.config, permitted_classes: [Symbol], aliases: true)
  repaired_state = OpenClashCustomizer.parse_state(repaired.state)
  raise unless repaired_config["rules"].first == "DOMAIN-SUFFIX,base.test,Proxies"
  raise unless repaired_config["dns"]["fake-ip-filter"].include?("*.lan")
  raise unless repaired_state.owned_rules == [["DOMAIN-SUFFIX", "base.test", "Proxies"]]
  raise unless repaired_state.owned_filters == ["*.lan"]
end

check.call("baseline matcher with a different policy is rejected before rendering") do
  begin
    OpenClashCustomizer.render(YAML.dump(config), "", request("RULE\tDOMAIN-SUFFIX\tbase.test\tAI"))
  rescue StandardError => error
    raise unless error.message == "BASELINE_MATCHER_CONFLICT"
    next
  end
  raise "expected baseline matcher conflict"
end

check.call("noncanonical baseline matcher forms cannot acquire duplicate ownership") do
  ["domain,base.test,Proxies", "Domain,BASE.TEST.,Proxies", "DOMAIN,base.test,Proxies,no-resolve"].each do |baseline|
    changed = config
    changed["rules"].unshift(baseline)
    begin
      OpenClashCustomizer.render(YAML.dump(changed), "", request("RULE\tDOMAIN\tbase.test\tProxies"))
    rescue StandardError => error
      raise unless error.message == "BASELINE_MATCHER_CONFLICT"
      next
    end
    raise "expected baseline matcher conflict for #{baseline}"
  end
end

check.call("normalized ipv4 and ipv6 baseline matchers are still conflicts") do
  [
    ["IP-CIDR,192.0.2.1/24,DIRECT", "RULE\tIP-CIDR\t192.0.2.0/24\tDIRECT"],
    ["IP-CIDR6,2001:0DB8:0:0:0:0:0:1/64,DIRECT", "RULE\tIP-CIDR6\t2001:db8::/64\tDIRECT"]
  ].each do |baseline, desired|
    changed = config
    changed["rules"].unshift(baseline)
    begin
      OpenClashCustomizer.render(YAML.dump(changed), "", request(desired))
    rescue StandardError => error
      raise unless error.message == "BASELINE_MATCHER_CONFLICT"
      next
    end
    raise "expected normalized baseline matcher conflict for #{baseline}"
  end
end

check.call("exact and noncanonical baseline matcher forms cannot be mixed") do
  changed = config
  changed["rules"].unshift("IP-CIDR,192.0.2.1/24,DIRECT", "IP-CIDR,192.0.2.0/24,DIRECT")
  begin
    OpenClashCustomizer.render(YAML.dump(changed), "", request("RULE\tIP-CIDR\t192.0.2.0/24\tDIRECT"))
  rescue StandardError => error
    raise unless error.message == "BASELINE_MATCHER_CONFLICT"
    next
  end
  raise "expected mixed baseline matcher conflict"
end

check.call("equivalent baseline fake filter with different syntax is rejected") do
  changed = YAML.safe_load(YAML.dump(config), permitted_classes: [Symbol], aliases: true)
  changed["dns"]["fake-ip-filter"] = ["*.LAN."]
  begin
    OpenClashCustomizer.render(YAML.dump(changed), "", request("FAKE\t*.lan"))
  rescue StandardError => error
    raise unless error.message == "BASELINE_FILTER_CONFLICT"
    next
  end
  raise "expected baseline filter conflict"
end

check.call("overlay keeps baseline without duplicate and owns only new content") do
  desired = request("RULE\tDOMAIN-SUFFIX\tbase.test\tProxies", "FAKE\t*.overlay.test")
  result = OpenClashCustomizer.render(YAML.dump(config), "", desired, remove_owned: false)
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  state = OpenClashCustomizer.parse_state(result.state)
  raise unless parsed["rules"].first == "DOMAIN-SUFFIX,base.test,Proxies"
  raise unless parsed["rules"].count("DOMAIN-SUFFIX,base.test,Proxies") == 1
  raise unless state.owned_rules.empty? && state.owned_filters == ["*.overlay.test"]
end

check.call("empty customization preserves exact config bytes") do
  original = "---\nproxies: []\nproxy-groups:\n- name: Proxies\n  type: select\n  proxies: [DIRECT]\ndns:\n  fake-ip-filter: [\"*.lan\"]\nrules: [\"MATCH,Proxies\"]\n"
  result = OpenClashCustomizer.render(original, "", request)
  raise unless result.config == original && result.rule_count.zero? && result.filter_count.zero?
end

{
  "unknown policy" => request("RULE\tDOMAIN\ta.example\tMissing"),
  "duplicate matcher" => request("RULE\tDOMAIN\ta.example\tDIRECT", "RULE\tDOMAIN\ta.example\tAI"),
  "invalid ipv4" => request("RULE\tIP-CIDR\t2001:db8::1\tDIRECT"),
  "invalid domain" => request("RULE\tDOMAIN\tbad_domain\tDIRECT"),
  "request ownership" => request("OWNED_FAKE\t*.example.com")
}.each do |name, manifest|
  check.call("reject #{name}") do
    begin
      OpenClashCustomizer.render(YAML.dump(config), "", manifest)
    rescue StandardError
      next
    end
    raise "expected rejection"
  end
end

check.call("inspect returns groups and desired model") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request("RULE\tDOMAIN-SUFFIX\texample.com\tAI", "FAKE\t*.example.com"))
  output = OpenClashCustomizer.inspect_state(result.config, result.state)
  raise unless output.include?("GROUP\tAI") && output.include?("RULE\tDOMAIN-SUFFIX\texample.com\tAI") &&
               output.include?("FAKE\t*.example.com") && output.include?("CONFIG_RULE\tMATCH,Proxies") &&
               output.include?("CONFIG_FAKE\t*.lan") &&
               output.include?("OWNED_RULE\tDOMAIN-SUFFIX\texample.com\tAI") &&
               output.include?("OWNED_FAKE\t*.example.com")
end

check.call("proxy sets use validated Maying groups and classify the remaining nodes as Nexitally") do
  health_config = config.merge(
    "proxies" => [{"name" => "M-1"}, {"name" => "N-1"}, {"name" => "N-2"}],
    "proxy-groups" => config["proxy-groups"] + [{"name" => "Maying-HK-Auto", "proxies" => ["M-1"]}]
  )
  sets = OpenClashCustomizer.proxy_sets(health_config)
  raise unless sets == {"Maying" => ["M-1"], "Nexitally" => ["N-1", "N-2"]}
end

check.call("node health probes every real node exactly once and returns provider counts") do
  health_config = config.merge(
    "proxies" => [{"name" => "M-1"}, {"name" => "M-2"}, {"name" => "N-1"}],
    "proxy-groups" => config["proxy-groups"] + [{"name" => "Maying-HK-Auto", "proxies" => ["M-1", "M-2"]}],
    "external-controller" => "127.0.0.1:9090", "secret" => "synthetic-secret"
  )
  calls = []
  original = OpenClashCustomizer.method(:controller_delay)
  OpenClashCustomizer.define_singleton_method(:controller_delay) do |_config, name, timeout_ms: 5_000|
    calls << [name, timeout_ms]
    name != "M-2"
  end
  begin
    result = OpenClashCustomizer.node_health(YAML.dump(health_config), concurrency: 2)
    raise unless result == {"Maying" => [1, 2], "Nexitally" => [1, 1]}
    raise unless calls.map(&:first).sort == %w[M-1 M-2 N-1]
  ensure
    OpenClashCustomizer.define_singleton_method(:controller_delay, original)
  end
end

check.call("node health refuses false zeroes when controller context is unavailable") do
  health_config = config.merge(
    "proxies" => [{"name" => "M-1"}],
    "proxy-groups" => config["proxy-groups"] + [{"name" => "Maying-HK-Auto", "proxies" => ["M-1"]}],
    "external-controller" => "127.0.0.1:9090"
  )
  begin
    OpenClashCustomizer.node_health(YAML.dump(health_config), concurrency: 1)
  rescue StandardError => error
    raise unless error.message == "HEALTH_CONTROLLER"
    next
  end
  raise "expected unavailable controller health rejection"
end

check.call("selection snapshot restores every manual selector and skips automatic groups") do
  selection_config = config.merge(
    "secret" => "synthetic-secret", "external-controller" => "127.0.0.1:9090",
    "proxy-groups" => [
      {"name" => "AI", "type" => "select", "proxies" => ["P-1", "P-2"]},
      {"name" => "DisneyPlus", "type" => "select", "proxies" => ["Maying-HK-Auto", "P-2"]},
      {"name" => "✈️Final", "type" => "select", "proxies" => ["Proxies", "DIRECT"]},
      {"name" => "Auto", "type" => "url-test", "proxies" => ["P-1", "P-2"]}
    ]
  )
  current = {
    "AI" => {"now" => "P-2", "all" => ["P-1", "P-2"]},
    "DisneyPlus" => {"now" => "Maying-HK-Auto", "all" => ["Maying-HK-Auto", "P-2"]},
    "✈️Final" => {"now" => "Proxies", "all" => ["Proxies", "DIRECT"]},
    "Auto" => {"now" => "P-1", "all" => ["P-1", "P-2"]}
  }
  puts_seen = []
  original_proxies = OpenClashCustomizer.method(:controller_proxies)
  original_request = OpenClashCustomizer.method(:controller_request)
  OpenClashCustomizer.define_singleton_method(:controller_proxies) { |_value| Marshal.load(Marshal.dump(current)) }
  OpenClashCustomizer.define_singleton_method(:controller_request) do |_value, method, path, body = nil|
    raise unless method == "PUT" && path.start_with?("/proxies/") && body
    group = path.delete_prefix("/proxies/")
    selected = body[/\A\{"name":"([^"]+)"\}\z/, 1]
    raise unless current.key?(group) && selected
    current[group]["now"] = selected
    puts_seen << [group, selected]
    ["", "204"]
  end
  begin
    snapshot = OpenClashCustomizer.selection_snapshot(YAML.dump(selection_config))
    parsed = OpenClashCustomizer.parse_selection_manifest(snapshot)
    raise unless parsed == {"AI" => "P-2", "DisneyPlus" => "Maying-HK-Auto", "✈️Final" => "Proxies"}
    raise if snapshot.include?("synthetic-secret") || snapshot.include?("Auto")
    current["AI"]["now"] = "P-1"
    current["DisneyPlus"]["now"] = "P-2"
    total, changed = OpenClashCustomizer.restore_selections(YAML.dump(selection_config), snapshot)
    raise unless [total, changed] == [3, 2]
    raise unless puts_seen == [["AI", "P-2"], ["DisneyPlus", "Maying-HK-Auto"]]
    raise unless OpenClashCustomizer.restore_selections(YAML.dump(selection_config), snapshot, write: false) == [3, 0]
  ensure
    OpenClashCustomizer.define_singleton_method(:controller_proxies, original_proxies)
    OpenClashCustomizer.define_singleton_method(:controller_request, original_request)
  end
end

check.call("selection restore fails before mutation when a selected member was removed") do
  selection_config = config.merge(
    "secret" => "synthetic-secret", "external-controller" => "127.0.0.1:9090",
    "proxy-groups" => [{"name" => "DisneyPlus", "type" => "select", "proxies" => ["Maying-HK-Auto"]}]
  )
  original_proxies = OpenClashCustomizer.method(:controller_proxies)
  original_request = OpenClashCustomizer.method(:controller_request)
  puts_seen = 0
  OpenClashCustomizer.define_singleton_method(:controller_proxies) do |_value|
    {"DisneyPlus" => {"now" => "Fallback", "all" => ["Fallback"]}}
  end
  OpenClashCustomizer.define_singleton_method(:controller_request) do |*_args|
    puts_seen += 1
    ["", "204"]
  end
  begin
    manifest = "OPENCLASH_SYNC_SELECTIONS_V1\nSELECT\tRGlzbmV5UGx1cw==\tTWF5aW5nLUhLLU91dG8=\n"
    begin
      OpenClashCustomizer.restore_selections(YAML.dump(selection_config), manifest)
    rescue StandardError => error
      raise unless error.message == "SELECTION_MEMBER_REMOVED" && puts_seen.zero?
      next
    end
    raise "expected removed member rejection"
  ensure
    OpenClashCustomizer.define_singleton_method(:controller_proxies, original_proxies)
    OpenClashCustomizer.define_singleton_method(:controller_request, original_request)
  end
end

check.call("route decision handles domain keyword ports no-resolve source context and uncertainty") do
  routing = config.merge("rules" => [
    "DOMAIN,api.example.com,DIRECT",
    "DOMAIN-SUFFIX,example.net,Proxies",
    "DOMAIN-KEYWORD,stream,AI",
    "IP-CIDR,192.0.2.0/24,DIRECT",
    "RULE-SET,remote,AI",
    "MATCH,Proxies"
  ])
  raise unless OpenClashCustomizer.route_decision(YAML.dump(routing), "https://api.example.com/path")[0] == "DIRECT"
  raise unless OpenClashCustomizer.route_decision(YAML.dump(routing), "www.example.net")[0] == "Proxies"
  raise unless OpenClashCustomizer.route_decision(YAML.dump(routing), "video-stream.example")[0] == "AI"
  raise unless OpenClashCustomizer.route_decision(YAML.dump(routing), "192.0.2.8")[0] == "DIRECT"
  raise unless OpenClashCustomizer.route_decision(YAML.dump(routing), "unknown.example")[2]

  port_rules = config.merge("rules" => ["DST-PORT,443,AI", "MATCH,Proxies"])
  raise unless OpenClashCustomizer.route_decision(YAML.dump(port_rules), "https://secure.example")[0] == "AI"

  source_rules = config.merge("rules" => ["SRC-IP-CIDR,100.64.0.0/10,DIRECT", "MATCH,Proxies"])
  source_result = OpenClashCustomizer.route_decision(
    YAML.dump(source_rules), "example.com", source_ip: "100.64.2.3"
  )
  raise unless source_result[0] == "DIRECT" && !source_result[2]

  no_resolve = config.merge("rules" => ["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve", "MATCH,Proxies"])
  raise unless OpenClashCustomizer.route_decision(YAML.dump(no_resolve), "example.com") == ["Proxies", "MATCH,Proxies", false]
  needs_dns = config.merge("rules" => ["IP-CIDR,192.0.2.0/24,DIRECT", "MATCH,Proxies"])
  raise unless OpenClashCustomizer.route_decision(YAML.dump(needs_dns), "example.com")[2]
  source_port = config.merge("rules" => ["SRC-PORT,53,DIRECT", "DOMAIN,api.example.com,AI"])
  raise unless OpenClashCustomizer.route_decision(YAML.dump(source_port), "api.example.com")[2]
  ["http://example.com:0", "https://example.com:99999"].each do |invalid|
    begin
      OpenClashCustomizer.route_decision(YAML.dump(routing), invalid)
    rescue StandardError => error
      raise unless error.message == "ROUTE_INPUT"
      next
    end
    raise "expected invalid route port rejection"
  end
end

check.call("route check CLI accepts only the two-line value and source IP manifest") do
  require "open3"
  require "tmpdir"
  Dir.mktmpdir do |root|
    config_path = File.join(root, "config.yaml")
    request_path = File.join(root, "request.json")
    cli_config = config.merge("rules" => ["RULE-SET,remote,AI"])
    File.write(config_path, YAML.dump(cli_config))
    File.write(request_path, "example.com\n100.64.2.3\n")
    output, _error, status = Open3.capture3(
      RbConfig.ruby, File.expand_path("../openclash_customizer.rb", __dir__), "route-check", config_path, request_path
    )
    raise unless status.success? && output == "ROUTE\tUNKNOWN\tUNKNOWN\tUNKNOWN\tUNKNOWN\tUNKNOWN\n"
    File.write(request_path, "example.com\n100.64.2.3\nextra\n")
    _output, _error, status = Open3.capture3(
      RbConfig.ruby, File.expand_path("../openclash_customizer.rb", __dir__), "route-check", config_path, request_path
    )
    raise if status.success?
  end
end

check.call("route check reports reject policies as blocked instead of proxy") do
  require "open3"
  require "tmpdir"
  Dir.mktmpdir do |root|
    config_path = File.join(root, "config.yaml")
    request_path = File.join(root, "request.json")
    File.write(config_path, YAML.dump(config.merge("rules" => ["DOMAIN,blocked.example,REJECT", "MATCH,Proxies"])))
    File.write(request_path, "blocked.example\n100.64.2.3\n")
    output, _error, status = Open3.capture3(
      RbConfig.ruby, File.expand_path("../openclash_customizer.rb", __dir__), "route-check", config_path, request_path
    )
    raise unless status.success? && output == "ROUTE\tREJECT\tREJECT\tBLOCKED\tDOMAIN\tEXACT\n"
  end
end

check.call("route check preserves proxy decision when controller health is unavailable") do
  require "open3"
  require "tmpdir"
  Dir.mktmpdir do |root|
    config_path = File.join(root, "config.yaml")
    request_path = File.join(root, "request.json")
    File.write(config_path, YAML.dump(config.merge("rules" => ["DOMAIN,proxy.example,AI", "MATCH,Proxies"])))
    File.write(request_path, "proxy.example\n100.64.2.3\n")
    output, _error, status = Open3.capture3(
      RbConfig.ruby, File.expand_path("../openclash_customizer.rb", __dir__), "route-check", config_path, request_path
    )
    raise unless status.success? && output == "ROUTE\tPROXY\tAI\tUNKNOWN\tDOMAIN\tEXACT\n"
  end
end

check.call("router customizer uses only Ruby libraries installed on OpenWrt") do
  source = File.binread(File.expand_path("../openclash_customizer.rb", __dir__))
  %w[ipaddr json open3 uri].each { |library| raise if source.include?(%(require "#{library}")) }
end

check.call("backup retention deletes only trusted committed backups older than seven days") do
  require "tmpdir"
  Dir.mktmpdir do |root|
    File.chmod(0o700, root)
    current = File.join(root, "20260823T000000Z-2-stage-main")
    expired = File.join(root, "20260801T000000Z-1-stage-main")
    recent = File.join(root, "20260822T000000Z-3-custom-apply")
    now = Time.now
    [current, expired, recent].each do |path|
      Dir.mkdir(path, 0o700)
      File.write(File.join(path, "main.yaml"), "rules: []\n")
      epoch = path == expired ? now.to_i - (8 * 24 * 60 * 60) : now.to_i
      File.write(File.join(path, "COMMITTED"), "STATUS=COMMITTED\nCOMMITTED_AT_EPOCH=#{epoch}\n")
      Dir.children(path).each { |name| File.chmod(0o600, File.join(path, name)) }
    end
    removed = OpenClashCustomizer.prune_backups(root, current, now: now, expected_uid: Process.uid)
    raise unless removed == 1 && !Dir.exist?(expired) && Dir.exist?(current) && Dir.exist?(recent)
  end
end

check.call("scheduled backup retention deletes expired trusted backups without an active transaction") do
  require "tmpdir"
  Dir.mktmpdir do |root|
    File.chmod(0o700, root)
    now = Time.now
    expired = File.join(root, "20260801T000000Z-7-stage-main")
    suspicious = File.join(root, "20260801T000000Z-8-stage-main")
    recent = File.join(root, "20260823T000000Z-9-stage-main")
    [expired, suspicious, recent].each do |path|
      Dir.mkdir(path, 0o700)
      File.write(File.join(path, "main.yaml"), "rules: []\n")
      epoch = path == recent ? now.to_i : now.to_i - (8 * 24 * 60 * 60)
      File.write(File.join(path, "COMMITTED"), "STATUS=COMMITTED\nCOMMITTED_AT_EPOCH=#{epoch}\n")
      Dir.children(path).each { |name| File.chmod(0o600, File.join(path, name)) }
    end
    File.write(File.join(suspicious, "unexpected"), "hold\n")
    File.chmod(0o600, File.join(suspicious, "unexpected"))
    removed = OpenClashCustomizer.prune_backups(root, nil, now: now, expected_uid: Process.uid)
    raise unless removed == 1 && !Dir.exist?(expired) && Dir.exist?(suspicious) && Dir.exist?(recent)
  end
end

check.call("inspect rejects stale policy") do
  stale_state = request("RULE\tDOMAIN-SUFFIX\texample.com\tRemovedGroup")
  begin
    OpenClashCustomizer.inspect_state(YAML.dump(config), stale_state)
  rescue StandardError
    next
  end
  raise "expected stale policy rejection"
end

check.call("verify accepts rendered config and rejects missing rule") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request("RULE\tDOMAIN\tverify.example\tDIRECT", "FAKE\t*.verify.example"))
  raise unless OpenClashCustomizer.verify(result.config, result.state)
  broken = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  broken["rules"].delete("DOMAIN,verify.example,DIRECT")
  begin
    OpenClashCustomizer.verify(YAML.dump(broken), result.state)
  rescue StandardError
    next
  end
  raise "expected verify rejection"
end

check.call("runtime verify allows OpenClash prefix and preserves custom priority") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request(
    "RULE\tDOMAIN\truntime.example\tDIRECT",
    "RULE\tIP-CIDR\t192.0.2.1/24\tAI",
    "FAKE\t*.runtime.example"
  ))
  runtime = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  prefix = 44.times.map { |index| "DOMAIN,openclash-#{index}.internal,DIRECT" }
  runtime["rules"] = prefix + runtime["rules"]
  raise unless OpenClashCustomizer.verify_runtime(result.config, YAML.dump(runtime), result.state)
end

check.call("runtime verify rejects custom rules after subscription baseline") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request("RULE\tDOMAIN\tlate.example\tDIRECT"))
  runtime = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  custom = runtime["rules"].shift
  runtime["rules"] << custom
  begin
    OpenClashCustomizer.verify_runtime(result.config, YAML.dump(runtime), result.state)
  rescue StandardError
    next
  end
  raise "expected runtime priority rejection"
end

check.call("runtime verify rejects stale runtime when customization is empty") do
  empty_state = OpenClashCustomizer::VERSION + "\n"
  stale = YAML.safe_load(YAML.dump(config), permitted_classes: [Symbol], aliases: true)
  stale["rules"] = ["MATCH,REJECT"]
  begin
    OpenClashCustomizer.verify_runtime(YAML.dump(config), YAML.dump(stale), empty_state)
  rescue StandardError => error
    raise unless error.message == "RUNTIME_RULE_TRANSFORM"
    next
  end
  raise
end

check.call("runtime verify accepts filter-only customization with baseline at first rule") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request("FAKE\t*.filter-only.example"))
  runtime = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  raise unless OpenClashCustomizer.verify_runtime(result.config, YAML.dump(runtime), result.state)
end

check.call("networks are canonicalized without ipaddr") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request(
    "RULE\tIP-CIDR\t198.51.100.87/24\tDIRECT",
    "RULE\tIP-CIDR6\t2001:0db8:0000:0000:0001:0000:0000:0001/64\tAI"
  ))
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  raise unless parsed["rules"][0] == "IP-CIDR,198.51.100.0/24,DIRECT"
  raise unless parsed["rules"][1] == "IP-CIDR6,2001:db8::/64,AI"
end

check.call("invalid network prefixes are rejected") do
  ["RULE\tIP-CIDR\t192.0.2.1/33\tDIRECT", "RULE\tIP-CIDR6\t2001:db8::1/129\tDIRECT", "RULE\tIP-CIDR6\t2001:::1\tDIRECT"].each do |line|
    begin
      OpenClashCustomizer.render(YAML.dump(config), "", request(line))
    rescue StandardError
      next
    end
    raise "expected network rejection"
  end
end

check.call("yaml aliases are rejected") do
  aliased = "---\nproxies: []\nproxy-groups: []\ndns:\n  fake-ip-filter: &filters [\"*.lan\"]\nextra: *filters\nrules: []\n"
  begin
    OpenClashCustomizer.render(aliased, "", request)
  rescue StandardError
    next
  end
  raise "expected alias rejection"
end

check.call("root config Symbol scalars are bounded and preserved") do
  symbolic = YAML.safe_load(YAML.dump(config), permitted_classes: [Symbol], aliases: true)
  symbolic["root-owned-metadata"] = :preserved
  result = OpenClashCustomizer.render(YAML.dump(symbolic), "", request)
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: false)
  raise unless parsed["root-owned-metadata"] == :preserved
end

check.call("binary state keeps Unicode policy names through render and verify") do
  changed = config
  name = "业务组🙂"
  changed["proxy-groups"] << {"name" => name, "type" => "select", "proxies" => ["DIRECT"]}
  incoming = request("RULE\tDOMAIN\texample.test\t#{name}").b
  result = OpenClashCustomizer.render(YAML.dump(changed), "", incoming)
  raise unless OpenClashCustomizer.verify(result.config, result.state.b)
  raise unless YAML.safe_load(result.config)["rules"].include?("DOMAIN,example.test,#{name}")
end

check.call("policies reject control characters without rejecting UTF-8 bytes") do
  ((0..31).to_a + (127..159).to_a).each do |codepoint|
    rejected = false
    begin
      OpenClashCustomizer.normalize_rule(["DOMAIN", "example.test", "Group" + codepoint.chr(Encoding::UTF_8) + "X"])
    rescue RuntimeError => error
      raise unless error.message == "POLICY"
      rejected = true
    end
    raise "control policy accepted" unless rejected
  end
end

check.call("invalid UTF-8 state is rejected before policy matching") do
  rejected = false
  begin
    OpenClashCustomizer.parse_state(request("RULE\tDOMAIN\texample.test\tGroup\xff".b))
  rescue RuntimeError => error
    raise unless error.message == "STATE_ENCODING"
    rejected = true
  end
  raise "invalid state accepted" unless rejected
end

puts "CUSTOMIZER_TESTS=#{tests}/#{tests}"
