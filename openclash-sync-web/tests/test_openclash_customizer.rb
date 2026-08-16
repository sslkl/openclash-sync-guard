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
    "RULE\tIP-CIDR\t203.0.113.7\tAI",
    "RULE\tIP-CIDR6\t2001:db8::1\tProxies",
    "FAKE\t+.example.com"
  ))
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  raise unless parsed["rules"][0, 3] == ["DOMAIN,api.example.com,DIRECT", "IP-CIDR,203.0.113.7/32,AI", "IP-CIDR6,2001:db8::1/128,Proxies"]
  raise unless parsed["dns"]["fake-ip-filter"] == ["*.lan", "+.example.com"]
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

check.call("baseline identical rule is explicitly owned at priority prefix") do
  result = OpenClashCustomizer.render(YAML.dump(config), "", request("RULE\tDOMAIN-SUFFIX\tbase.test\tProxies"))
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  state = OpenClashCustomizer.parse_state(result.state)
  raise unless parsed["rules"].first == "DOMAIN-SUFFIX,base.test,Proxies"
  raise unless parsed["rules"].count("DOMAIN-SUFFIX,base.test,Proxies") == 2
  raise unless state.owned_rules == [["DOMAIN-SUFFIX", "base.test", "Proxies"]]
  cleared = OpenClashCustomizer.render(result.config, result.state, request)
  restored = YAML.safe_load(cleared.config, permitted_classes: [Symbol], aliases: true)
  raise unless restored["rules"].count("DOMAIN-SUFFIX,base.test,Proxies") == 1
end

check.call("overlay keeps baseline and owns custom prefix") do
  desired = request("RULE\tDOMAIN-SUFFIX\tbase.test\tProxies", "FAKE\t*.overlay.test")
  result = OpenClashCustomizer.render(YAML.dump(config), "", desired, remove_owned: false)
  parsed = YAML.safe_load(result.config, permitted_classes: [Symbol], aliases: true)
  state = OpenClashCustomizer.parse_state(result.state)
  raise unless parsed["rules"].first == "DOMAIN-SUFFIX,base.test,Proxies"
  raise unless parsed["rules"].count("DOMAIN-SUFFIX,base.test,Proxies") == 2
  raise unless state.owned_rules.length == 1 && state.owned_filters == ["*.overlay.test"]
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
  raise unless output.include?("GROUP\tAI") && output.include?("RULE\tDOMAIN-SUFFIX\texample.com\tAI") && output.include?("FAKE\t*.example.com")
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
  runtime["rules"] = ["DOMAIN,openclash.internal,DIRECT", "GEOIP,LAN,DIRECT"] + runtime["rules"]
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
    raise unless error.message == "RUNTIME_STATIC_BLOCK"
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
  ["RULE\tIP-CIDR\t203.0.113.1/33\tDIRECT", "RULE\tIP-CIDR6\t2001:db8::1/129\tDIRECT", "RULE\tIP-CIDR6\t2001:::1\tDIRECT"].each do |line|
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

puts "CUSTOMIZER_TESTS=#{tests}/#{tests}"
