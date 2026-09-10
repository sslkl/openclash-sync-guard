#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require_relative "../openclash_customizer"

raise "ARGS" unless ARGV.length == 2
static_path, runtime_path = ARGV
static_bytes = File.binread(static_path)
runtime_bytes = File.binread(runtime_path)
request = [
  OpenClashCustomizer::VERSION,
  "RULE\tDOMAIN\tsyncsvc-runtime-shape.invalid\tDIRECT",
  "RULE\tIP-CIDR\t192.0.2.123/24\tAI",
  "RULE\tIP-CIDR6\t2001:db8:ffff::1/64\tProxies",
  "FAKE\t*.syncsvc-runtime-shape.invalid",
].join("\n") + "\n"
rendered = OpenClashCustomizer.render(static_bytes, "", request)
static_config = OpenClashCustomizer.safe_yaml(static_bytes)
runtime_config = OpenClashCustomizer.safe_yaml(runtime_bytes)
baseline_rules = static_config["rules"]
runtime_rules = runtime_config["rules"]
raise "CONFIG" unless baseline_rules.is_a?(Array) && runtime_rules.is_a?(Array)
anchor = baseline_rules.find { |rule| runtime_rules.include?(rule) }
raise "ANCHOR" unless anchor
anchor_index = runtime_rules.index(anchor)

model = OpenClashCustomizer.parse_state(rendered.state)
owned_text = model.owned_rules.map { |rule| OpenClashCustomizer.rule_text(rule) }
synthetic = Marshal.load(Marshal.dump(runtime_config))
synthetic["rules"] = runtime_rules.dup
synthetic["rules"].insert(anchor_index, *owned_text)
synthetic["dns"]["fake-ip-filter"] += model.owned_filters
synthetic_bytes = YAML.dump(synthetic)
raise "VERIFY" unless OpenClashCustomizer.verify_runtime(rendered.config, synthetic_bytes, rendered.state)

late = Marshal.load(Marshal.dump(runtime_config))
late["rules"] = runtime_rules.dup + owned_text
late["dns"]["fake-ip-filter"] += model.owned_filters
begin
  OpenClashCustomizer.verify_runtime(rendered.config, YAML.dump(late), rendered.state)
rescue StandardError
  puts "REAL_RUNTIME_PREFIX=#{anchor_index}"
  puts "REAL_RUNTIME_VERIFY=PASS"
  puts "LATE_CUSTOM_RULES=REJECTED"
  exit 0
end
raise "LATE_PRIORITY_ACCEPTED"
