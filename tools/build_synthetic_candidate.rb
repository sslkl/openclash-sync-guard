#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require_relative "../openclash_router_stage_builder"

business = RouterStageBuilder::BUSINESS_GROUPS
base_proxy = {
  "name" => "Synthetic-Base", "type" => "ss", "server" => "base.example.invalid",
  "port" => 443, "cipher" => "aes-128-gcm", "password" => "synthetic", "udp" => true
}
base = {
  "mixed-port" => 7890, "allow-lan" => false, "mode" => "rule", "log-level" => "warning",
  "proxies" => [base_proxy],
  "proxy-groups" => business.map { |name| { "name" => name, "type" => "select", "proxies" => [base_proxy["name"]] } },
  "rules" => ["MATCH,✈️Final"],
  "dns" => {
    "enable" => true, "ipv6" => false,
    "nameserver" => ["https://1.1.1.1/dns-query"],
    "proxy-server-nameserver" => ["https://8.8.8.8/dns-query"]
  }
}
region_names = %w[HK-Auto JP-Auto SG-Auto US-Auto TW-Auto 🍀\ Others]
maying_proxies = Array.new(6) do |index|
  {
    "name" => "Synthetic-Maying-#{index + 1}", "type" => "ssr",
    "server" => "m#{index + 1}.example.invalid", "port" => 443,
    "cipher" => "aes-256-cfb", "protocol" => "origin", "obfs" => "plain",
    "password" => "synthetic", "udp" => true, "tfo" => false
  }
end
maying = {
  "proxies" => maying_proxies,
  "proxy-groups" => region_names.zip(maying_proxies).map do |group, proxy|
    { "name" => group, "type" => "url-test", "proxies" => [proxy["name"]] }
  end
}
runtime = YAML.safe_load(YAML.dump(base), permitted_classes: [], aliases: false)
result = RouterStageBuilder.new.build(
  base_bytes: YAML.dump(base), maying_bytes: YAML.dump(maying),
  runtime_bytes: YAML.dump(runtime), expected_maying_count: maying_proxies.length
)
raise "BUILD_HOLD" unless result.receipt["decision"] == "PASS"
STDOUT.write(result.candidate)
