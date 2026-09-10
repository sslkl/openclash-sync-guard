#!/usr/bin/env ruby
# frozen_string_literal: true
require_relative '../openclash_customizer'
require 'json'
C = OpenClashCustomizer

def fixture
  YAML.dump({"proxies" => [
    {"name" => "上游 A", "type" => "ss", "server" => "upstream.example.com", "port" => 443, "cipher" => "aes-128-gcm", "password" => "synthetic-upstream"},
    {"name" => "上游 B", "type" => "socks5", "server" => "second.example.com", "port" => 1080}
  ], "proxy-groups" => [{"name" => "Proxies", "type" => "select", "proxies" => ["上游 A", "上游 B"]}],
  "dns" => {"fake-ip-filter" => ["*.lan"]}, "rules" => ["MATCH,Proxies"]})
end

def profile(overrides = {})
  {"node" => "上游 A", "type" => "socks5", "server" => "exit.example.com", "port" => 1080, "username" => "user", "password" => "synthetic-secret"}.merge(overrides)
end

def add(bytes = fixture, state = '', overrides = {})
  C.render(bytes, state, C.chain_request(state, {"operation" => "upsert", "chain" => profile(overrides)}))
end

def assert(value, message = 'assertion failed')
  raise message unless value
end

def rejects(label = nil)
  begin
    yield
  rescue StandardError => error
    raise if label && !error.message.include?(label)
    return
  end
  raise 'expected rejection'
end

count = 0
check = lambda do |name, &block|
  block.call
  count += 1
  puts "PASS #{name}"
end

check.call('direction, name stability and original preservation') do
  result = add
  data = C.safe_yaml(result.config)
  upstream, exit_proxy = C.chain_pair(C.parse_state(result.state).chains.first, C.parse_state(result.state).owned_chains.first)
  assert(data['proxies'].include?(upstream))
  assert(data['proxies'].include?(exit_proxy))
  assert(exit_proxy['dialer-proxy'] == upstream['name'])
  assert(!upstream.key?('dialer-proxy') && exit_proxy['server'] == 'exit.example.com')
  assert(data['proxy-groups'] == C.safe_yaml(fixture)['proxy-groups'])
  assert(C.verify(result.config, result.state))
  assert(C.verify_runtime(result.config, result.config, result.state))
end
check.call('cancel restores exact original definitions and rules') do
  one = add
  removed = C.render(one.config, one.state, C.chain_request(one.state, {'operation' => 'remove', 'node' => '上游 A'}))
  assert(C.safe_yaml(removed.config) == C.safe_yaml(fixture))
  assert(C.parse_state(removed.state).chains.empty?)
end
check.call('no-op does not rewrite config or state') do
  one = add
  second = add(one.config, one.state)
  assert(second.config == one.config && second.state == one.state)
end
check.call('ordinary custom request preserves chains and secrets') do
  one = add
  next_result = C.render(one.config, one.state, C::VERSION + "\nRULE\tDOMAIN\tnew.example.com\tDIRECT\n")
  assert(C.parse_state(next_result.state).chains == C.parse_state(one.state).chains)
  assert(C.safe_yaml(next_result.config)['proxies'] == C.safe_yaml(one.config)['proxies'])
end
check.call('chain update preserves rule ownership') do
  baseline = C.render(fixture, '', C::VERSION + "\nRULE\tDOMAIN\tnew.example.com\tDIRECT\n")
  result = add(baseline.config, baseline.state)
  assert(C.parse_state(result.state).owned_rules == C.parse_state(baseline.state).owned_rules)
end
check.call('subscription replay rebuilds from fresh upstream') do
  one = add
  fresh = C.safe_yaml(fixture)
  fresh['proxies'][0]['port'] = 8443
  request = one.state.lines.reject { |line| line.start_with?('OWNED_') }.join
  replayed = C.render(YAML.dump(fresh), '', request, remove_owned: false)
  original = C.parse_state(replayed.state).owned_chains.first['original']
  assert(original['port'] == 8443)
  assert(C.verify(replayed.config, replayed.state))
end
check.call('two chains isolate cancellation and updates') do
  one = add
  two = add(one.config, one.state, 'node' => '上游 B', 'server' => 'exit2.example.com')
  removed = C.render(two.config, two.state, C.chain_request(two.state, {'operation' => 'remove', 'node' => '上游 A'}))
  assert(C.parse_state(removed.state).chains.map { |x| x['node'] } == ['上游 B'])
  assert(C.verify(removed.config, removed.state))
  assert(C.safe_yaml(removed.config)['proxies'].first == C.safe_yaml(fixture)['proxies'].first)
end
check.call('update rotates generated live linkage identity') do
  one = add
  two = add(one.config, one.state, 'password' => 'new-synthetic')
  assert(C.safe_yaml(one.config)['proxies'][0]['dialer-proxy'] != C.safe_yaml(two.config)['proxies'][0]['dialer-proxy'])
end
check.call('keep-password succeeds only for identical endpoint identity') do
  one = add
  retained = profile.reject { |key, _| key == 'password' }.merge('keep_password' => true)
  manifest = C.chain_request(one.state, {'operation' => 'upsert', 'chain' => retained})
  assert(C.render(one.config, one.state, manifest).state == one.state)
  %w[server username type port tls cipher].each do |field|
    altered = retained.merge(field => {'server' => 'other.example.com', 'username' => 'other', 'type' => 'http', 'port' => 1081, 'tls' => true, 'cipher' => 'aes-128-gcm'}[field])
    rejects { C.chain_request(one.state, {'operation' => 'upsert', 'chain' => altered}) }
  end
end
check.call('read never returns source or endpoint secrets') do
  one = add
  view = C.chain_view(one.config, one.state)
  rendered = C.chain_json(view)
  assert(!rendered.include?('synthetic-') && !rendered.include?('"password"') && !rendered.include?('original'))
  assert(view['chains'].first['has_password'] == true)
  assert(view['nodes'].length == 2 && JSON.parse(rendered)['ok'])
end
check.call('configuration drift is fail closed on read update and cancel') do
  one = add
  modified = C.safe_yaml(one.config)
  modified['proxies'][0]['server'] = 'foreign.example.com'
  modified = YAML.dump(modified)
  rejects('CHAIN_DRIFT') { C.chain_view(modified, one.state) }
  rejects('CHAIN_DRIFT') { add(modified, one.state) }
  rejects('CHAIN_DRIFT') { C.render(modified, one.state, C.chain_request(one.state, {'operation' => 'remove', 'node' => '上游 A'})) }
end
check.call('original dialer, reserved prefix and include-all groups are rejected') do
  data = C.safe_yaml(fixture)
  data['proxies'][0]['dialer-proxy'] = '上游 B'
  rejects('CHAIN_ORIGINAL') { add(YAML.dump(data)) }
  data = C.safe_yaml(fixture)
  data['proxy-groups'][0]['include-all'] = true
  rejects('CHAIN_INCLUDE_ALL') { add(YAML.dump(data)) }
  rejects('CHAIN_NODE') { add(fixture, '', 'node' => '__OCS_UP_bad') }
end
check.call('unsafe endpoint syntax and local privileged addresses rejected') do
  ['http://example.com', 'a.com/path', 'localhost', 'x.localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', '224.0.0.1', '::1', '::', 'fe80::1', 'ff02::1', '::ffff:7f00:1', '::7f00:1', "bad.com\n"].each do |host|
    rejects { C.chain_profile(profile('server' => host)) }
  end
end
check.call('private vpn addresses and normalized IPv6 allowed') do
  ['192.168.254.254', '10.254.254.1', '100.64.2.3', 'fd00::2', '2001:db8::2'].each do |host|
    assert(C.chain_profile(profile('server' => host))['server'] == host)
  end
end
check.call('strict authentication protocol and field bounds') do
  [0, -1, 65536, true, '1080'].each { |port| rejects { C.chain_profile(profile('port' => port)) } }
  rejects { C.chain_profile(profile('password' => 'x' * 256)) }
  rejects { C.chain_profile(profile('skip-cert-verify' => true)) }
  rejects { C.chain_profile(profile('tls' => 'false')) }
  rejects { C.chain_profile(profile('sni' => 'cert.example.com')) }
  rejects { C.chain_profile(profile('password' => "bad\nsecret")) }
  rejects { C.chain_profile(profile('password' => '')) }
  rejects { C.chain_profile(profile('keep_password' => true)) }
end
check.call('HTTP TLS and shadowsocks produce supported fields') do
  http = add(fixture, '', 'type' => 'http', 'tls' => true, 'sni' => 'cert.example.com')
  assert(C.safe_yaml(http.config)['proxies'][0]['tls'])
  ss = profile('type' => 'ss', 'cipher' => 'aes-128-gcm').reject { |key, _| key == 'username' }
  manifest = C.chain_request('', {'operation' => 'upsert', 'chain' => ss})
  rendered = C.render(fixture, '', manifest)
  assert(C.verify(rendered.config, rendered.state))
end
check.call('SOCKS TLS rejects unsupported SNI instead of silently ignoring it') do
  rejects('CHAIN_SNI') { C.chain_profile(profile('tls' => true, 'sni' => 'cert.example.com')) }
end
check.call('runtime cannot silently disable endpoint TLS certificate verification') do
  one = add(fixture, '', 'type' => 'http', 'tls' => true, 'sni' => 'cert.example.com')
  config = C.safe_yaml(one.config)
  config['proxies'][0]['skip-cert-verify'] = true
  rejects('CHAIN_DRIFT') { C.verify_chains(config, C.parse_state(one.state), runtime: true) }
end
check.call('duplicate chain and unauthorized ownership records rejected') do
  one = add
  line = one.state.lines.find { |text| text.start_with?("CHAIN\t") }
  rejects('CHAIN_DUPLICATE') { C.parse_state(one.state + line) }
  rejects('REQUEST_OWNERSHIP') { C.parse_state(one.state, request: true) }
  rejects { C.parse_state(C::VERSION + "\nCHAIN_SET\nCHAIN\t!!!!\n") }
end
check.call('JSON parser enforces duplicate depth number and byte limits') do
  rejects { C::StrictJson.new('[' * 40 + '0' + ']' * 40).parse }
  rejects { C::StrictJson.new('{"x":1,"x":2}').parse }
  rejects { C::StrictJson.new('1e9999').parse }
  rejects { C::StrictJson.new(' ' * (2 * 1024 * 1024 + 1)).parse }
  assert(C::StrictJson.new(C.chain_json({'x' => "quote\"\\\n\t中文", 'n' => 12})).parse['n'] == 12)
end

# Stub only controller transport; exercise actual proof classification.
one = add
node = '上游 A'
upstream = C.safe_yaml(one.config)['proxies'][0]['dialer-proxy']
live = {node => {'id' => 'live-exit', 'dialer-proxy' => upstream}, upstream => {'id' => 'live-upstream', 'dialer-proxy' => ''}}
original_proxies = C.method(:controller_proxies)
original_delay = C.method(:controller_delay)
begin
  C.define_singleton_method(:controller_proxies) { |_cfg| live }
  C.define_singleton_method(:controller_delay) { |_cfg, _name| true }
  check.call('test requires configuration runtime linkage and fixed chain probe') do
    assert(C.chain_test(one.config, one.config, one.state, node)['verdict'] == 'PASS')
  end
  check.call('unreachable full chain fails even when upstream works') do
    C.define_singleton_method(:controller_delay) { |_cfg, name| name != node }
    test = C.chain_test(one.config, one.config, one.state, node)
    assert(test['verdict'] == 'FAIL' && test['upstream'] == 'REACHABLE' && test['chain'] == 'UNREACHABLE')
  end
  check.call('successful exit probe alone cannot mask an unavailable upstream probe') do
    C.define_singleton_method(:controller_delay) { |_cfg, name| name == node }
    test = C.chain_test(one.config, one.config, one.state, node)
    assert(test['verdict'] == 'UNKNOWN' && test['upstream'] == 'UNREACHABLE' && test['chain'] == 'REACHABLE')
  end
  check.call('missing linkage cannot be called successful') do
    C.define_singleton_method(:controller_delay) { |_cfg, _name| true }
    live[node].delete('dialer-proxy')
    assert(C.chain_test(one.config, one.config, one.state, node)['verdict'] == 'UNKNOWN')
  end
  check.call('wrong linkage fails without sending any probe') do
    live[node]['dialer-proxy'] = 'DIRECT'
    C.define_singleton_method(:controller_delay) { |_cfg, _name| raise 'must not probe' }
    assert(C.chain_test(one.config, one.config, one.state, node)['verdict'] == 'FAIL')
  end
  check.call('core reload during probe cannot give false success') do
    live[node]['dialer-proxy'] = upstream
    C.define_singleton_method(:controller_delay) { |_cfg, _name| true }
    calls = 0
    C.define_singleton_method(:controller_proxies) do |_cfg|
      calls += 1
      calls == 1 ? live : live.merge(node => live[node].merge('id' => 'reloaded'))
    end
    assert(C.chain_test(one.config, one.config, one.state, node)['verdict'] == 'UNKNOWN')
  end
ensure
  C.define_singleton_method(:controller_proxies, original_proxies)
  C.define_singleton_method(:controller_delay, original_delay)
end
puts "CHAIN_CUSTOMIZER_TESTS=#{count}/#{count}"
