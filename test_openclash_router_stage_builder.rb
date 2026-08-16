#!/usr/bin/env ruby
# frozen_string_literal: true
require "yaml"
require_relative "openclash_router_stage_builder"

def proxy(name, type, server, tfo = nil)
  value = {"name"=>name,"type"=>type,"server"=>server,"port"=>443,"password"=>"synthetic","udp"=>true,"cipher"=>"aes-256-cfb","protocol"=>"origin","obfs"=>"plain"}
  value["tfo"] = tfo unless tfo.nil?
  value
end

business = RouterStageBuilder::BUSINESS_GROUPS
base = {"proxies"=>[proxy("Base","anytls","base.example.invalid")],
        "proxy-groups"=>business.map{|name|{"name"=>name,"type"=>"select","proxies"=>["Base"]}},
        "rules"=>["MATCH,✈️Final"],"dns"=>{"nameserver"=>["https://dns.example.invalid/dns-query"],"proxy-server-nameserver"=>["https://proxy.example.invalid/dns-query"]}}
names = %w[HK JP SG US TW OT]
maying_proxies = names.map{|name| proxy("M-#{name}","ssr","#{name.downcase}.example.invalid",false)}
source_names = %w[HK-Auto JP-Auto SG-Auto US-Auto TW-Auto 🍀\ Others]
maying = {"proxies"=>maying_proxies,"proxy-groups"=>source_names.zip(maying_proxies).map{|group,node|{"name"=>group,"type"=>"url-test","proxies"=>[node["name"]]}}}
runtime = YAML.safe_load(YAML.dump(base), permitted_classes:[Symbol], aliases:true)
runtime["proxies"] << {"name"=>"Supplement","type"=>"vless","server"=>"192.0.2.1","port"=>443}
runtime["proxy-groups"].first["proxies"] << "Supplement"

tests=[]
def check(tests,name)
  yield
  tests << [name,true]
  puts "PASS #{name}"
rescue StandardError
  tests << [name,false]
  puts "FAIL #{name}"
end

builder=RouterStageBuilder.new
check(tests,"dynamic build preserves base and applies normalized Maying") do
  result=builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump(maying),runtime_bytes:YAML.dump(runtime),expected_maying_count:6)
  candidate=YAML.safe_load(result.candidate,permitted_classes:[Symbol],aliases:true)
  raise unless result.receipt["decision"]=="PASS" && result.receipt["candidate_proxy_count"]==8
  raise unless candidate["proxies"].first==base["proxies"].first && candidate["rules"]==base["rules"]
  raise unless candidate["proxies"].select{|p|p["type"]=="ssr"}.all?{|p|p["tfo"]==false}
  raise unless candidate["dns"]["proxy-server-nameserver-policy"].length==6
end

check(tests,"managed region references in runtime are rebuilt without duplication") do
  managed_runtime=YAML.safe_load(YAML.dump(runtime),permitted_classes:[Symbol],aliases:true)
  managed_runtime["proxies"].concat(YAML.safe_load(YAML.dump(maying_proxies),permitted_classes:[Symbol],aliases:true))
  RouterStageBuilder::REGIONS.each_with_index do |(managed_name,_),index|
    managed_runtime["proxy-groups"] << {"name"=>managed_name,"type"=>"url-test","proxies"=>[maying_proxies[index]["name"]]}
  end
  managed_names=RouterStageBuilder::REGIONS.map(&:first)
  managed_runtime["proxy-groups"].select{|group|business.include?(group["name"])}.each do |group|
    group["proxies"].concat(managed_names)
  end
  result=builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump(maying),runtime_bytes:YAML.dump(managed_runtime),expected_maying_count:6)
  candidate=YAML.safe_load(result.candidate,permitted_classes:[Symbol],aliases:true)
  names=candidate["proxy-groups"].map{|group|group["name"]}
  raise unless managed_names.all?{|name|names.count(name)==1}
  candidate["proxy-groups"].select{|group|business.include?(group["name"])}.each do |group|
    raise unless (group["proxies"] & managed_names).sort==managed_names.sort
    raise unless group["proxies"].uniq==group["proxies"]
  end
end

check(tests,"unknown runtime group addition remains rejected") do
  unknown_runtime=YAML.safe_load(YAML.dump(runtime),permitted_classes:[Symbol],aliases:true)
  unknown_runtime["proxy-groups"].first["proxies"] << "Unknown-Managed-Group"
  begin
    builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump(maying),runtime_bytes:YAML.dump(unknown_runtime),expected_maying_count:6)
  rescue StandardError => error
    raise unless error.message=="RUNTIME_GROUP_ADDITION"
    next
  end
  raise
end

check(tests,"name-only base rotation replaces stale runtime nodes") do
  rotated_base=YAML.safe_load(YAML.dump(base),permitted_classes:[Symbol],aliases:true)
  rotated_base["proxies"]=[proxy("Base-Rotated-A","anytls","base.example.invalid"),proxy("Base-Rotated-B","anytls","base.example.invalid")]
  rotated_base["proxy-groups"].each{|group|group["proxies"]=["Base-Rotated-A","Base-Rotated-B"]}
  rotated_runtime=YAML.safe_load(YAML.dump(runtime),permitted_classes:[Symbol],aliases:true)
  rotated_runtime["proxies"].insert(1,proxy("Base-Old-B","anytls","base.example.invalid"))
  rotated_runtime["proxy-groups"].each{|group|group["proxies"]=["Base","Base-Old-B"]}
  rotated_runtime["proxy-groups"].first["proxies"] << "Supplement"
  result=builder.build(base_bytes:YAML.dump(rotated_base),maying_bytes:YAML.dump(maying),runtime_bytes:YAML.dump(rotated_runtime),expected_maying_count:6)
  candidate=YAML.safe_load(result.candidate,permitted_classes:[Symbol],aliases:true)
  candidate_names=candidate["proxies"].map{|proxy|proxy["name"]}
  raise unless result.receipt["rotated_runtime_proxy_count"]==2
  raise unless candidate_names.include?("Base-Rotated-A") && candidate_names.include?("Base-Rotated-B")
  raise if candidate_names.include?("Base") || candidate_names.include?("Base-Old-B")
  raise unless candidate_names.include?("Supplement")
end

check(tests,"nonmatching stale runtime proxy remains rejected") do
  stale_runtime=YAML.safe_load(YAML.dump(runtime),permitted_classes:[Symbol],aliases:true)
  stale_runtime["proxies"] << proxy("Unknown-Old","anytls","unknown.example.invalid")
  begin
    builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump(maying),runtime_bytes:YAML.dump(stale_runtime),expected_maying_count:6)
  rescue StandardError => error
    raise unless error.message=="RUNTIME_PROXY_ROTATION"
    next
  end
  raise
end

check(tests,"name rotation with changed group membership remains rejected") do
  rotated_base=YAML.safe_load(YAML.dump(base),permitted_classes:[Symbol],aliases:true)
  rotated_base["proxies"]=[proxy("Base-Rotated","anytls","base.example.invalid")]
  rotated_base["proxy-groups"].first["proxies"]=["Base-Rotated"]
  begin
    builder.build(base_bytes:YAML.dump(rotated_base),maying_bytes:YAML.dump(maying),runtime_bytes:YAML.dump(runtime),expected_maying_count:6)
  rescue StandardError => error
    raise unless error.message=="RUNTIME_GROUP_ROTATION"
    next
  end
  raise
end

check(tests,"malformed managed runtime region remains rejected") do
  malformed=YAML.safe_load(YAML.dump(runtime),permitted_classes:[Symbol],aliases:true)
  malformed["proxy-groups"] << {"name"=>RouterStageBuilder::REGIONS.first.first,"type"=>"select","proxies"=>["Unknown SSR"]}
  begin
    builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump(maying),runtime_bytes:YAML.dump(malformed),expected_maying_count:6)
  rescue StandardError => error
    raise unless error.message=="RUNTIME_MANAGED_REGION"
    next
  end
  raise
end

check(tests,"recursive YAML aliases are rejected before deep copy") do
  recursive_base=YAML.safe_load(YAML.dump(base),permitted_classes:[Symbol],aliases:true)
  recursive_base["proxies"].first["recursive"]=recursive_base["proxies"].first
  begin
    builder.build(base_bytes:YAML.dump(recursive_base),maying_bytes:YAML.dump(maying),runtime_bytes:YAML.dump(runtime),expected_maying_count:6)
  rescue StandardError => error
    raise unless error.message=="YAML_ALIAS"
    next
  end
  raise
end

check(tests,"IP literal proxy servers do not create DNS policy host entries") do
  addresses=["192.0.2.1","198.51.100.2","203.0.113.3","2001:db8::4","[2001:db8::5]","2001:db8::6"]
  ip_proxies=maying_proxies.each_with_index.map{|item,index|item.merge("server"=>addresses[index])}
  ip_maying={"proxies"=>ip_proxies,"proxy-groups"=>source_names.zip(ip_proxies).map{|group,node|{"name"=>group,"type"=>"url-test","proxies"=>[node["name"]]}}}
  result=builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump(ip_maying),runtime_bytes:YAML.dump(runtime),expected_maying_count:6)
  candidate=YAML.safe_load(result.candidate,permitted_classes:[Symbol],aliases:true)
  raise unless candidate.dig("dns","proxy-server-nameserver-policy")=={}
  raise unless result.receipt["dns_policy_host_count"]==0
end

check(tests,"group-less converter output derives closed flag partition") do
  flagged_names=["🇭🇰 HK","🇯🇵 JP","🇸🇬 SG","🇺🇸 US","🇨🇳 TW","No Flag"]
  flagged_proxies=flagged_names.each_with_index.map{|name,index| proxy(name,"ssr","f#{index}.example.invalid",false)}
  group_less={"proxies"=>flagged_proxies,"proxy-groups"=>[]}
  result=builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump(group_less),runtime_bytes:YAML.dump(runtime),expected_maying_count:6)
  candidate=YAML.safe_load(result.candidate,permitted_classes:[Symbol],aliases:true)
  region_map=candidate["proxy-groups"].select{|group|RouterStageBuilder::REGIONS.map(&:first).include?(group["name"])}.to_h{|group|[group["name"],group["proxies"]]}
  raise unless region_map["Maying-HK-Auto"]==["🇭🇰 HK"] && region_map["Maying-TW-Auto"]==["🇨🇳 TW"]
  raise unless region_map["Maying-Others-Auto"]==["No Flag"]
end

check(tests,"partial converter region groups remain rejected") do
  partial={"proxies"=>maying_proxies,"proxy-groups"=>maying["proxy-groups"][0,1]}
  begin
    builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump(partial),runtime_bytes:YAML.dump(runtime),expected_maying_count:6)
  rescue StandardError => error
    raise unless error.message=="REGION_GROUP_SHAPE"
    next
  end
  raise
end

check(tests,"ambiguous controlled flags remain rejected") do
  flagged=[proxy("🇭🇰🇯🇵 Ambiguous","ssr","ambiguous.example.invalid",false)] +
          [proxy("🇯🇵 JP","ssr","j.example.invalid",false),proxy("🇸🇬 SG","ssr","s.example.invalid",false),
           proxy("🇺🇸 US","ssr","u.example.invalid",false),proxy("🇨🇳 TW","ssr","t.example.invalid",false),
           proxy("Other","ssr","o.example.invalid",false)]
  begin
    builder.build(base_bytes:YAML.dump(base),maying_bytes:YAML.dump({"proxies"=>flagged,"proxy-groups"=>[]}),runtime_bytes:YAML.dump(runtime),expected_maying_count:6)
  rescue StandardError => error
    raise unless error.message=="REGION_NAME_AMBIGUOUS"
    next
  end
  raise
end

{"count mismatch"=>[7,maying],"tfo true"=>[6,maying.merge("proxies"=>maying_proxies.map{|p|p.merge("tfo"=>true)})],"duplicate node"=>[6,maying.merge("proxies"=>maying_proxies+[maying_proxies.first])],"region missing"=>[6,maying.merge("proxy-groups"=>maying["proxy-groups"][0,5])],"existing DNS policy"=>[6,maying]}.each do |name,(count,input)|
  check(tests,"reject #{name}") do
    altered=YAML.safe_load(YAML.dump(base),permitted_classes:[Symbol],aliases:true)
    altered["dns"]["proxy-server-nameserver-policy"]={"x"=>["y"]} if name=="existing DNS policy"
    begin
      builder.build(base_bytes:YAML.dump(altered),maying_bytes:YAML.dump(input),runtime_bytes:YAML.dump(runtime),expected_maying_count:count)
    rescue StandardError
      next
    end
    raise
  end
end
puts "ROUTER_BUILDER_TESTS=#{tests.length} PASS=#{tests.count{|_,ok|ok}} FAIL=#{tests.count{|_,ok|!ok}}"
exit 1 unless tests.all?{|_,ok|ok}
