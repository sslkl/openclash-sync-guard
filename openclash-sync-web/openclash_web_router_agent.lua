#!/usr/bin/lua
local json = require("luci.jsonc")
local nixio = require("nixio")
local fs = require("nixio.fs")

local target = arg[1]
if target ~= "router_a" and target ~= "router_b" then os.exit(10) end
local raw = io.read(2097153) or ""
if #raw < 2 or #raw > 2097152 then os.exit(11) end
local request = json.parse(raw)
if type(request) ~= "table" or request.target ~= target or type(request.action) ~= "string" then os.exit(12) end

local main = "ProviderBase-ProviderSource.yaml"
local base = "ProviderBase.yaml"
local source = "ProviderSource.yaml"
local allowed = {[main]=true,[base]=true,[source]=true}
local config_root = "/etc/openclash/config/"
local stage_client = "/etc/openclash/publisher-v4/bin/openclash_router_stage_client.sh"
local custom_transaction = "/etc/openclash/publisher-v4/web/openclash_custom_transaction.sh"
local customizer = "/etc/openclash/publisher-v4/web/openclash_customizer.rb"
local runtime = "/etc/openclash/" .. main

local function reply(value) io.write(json.stringify(value)); io.write("\n") end
local function failure(message) reply({ok=false,message=message}); os.exit(0) end
local function shell_quote(value) return "'" .. value:gsub("'", "'\\''") .. "'" end
local function command_ok(command)
  local a,b,c = os.execute(command)
  if type(a) == "number" then return a == 0 end
  return a == true and c == 0
end
-- Lua 5.1 pipe:close() only confirms pclose itself, not the command status.
-- Keep exit/exec inside a subshell so the parent always appends the status.
-- Reject any marker in command output; stdout cannot forge a successful frame.
local function capture(command)
  local pipe = io.popen("(\n" .. command .. "\n); openclash_pipe_status=$?; printf '\nOPENCLASH_PIPE_STATUS=%s\n' \"$openclash_pipe_status\"")
  if not pipe then return "",false end
  local output = pipe:read(2097153)
  local closed = pipe:close()
  if type(output) ~= "string" or #output > 2097152 then return "",false end
  local bytes,status = output:match("^(.*)\nOPENCLASH_PIPE_STATUS=([0-9]+)\n$")
  if not bytes or bytes:find("OPENCLASH_PIPE_STATUS",1,true) then return "",false end
  return bytes,closed and status == "0" or false
end
local function sha(path)
  local output,ok = capture("sha256sum " .. shell_quote(path) .. " 2>/dev/null")
  local digest = output:match("^([0-9a-f]+)%s+[^\n]+\n$")
  if not ok or not digest or #digest ~= 64 then return nil end
  return digest
end
local function same_file(left, right)
  if not left or not right then return false end
  for _,field in ipairs({"dev","ino","size","mtime","ctime","nlink","type","uid","gid","modestr"}) do
    if left[field] ~= right[field] then return false end
  end
  return true
end
local function stable_read(path, max)
  local named_before = fs.lstat(path)
  if not named_before or named_before.type ~= "reg" or named_before.nlink ~= 1 or named_before.size > max then return nil end
  local file = nixio.open(path,"r")
  if not file then return nil end
  local opened_before = file:stat()
  if not same_file(named_before,opened_before) then file:close(); return nil end
  local descriptor_path = "/proc/"..nixio.getpid().."/fd/"..file:fileno()
  local digest_before = sha(descriptor_path)
  if not digest_before or file:seek(0,"set") ~= 0 then file:close(); return nil end
  local chunks,total = {},0
  while true do
    local chunk = file:read(8192)
    if not chunk or #chunk == 0 then break end
    total = total + #chunk
    if total > max then file:close(); return nil end
    chunks[#chunks+1] = chunk
  end
  local opened_after = file:stat()
  local digest_after = sha(descriptor_path)
  local named_after = fs.lstat(path)
  file:close()
  if digest_before ~= digest_after or not same_file(opened_before,opened_after) or
     not same_file(opened_after,named_after) or total ~= named_after.size then return nil end
  return table.concat(chunks),digest_after
end
local function journal_value(bytes, key)
  if type(bytes) ~= "string" or type(key) ~= "string" then return nil end
  local value=nil
  for line in bytes:gmatch("([^\n]+)") do
    local current=line:match("^"..key.."=(.*)$")
    if current then
      if value then return nil end
      value=current
    end
  end
  return value
end
local function valid_digest(value)
  return type(value)=="string" and value:match("^[0-9a-f]+$")~=nil and #value==64
end
local function trusted_stage_commit(bytes, expected_target)
  if journal_value(bytes,"ROUTER_STAGE")~="PASS" or journal_value(bytes,"TARGET")~=expected_target or
     journal_value(bytes,"DNS_RESOLVER_REACHABILITY")~="PASS" or
     journal_value(bytes,"ACTIVE_CHANGED")~="false" or journal_value(bytes,"UCI_CHANGED")~="false" or
     journal_value(bytes,"SERVICE_RESTARTED")~="false" then return nil end
  local digest=journal_value(bytes,"CANDIDATE_SHA256")
  return valid_digest(digest) and digest or nil
end
local function custom_result(bytes, marker)
  if journal_value(bytes,marker)~="PASS" or journal_value(bytes,"ACTIVE_CHANGED")~="false" or
     journal_value(bytes,"UCI_CHANGED")~="false" then return nil end
  local digest=journal_value(bytes,"CONFIG_SHA256")
  local state_digest=journal_value(bytes,"STATE_SHA256")
  local restarted=journal_value(bytes,"SERVICE_RESTARTED")
  if not valid_digest(digest) or not valid_digest(state_digest) or
     (restarted~="true" and restarted~="false") then return nil end
  return {sha256=digest,state_sha256=state_digest,service_restarted=restarted=="true"}
end
local function current_custom_result(result)
  if not result then return false end
  local _,digest=stable_read(config_root..main,1048576)
  return digest==result.sha256
end
local function transaction_unknown()
  failure("无法确认主配置事务最终结果；写入或重启状态 UNKNOWN，请重新读取并核对后再操作")
end
local function stage_failure_reason(bytes)
  local reason=journal_value(bytes,"REASON")
  if type(reason)~="string" or #reason>64 or not reason:match("^[A-Z0-9_-]+$") then return nil end
  return reason
end
local function private_path(path, expected_type, mode_string)
  local info=fs.lstat(path)
  return info and info.type==expected_type and info.uid==0 and info.gid==0 and
    type(info.modestr)=="string" and info.modestr == mode_string
end
local function make_temp_file(template, pattern)
  local out,ok = capture("umask 077; mktemp " .. shell_quote(template))
  local path = out:match("^([^\n]+)\n$")
  -- Never delete a path that came from failed or untrusted mktemp output.
  if not ok or not path or not path:match(pattern) or not private_path(path,"reg","rw-------") then return nil end
  return path
end
local function make_temp_dir(template, pattern)
  local out,ok = capture("umask 077; mktemp -d " .. shell_quote(template))
  local path = out:match("^([^\n]+)\n$")
  if not ok or not path or not path:match(pattern) or not private_path(path,"dir","rwx------") then return nil end
  return path
end
local function active_path()
  local out,ok = capture("uci -q get openclash.config.config_path 2>/dev/null")
  local value = out:match("^(/etc/openclash/config/[A-Za-z0-9_-]+%.yaml)\n$")
  return ok and value or nil
end
local function validate_yaml(path, is_main)
  local ruby = "ruby -e 'require \"yaml\"; v=YAML.safe_load(File.binread(ARGV[0]), permitted_classes:[Symbol], aliases:false); abort unless v.is_a?(Hash) && %w[proxies proxy-groups rules].all?{|k|v[k].is_a?(Array)}' " .. shell_quote(path)
  if not command_ok(ruby .. " >/dev/null 2>/dev/null") then return false,"YAML 结构检查未通过" end
  if is_main then
    local out,ok = capture("pidof clash_meta 2>/dev/null")
    local p = out:match("^([1-9][0-9]*)\n$")
    if not ok or not p then return false,"Mihomo 进程状态异常" end
    local core = fs.readlink("/proc/" .. p .. "/exe")
    if not core or not command_ok(shell_quote(core) .. " -t -d /etc/openclash -f " .. shell_quote(path) .. " >/dev/null 2>/dev/null") then return false,"Mihomo 静态检查未通过" end
  end
  return true,nil
end
local function custom_control(value)
  -- Lua patterns operate on bytes; C1 controls are two-byte UTF-8 sequences.
  -- Do not reject continuation bytes inside ordinary Chinese/Emoji names.
  return value:find("[%z\1-\31\127]") or value:find("\194[\128-\159]")
end
local function custom_request(value)
  if type(value) ~= "table" or type(value.rules) ~= "table" or type(value.fake_ip_filter) ~= "table" or
     type(value.supplemental_rules) ~= "table" or type(value.supplemental_fake_ip_filter) ~= "table" then return nil end
  if #value.rules > 256 or #value.fake_ip_filter > 256 or #value.supplemental_rules > 10000 or #value.supplemental_fake_ip_filter > 10000 then return nil end
  local lines={"OPENCLASH_SYNC_CUSTOM_V1"}
  for _,rule in ipairs(value.rules) do
    if type(rule)~="table" or type(rule.type)~="string" or type(rule.value)~="string" or type(rule.policy)~="string" then return nil end
    for _,field in ipairs({rule.type,rule.value,rule.policy}) do if custom_control(field) then return nil end end
    lines[#lines+1]="RULE\t"..rule.type.."\t"..rule.value.."\t"..rule.policy
  end
  for _,filter in ipairs(value.fake_ip_filter) do
    if type(filter)~="string" or filter:find("[\t\r\n]") then return nil end
    lines[#lines+1]="FAKE\t"..filter
  end
  for _,rule in ipairs(value.supplemental_rules) do
    if type(rule)~="string" or #rule<1 or #rule>8192 or rule:find("[\t\r\n%z]") then return nil end
    lines[#lines+1]="SUPPLEMENT_RULE\t"..rule
  end
  for _,filter in ipairs(value.supplemental_fake_ip_filter) do
    if type(filter)~="string" or #filter<1 or #filter>8192 or filter:find("[\t\r\n%z]") then return nil end
    lines[#lines+1]="SUPPLEMENT_FAKE\t"..filter
  end
  return table.concat(lines,"\n").."\n"
end

local function parse_custom_inspect(bytes)
  local groups,rules,filters,supplemental_rules,supplemental_filters,owned_rules,owned_filters,owned_supplemental_rules,owned_supplemental_filters,configured_rules,configured_filters,state_sha,config_sha={},{},{},{},{},{},{},{},{},{},{},nil,nil
  for line in bytes:gmatch("([^\n]+)") do
    local tag,a,b,c=line:match("^([^\t]+)\t?([^\t]*)\t?([^\t]*)\t?(.*)$")
    if tag=="GROUP" and a~="" then groups[#groups+1]=a
    elseif tag=="RULE" and a~="" and b~="" and c~="" then rules[#rules+1]={type=a,value=b,policy=c}
    elseif tag=="FAKE" and a~="" then filters[#filters+1]=a
    elseif tag=="SUPPLEMENT_RULE" and a~="" and b=="" and c=="" then supplemental_rules[#supplemental_rules+1]=a
    elseif tag=="SUPPLEMENT_FAKE" and a~="" and b=="" and c=="" then supplemental_filters[#supplemental_filters+1]=a
    elseif tag=="OWNED_RULE" and a~="" and b~="" and c~="" then owned_rules[#owned_rules+1]={type=a,value=b,policy=c}
    elseif tag=="OWNED_FAKE" and a~="" then owned_filters[#owned_filters+1]=a
    elseif tag=="OWNED_SUPPLEMENT_RULE" and a~="" and b=="" and c=="" then owned_supplemental_rules[#owned_supplemental_rules+1]=a
    elseif tag=="OWNED_SUPPLEMENT_FAKE" and a~="" and b=="" and c=="" then owned_supplemental_filters[#owned_supplemental_filters+1]=a
    elseif tag=="CONFIG_RULE" and a~="" and b=="" and c=="" then configured_rules[#configured_rules+1]=a
    elseif tag=="CONFIG_FAKE" and a~="" and b=="" and c=="" then configured_filters[#configured_filters+1]=a
    elseif tag=="STATE_SHA256" and a:match("^[0-9a-f]+$") and #a==64 and b=="" and c=="" and not state_sha then state_sha=a
    elseif tag=="CONFIG_SHA256" and a:match("^[0-9a-f]+$") and #a==64 and b=="" and c=="" and not config_sha then config_sha=a
    else return nil end
  end
  if not state_sha or not config_sha then return nil end
  return {groups=groups,rules=rules,fake_ip_filter=filters,supplemental_rules=supplemental_rules,supplemental_fake_ip_filter=supplemental_filters,owned_rules=owned_rules,owned_fake_ip_filter=owned_filters,owned_supplemental_rules=owned_supplemental_rules,owned_supplemental_fake_ip_filter=owned_supplemental_filters,configured_rules=configured_rules,configured_fake_ip_filter=configured_filters,state_sha256=state_sha,config_sha256=config_sha}
end

local function node_health()
  local out,closed=capture("ruby "..shell_quote(customizer).." node-health "..shell_quote(runtime).." 2>/dev/null")
  if not closed then return nil end
  local result={}
  for line in out:gmatch("([^\n]+)") do
    local provider,passed,total=line:match("^HEALTH\t(MAYING)\t([0-9]+)\t([0-9]+)$")
    if not provider then provider,passed,total=line:match("^HEALTH\t(NEXITALLY)\t([0-9]+)\t([0-9]+)$") end
    if not provider then return nil end
    provider=provider:lower()
    if result[provider] then return nil end
    passed,total=tonumber(passed),tonumber(total)
    if not passed or not total or passed>total or total>100000 then return nil end
    result[provider]={passed=passed,total=total}
  end
  return result.maying and result.nexitally and result or nil
end

if request.action == "status" then
  local active=active_path(); if not active then failure("ACTIVE 配置路径异常") end
  reply({ok=true,targets={{id=target,name=target=="router_a" and "路由器 A" or "路由器 B",address=target=="router_a" and "192.0.2.10" or "192.0.2.11",state=command_ok("/etc/init.d/openclash running >/dev/null 2>/dev/null") and "运行中" or "异常",active=active:match("([^/]+)$")}}})
elseif request.action == "read" then
  local name=request.name or main
  if type(name)~="string" or not allowed[name] then failure("只允许浏览三份受管配置") end
  local path=config_root..name; local content,digest=stable_read(path,1048576)
  if not content then failure("配置不存在、不是普通文件或超过 1 MiB") end
  reply({ok=true,content=content,sha256=digest,message="已从 "..target.." 读取 "..name})
elseif request.action == "write" or request.action == "converter_apply" then
  local name=request.name; local content=request.content; local expected=request.expected_sha256
  if type(name)~="string" or not allowed[name] or type(content)~="string" or #content<1 or #content>1048576 or type(expected)~="string" or not expected:match("^[0-9a-f]+$") or #expected~=64 then failure("写入参数无效") end
  if name~=main then failure("机场源文件仅允许只读浏览；请使用对应的受控更新操作") end
  local path=config_root..name
  local _,current_digest=stable_read(path,1048576)
  if not current_digest then failure("配置不存在、不是普通文件或超过 1 MiB") end
  if current_digest~=expected then failure("文件已在服务器端变化，请重新读取后再保存") end
  local tmp=make_temp_file(config_root..".openclash-web-XXXXXX", "^/etc/openclash/config/%.openclash%-web%-[A-Za-z0-9]+$")
  if not tmp or not fs.writefile(tmp,content) or not command_ok("chmod 600 "..shell_quote(tmp)) then
    if tmp then fs.unlink(tmp) end
    failure("临时文件写入失败")
  end
  local ok,reason=validate_yaml(tmp,name==main); if not ok then fs.unlink(tmp); failure(reason) end
  local activate=request.action=="converter_apply"
  local label=activate and "converter-apply" or "manual-write"
  local out,closed=capture(shell_quote(custom_transaction).." replace "..target.." "..shell_quote(tmp).." "..label.." "..expected.." 2>/dev/null")
  local result=closed and custom_result(out,"CUSTOM_TRANSACTION") or nil
  if not current_custom_result(result) or (not activate and result.service_restarted) then fs.unlink(tmp); transaction_unknown() end
  if activate then
    local message=result.service_restarted and "转换结果已合并，OpenClash 已受控重启并通过运行态、选点和连通性检查" or "合并后主配置未变化，未重启；本次未重新验证运行配置"
    reply({ok=true,message=message,sha256=result.sha256,state_sha256=result.state_sha256,service_restarted=result.service_restarted,runtime_verified=result.service_restarted})
  else
    reply({ok=true,message="主配置已保存并重放定制项；未 reload、未写 UCI、未重启",sha256=result.sha256})
  end
elseif request.action == "stage_main" then
  local stage_dir=make_temp_dir("/tmp/openclash-web-stage.XXXXXX","^/tmp/openclash%-web%-stage%.[A-Za-z0-9]+$")
  if not stage_dir then failure("Candidate 临时目录创建失败") end
  local before_path=stage_dir.."/before"
  local after_path=stage_dir.."/after"
  local list_committed="find /etc/openclash/publisher-v4/stage -mindepth 2 -maxdepth 2 -type f -name COMMITTED 2>/dev/null"
  if not command_ok(list_committed.." >"..shell_quote(before_path)) then command_ok("rm -rf "..shell_quote(stage_dir)); failure("无法建立 Candidate 事务前置清单") end
  local out,closed=capture(shell_quote(stage_client).." "..target.." 2>/dev/null")
  if not command_ok(list_committed.." >"..shell_quote(after_path)) then command_ok("rm -rf "..shell_quote(stage_dir)); failure("无法建立 Candidate 事务后置清单") end
  local find="awk 'FILENAME==ARGV[1] {seen[$0]=1; next} !seen[$0]' "..shell_quote(before_path).." "..shell_quote(after_path).." 2>/dev/null"
  local matches={}; local found,found_ok=capture(find)
  if found_ok then for line in found:gmatch("([^\n]+)") do
    local receipt=stable_read(line,8192)
    local receipt_sha=receipt and trusted_stage_commit(receipt,target) or nil
    if receipt_sha then table.insert(matches,{path=line,sha256=receipt_sha}) end
  end end
  command_ok("rm -rf "..shell_quote(stage_dir))
  if not found_ok then failure("无法比对本次 Candidate 事务，主配置未更新") end
  local output_pass=closed and journal_value(out,"ROUTER_STAGE")=="PASS"
  local output_sha=journal_value(out,"CANDIDATE_SHA256")
  if not valid_digest(output_sha) then output_sha=nil end
  if #matches==0 and not output_pass then
    local reason=stage_failure_reason(out)
    failure(reason and ("主配置生成或校验未通过（"..reason.."），未切换 ACTIVE") or "主配置生成或校验未通过，未切换 ACTIVE")
  end
  if #matches~=1 then failure("本次 Candidate 事务绑定不唯一，主配置未更新") end
  local candidate_sha=matches[1].sha256
  if output_pass and output_sha and output_sha~=candidate_sha then failure("Candidate 输出与事务摘要不匹配，主配置未更新") end
  local stage_recovered=not output_pass or output_sha~=candidate_sha
  local candidate=matches[1].path:gsub("/COMMITTED$","/candidate.yaml")
  local _,candidate_digest=stable_read(candidate,1048576)
  if candidate_digest~=candidate_sha then failure("Candidate 文件摘要不匹配，主配置未更新") end
  local ok,reason=validate_yaml(candidate,true); if not ok then failure(reason) end
  local out2,closed2=capture(shell_quote(custom_transaction).." replace "..target.." "..shell_quote(candidate).." stage-main 2>/dev/null")
  local result=closed2 and custom_result(out2,"CUSTOM_TRANSACTION") or nil
  if not result then transaction_unknown() end
  local restarted=result.service_restarted
  local health=node_health()
  if not current_custom_result(result) then transaction_unknown() end
  if not health then failure("已收到主配置提交回执，但全节点检查未取得可信结果；最终验收 UNKNOWN，请重新读取并核对") end
  local message=restarted and "主配置已更新，OpenClash 已受控重启并通过运行态检查" or "主配置内容未变化，无需重启 OpenClash"
  if stage_recovered then message=message.."；已由可信 COMMITTED 回执恢复 Candidate 结果" end
  message=message.."；全节点检查已完成"
  if journal_value(out2,"BACKUP_RETENTION")=="HOLD" then message=message.."；七天备份清理未完成，旧备份已保留" end
  reply({ok=true,message=message,sha256=result.sha256,service_restarted=restarted,node_health=health})
elseif request.action == "update_maying" or request.action == "update_nexitally" then
  local filename=request.action=="update_maying" and base or source
  local name=filename:sub(1,-6) -- openclash.sh accepts the configured YAML stem.
  if not command_ok("/usr/share/openclash/openclash.sh "..shell_quote(name).." >/dev/null 2>/dev/null") then failure(name.." 更新未通过，OpenClash 已执行自身失败恢复") end
  reply({ok=true,message=name.." 机场文件更新完成"})
elseif request.action == "rollback" then
  local out2,closed2=capture(shell_quote(custom_transaction).." rollback-latest "..target.." 2>/dev/null")
  local result=closed2 and custom_result(out2,"CUSTOM_TRANSACTION") or nil
  if not current_custom_result(result) or result.service_restarted then transaction_unknown() end
  reply({ok=true,message="主配置已回滚并重放定制项；未 reload、未写 UCI、未重启"})
elseif request.action == "chain_read" then
  local out,closed=capture(shell_quote(custom_transaction).." chain-read "..target.." 2>/dev/null")
  local parsed=closed and json.parse(out) or nil
  if type(parsed)~="table" or parsed.ok~=true then failure("读取链式配置失败；请检查受管节点是否漂移") end
  parsed.message="已读取链式配置；不会返回代理密码"
  reply(parsed)
elseif request.action == "chain_apply" or request.action == "chain_test" then
  local payload=nil
  if request.action=="chain_apply" then
    if not valid_digest(request.expected_state_sha256) or not valid_digest(request.expected_config_sha256) then failure("缺少当前配置与状态摘要，请重新读取") end
    if request.operation=="upsert" and type(request.chain)=="table" then payload={operation="upsert",chain=request.chain}
    elseif request.operation=="remove" and type(request.node)=="string" then payload={operation="remove",node=request.node}
    else failure("链式请求格式无效") end
  else
    if type(request.node)~="string" or #request.node<1 or #request.node>512 or request.node:find("[%c]") then failure("链式节点无效") end
    payload=request.node
  end
  local root=make_temp_dir("/tmp/openclash-web-custom.XXXXXX","^/tmp/openclash%-web%-custom%.[A-Za-z0-9]+$")
  if not root then failure("链式请求临时目录创建失败") end
  local path=root.."/chain.json"
  if not fs.writefile(path,json.stringify(payload)) or not command_ok("chmod 600 "..shell_quote(path)) then
    command_ok("rm -rf "..shell_quote(root)); failure("链式请求暂存失败")
  end
  local command=shell_quote(custom_transaction)..(request.action=="chain_apply" and " chain-apply " or " chain-test ")..target.." "..shell_quote(path)
  if request.action=="chain_apply" then command=command.." "..request.expected_state_sha256.." "..request.expected_config_sha256 end
  local out,closed=capture(command.." 2>/dev/null")
  command_ok("rm -rf "..shell_quote(root))
  if request.action=="chain_apply" then
    local result=closed and custom_result(out,"CUSTOM_TRANSACTION") or nil
    if not current_custom_result(result) then transaction_unknown() end
    reply({ok=true,message=result.service_restarted and "链式配置已保存，受控重启与运行态检查通过；请运行链路测试验证出口通畅" or "链式配置未变化；未重启 OpenClash"})
  else
    local parsed=closed and json.parse(out) or nil
    if type(parsed)~="table" or parsed.ok~=true or parsed.node~=request.node then failure("链路测试失败或当前节点未启用链式代理") end
    parsed.message="固定 TCP 探针：配置、运行态关联和链路可达分别验证；不代表所有网站、UDP 或家宽出口身份"
    reply(parsed)
  end
elseif request.action == "custom_read" then
  local out,closed=capture(shell_quote(custom_transaction).." inspect "..target.." 2>/dev/null")
  if not closed then failure("读取定制项失败") end
  local parsed=parse_custom_inspect(out); if not parsed then failure("定制项响应格式无效") end
  reply({ok=true,groups=parsed.groups,rules=parsed.rules,fake_ip_filter=parsed.fake_ip_filter,supplemental_rules=parsed.supplemental_rules,supplemental_fake_ip_filter=parsed.supplemental_fake_ip_filter,owned_rules=parsed.owned_rules,owned_fake_ip_filter=parsed.owned_fake_ip_filter,owned_supplemental_rules=parsed.owned_supplemental_rules,owned_supplemental_fake_ip_filter=parsed.owned_supplemental_fake_ip_filter,configured_rules=parsed.configured_rules,configured_fake_ip_filter=parsed.configured_fake_ip_filter,state_sha256=parsed.state_sha256,config_sha256=parsed.config_sha256,message="已读取当前定制项、所有权与完整规则只读视图"})
elseif request.action == "custom_preview" or request.action == "custom_apply" then
  local manifest=custom_request(request.customization); if not manifest then failure("定制请求格式无效") end
  local expected=request.expected_state_sha256
  local expected_config=request.expected_config_sha256
  if type(expected)~="string" or #expected~=64 or not expected:match("^[0-9a-f]+$") or type(expected_config)~="string" or #expected_config~=64 or not expected_config:match("^[0-9a-f]+$") then failure("缺少读取时的定制状态或主配置摘要") end
  local root=make_temp_dir("/tmp/openclash-web-custom.XXXXXX","^/tmp/openclash%-web%-custom%.[A-Za-z0-9]+$")
  if not root then failure("定制临时目录创建失败") end
  local request_path=root.."/request.state"
  if not fs.writefile(request_path,manifest) or not command_ok("chmod 600 "..shell_quote(request_path)) then command_ok("rm -rf "..shell_quote(root)); failure("定制请求写入失败") end
  local transaction_action=request.action=="custom_preview" and "preview" or "apply"
  local out,closed=capture(shell_quote(custom_transaction).." "..transaction_action.." "..target.." "..shell_quote(request_path).." "..expected.." "..expected_config.." 2>/dev/null")
  command_ok("rm -rf "..shell_quote(root))
  if request.action=="custom_preview" then
    local result=closed and custom_result(out,"CUSTOM_PREVIEW") or nil
    if not result or result.service_restarted then failure("定制预演或 Mihomo 检查未通过；尚未写入") end
    reply({ok=true,message="定制预演与 Mihomo 检查通过；未写入、未重启"})
  else
    local result=closed and custom_result(out,"CUSTOM_TRANSACTION") or nil
    if not current_custom_result(result) then transaction_unknown() end
    local message=result.service_restarted and "定制项已保存，OpenClash 已受控重启并通过运行态检查；未修改 ACTIVE/UCI" or
      "定制状态已保存；主配置内容未变化，因此未重启 OpenClash"
    if journal_value(out,"BACKUP_RETENTION")=="HOLD" then message=message.."；七天备份清理未完成，旧备份已保留" end
    reply({ok=true,message=message})
  end
elseif request.action == "route_check" then
  local value=request.value
  local source_ip=request.source_ip
  if type(value)~="string" or #value<1 or #value>2048 or value:find("[\t\r\n%z]") or
     type(source_ip)~="string" or #source_ip<3 or #source_ip>64 or source_ip:find("[^0-9A-Fa-f:%.]") then
    failure("网址、域名、IP 或来源地址格式无效")
  end
  local path=make_temp_file("/tmp/openclash-web-route.XXXXXX","^/tmp/openclash%-web%-route%.[A-Za-z0-9]+$")
  if not path or not fs.writefile(path,value.."\n"..source_ip.."\n") then if path then fs.unlink(path) end; failure("判路请求暂存失败") end
  local out,closed=capture("ruby "..shell_quote(customizer).." route-check "..shell_quote(runtime).." "..shell_quote(path).." 2>/dev/null"); fs.unlink(path)
  if not closed then failure("当前运行规则无法安全判定该输入") end
  local mode,policy,reachability,rule_type,certainty=out:match("^ROUTE\t([^\t\n]+)\t([^\t\n]+)\t([^\t\n]+)\t([^\t\n]+)\t([^\t\n]+)\n?$")
  if not mode or not ({DIRECT=true,PROXY=true,REJECT=true,UNKNOWN=true})[mode] or not ({REACHABLE=true,UNREACHABLE=true,BLOCKED=true,UNKNOWN=true})[reachability] or
     not ({EXACT=true,CONTEXTUAL=true,UNKNOWN=true})[certainty] then
    failure("判路结果格式无效")
  end
  reply({ok=true,mode=mode,policy=policy,reachability=reachability,rule_type=rule_type,certainty=certainty})
else
  failure("动作不在白名单")
end
