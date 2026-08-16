#!/usr/bin/lua
local json = require("luci.jsonc")
local nixio = require("nixio")
local fs = require("nixio.fs")

local target = arg[1]
if target ~= "router_a" and target ~= "router_b" then os.exit(10) end
local raw = io.read("*a") or ""
if #raw < 2 or #raw > 2097152 then os.exit(11) end
local request = json.parse(raw)
if type(request) ~= "table" or request.target ~= target or type(request.action) ~= "string" then os.exit(12) end

local main = "ProviderBase-ProviderSource.yaml"
local allowed = {[main]=true,["ProviderBase.yaml"]=true,["ProviderSource.yaml"]=true}
local config_root = "/etc/openclash/config/"
local backup_root = "/etc/openclash/publisher-v4/web-backups"
local stage_client = "/etc/openclash/publisher-v4/bin/openclash_router_stage_client.sh"
local custom_transaction = "/etc/openclash/publisher-v4/web/openclash_custom_transaction.sh"

local function reply(value) io.write(json.stringify(value)); io.write("\n") end
local function failure(message) reply({ok=false,message=message}); os.exit(0) end
local function shell_quote(value) return "'" .. value:gsub("'", "'\\''") .. "'" end
local function command_ok(command)
  local a,b,c = os.execute(command)
  if type(a) == "number" then return a == 0 end
  return a == true and c == 0
end
local function read_file(path, max)
  local stat = fs.lstat(path)
  if not stat or stat.type ~= "reg" or stat.size > max then return nil end
  return fs.readfile(path)
end
local function sha(path)
  local pipe = io.popen("sha256sum " .. shell_quote(path) .. " 2>/dev/null")
  if not pipe then return nil end
  local line = pipe:read("*l") or ""; local closed = pipe:close()
  local digest = line:match("^([0-9a-f]+)%s")
  if not closed or not digest or #digest ~= 64 then return nil end
  return digest
end
local function private_path(path, expected_type, permissions)
  local info=fs.lstat(path)
  return info and info.type==expected_type and info.uid==0 and info.gid==0 and
    type(info.modedec)=="number" and info.modedec % 512 == permissions
end
local function make_temp_file(template, pattern)
  local pipe = io.popen("umask 077; mktemp " .. shell_quote(template))
  local path = pipe and pipe:read("*l") or nil
  local closed = pipe and pipe:close()
  if not closed or type(path) ~= "string" or not path:match(pattern) then
    if type(path) == "string" then fs.unlink(path) end
    return nil
  end
  if not private_path(path,"reg",384) then fs.unlink(path); return nil end
  return path
end
local function make_temp_dir(template, pattern)
  local pipe=io.popen("umask 077; mktemp -d "..shell_quote(template))
  local path=pipe and pipe:read("*l") or nil
  local closed=pipe and pipe:close()
  if not closed or type(path)~="string" or not path:match(pattern) or not private_path(path,"dir",448) then
    if type(path)=="string" then command_ok("rm -rf "..shell_quote(path)) end
    return nil
  end
  return path
end
local function active_path()
  local pipe = io.popen("uci -q get openclash.config.config_path 2>/dev/null")
  local value = pipe and pipe:read("*l") or nil
  if pipe then pipe:close() end
  if type(value) ~= "string" or not value:match("^/etc/openclash/config/[A-Za-z0-9_-]+%.yaml$") then return nil end
  return value
end
local function validate_yaml(path, is_main)
  local ruby = "ruby -e 'require \"yaml\"; v=YAML.safe_load(File.binread(ARGV[0]), permitted_classes:[], aliases:false); abort unless v.is_a?(Hash) && %w[proxies proxy-groups rules].all?{|k|v[k].is_a?(Array)}' " .. shell_quote(path)
  if not command_ok(ruby .. " >/dev/null 2>/dev/null") then return false,"YAML 结构检查未通过" end
  if is_main then
    local pid = io.popen("pidof clash_meta 2>/dev/null"); local p = pid and pid:read("*l") or nil; if pid then pid:close() end
    if not p or p:find(" ",1,true) then return false,"Mihomo 进程状态异常" end
    local core = fs.readlink("/proc/" .. p .. "/exe")
    if not core or not command_ok(shell_quote(core) .. " -t -d /etc/openclash -f " .. shell_quote(path) .. " >/dev/null 2>/dev/null") then return false,"Mihomo 静态检查未通过" end
  end
  return true,nil
end
local function stamp()
  local pipe=io.popen("date -u +%Y%m%dT%H%M%SZ"); local value=pipe and pipe:read("*l") or nil; if pipe then pipe:close() end
  if not value or not value:match("^%d%d%d%d%d%d%d%dT%d%d%d%d%d%dZ$") then return nil end
  return value
end
local function backup(path, label)
  local ts=stamp(); if not ts then return nil end
  local root_stat=fs.lstat(backup_root)
  if root_stat then
    if root_stat.type~="dir" then return nil end
  elseif not command_ok("mkdir " .. shell_quote(backup_root)) then
    return nil
  end
  if not command_ok("chmod 700 " .. shell_quote(backup_root)) then return nil end
  root_stat=fs.lstat(backup_root)
  if not root_stat or not private_path(backup_root,"dir",448) then return nil end
  local out=backup_root .. "/" .. ts .. "-" .. tostring(nixio.getpid()) .. "-" .. label
  if fs.lstat(out) then return nil end
  local source_sha=sha(path); if not source_sha then return nil end
  if not command_ok("cp -p " .. shell_quote(path) .. " " .. shell_quote(out) .. " && chmod 600 " .. shell_quote(out)) then return nil end
  local backup_sha=sha(out)
  if not private_path(out,"reg",384) or not read_file(out,1048576) or not backup_sha or backup_sha~=source_sha then fs.unlink(out); return nil end
  return out
end

local function custom_request(value)
  if type(value) ~= "table" or type(value.rules) ~= "table" or type(value.fake_ip_filter) ~= "table" then return nil end
  if #value.rules > 256 or #value.fake_ip_filter > 256 then return nil end
  local lines={"OPENCLASH_SYNC_CUSTOM_V1"}
  for _,rule in ipairs(value.rules) do
    if type(rule)~="table" or type(rule.type)~="string" or type(rule.value)~="string" or type(rule.policy)~="string" then return nil end
    for _,field in ipairs({rule.type,rule.value,rule.policy}) do if field:find("[\t\r\n]") then return nil end end
    lines[#lines+1]="RULE\t"..rule.type.."\t"..rule.value.."\t"..rule.policy
  end
  for _,filter in ipairs(value.fake_ip_filter) do
    if type(filter)~="string" or filter:find("[\t\r\n]") then return nil end
    lines[#lines+1]="FAKE\t"..filter
  end
  return table.concat(lines,"\n").."\n"
end

local function parse_custom_inspect(bytes)
  local groups,rules,filters,state_sha={},{},{},nil
  for line in bytes:gmatch("([^\n]+)") do
    local tag,a,b,c=line:match("^([^\t]+)\t?([^\t]*)\t?([^\t]*)\t?(.*)$")
    if tag=="GROUP" and a~="" then groups[#groups+1]=a
    elseif tag=="RULE" and a~="" and b~="" and c~="" then rules[#rules+1]={type=a,value=b,policy=c}
    elseif tag=="FAKE" and a~="" then filters[#filters+1]=a
    elseif tag=="STATE_SHA256" and a:match("^[0-9a-f]+$") and #a==64 and b=="" and c=="" and not state_sha then state_sha=a
    else return nil end
  end
  if not state_sha then return nil end
  return {groups=groups,rules=rules,fake_ip_filter=filters,state_sha256=state_sha}
end

if request.action == "status" then
  local active=active_path(); if not active then failure("ACTIVE 配置路径异常") end
  reply({ok=true,targets={{id=target,name=target=="router_a" and "路由器 A" or "路由器 B",address=target=="router_a" and "192.0.2.10" or "192.0.2.11",state=command_ok("/etc/init.d/openclash running >/dev/null 2>/dev/null") and "运行中" or "异常",active=active:match("([^/]+)$")}}})
elseif request.action == "read" then
  local name=request.name or main
  if type(name)~="string" or not allowed[name] then failure("只允许浏览三份受管配置") end
  local path=config_root..name; local content=read_file(path,1048576)
  if not content then failure("配置不存在、不是普通文件或超过 1 MiB") end
  local digest=sha(path); if not digest then failure("配置摘要计算失败") end
  reply({ok=true,content=content,sha256=digest,message="已从 "..target.." 读取 "..name})
elseif request.action == "write" then
  local name=request.name; local content=request.content; local expected=request.expected_sha256
  if type(name)~="string" or not allowed[name] or type(content)~="string" or #content<1 or #content>1048576 or type(expected)~="string" or not expected:match("^[0-9a-f]+$") or #expected~=64 then failure("写入参数无效") end
  local path=config_root..name
  if not read_file(path,1048576) then failure("配置不存在、不是普通文件或超过 1 MiB") end
  if sha(path)~=expected then failure("文件已在服务器端变化，请重新读取后再保存") end
  local tmp=make_temp_file(config_root..".openclash-web-XXXXXX", "^/etc/openclash/config/%.openclash%-web%-[A-Za-z0-9]+$")
  if not tmp or not fs.writefile(tmp,content) or not command_ok("chmod 600 "..shell_quote(tmp)) then
    if tmp then fs.unlink(tmp) end
    failure("临时文件写入失败")
  end
  local ok,reason=validate_yaml(tmp,name==main); if not ok then fs.unlink(tmp); failure(reason) end
  if name==main then
    local pipe=io.popen(shell_quote(custom_transaction).." replace "..target.." "..shell_quote(tmp).." manual-write "..expected.." 2>/dev/null")
    local out=pipe and pipe:read("*a") or ""; local closed=pipe and pipe:close()
    if not closed or not out:match("CUSTOM_TRANSACTION=PASS") then fs.unlink(tmp); failure("主配置保存或定制重放失败，原文件保持不变") end
    reply({ok=true,message="主配置已保存并重放定制项；未 reload、未写 UCI、未重启",sha256=sha(path)})
  else
    local saved=backup(path,name); if not saved then fs.unlink(tmp); failure("创建回滚备份失败") end
    if sha(path)~=expected then fs.unlink(tmp); failure("校验期间文件已变化，请重新读取后再保存") end
    if not command_ok("mv "..shell_quote(tmp).." "..shell_quote(path).." && chmod 600 "..shell_quote(path)) then fs.unlink(tmp); command_ok("cp -p "..shell_quote(saved).." "..shell_quote(path)); failure("原子替换失败，已恢复原文件") end
    reply({ok=true,message="配置已保存并通过检查；当前运行内核未 reload（重新加载）",sha256=sha(path)})
  end
elseif request.action == "stage_main" then
  local stage_dir=make_temp_dir("/tmp/openclash-web-stage.XXXXXX","^/tmp/openclash%-web%-stage%.[A-Za-z0-9]+$")
  if not stage_dir then failure("Candidate 临时目录创建失败") end
  local before_path=stage_dir.."/before"
  local after_path=stage_dir.."/after"
  local list_committed="find /etc/openclash/publisher-v4/stage -mindepth 2 -maxdepth 2 -type f -name COMMITTED 2>/dev/null | LC_ALL=C sort"
  if not command_ok(list_committed.." >"..shell_quote(before_path)) then command_ok("rm -rf "..shell_quote(stage_dir)); failure("无法建立 Candidate 事务前置清单") end
  local pipe=io.popen(shell_quote(stage_client).." "..target.." 2>/dev/null"); local out=pipe and pipe:read("*a") or ""; local closed=pipe and pipe:close()
  if not closed or not out:match("ROUTER_STAGE=PASS") then command_ok("rm -rf "..shell_quote(stage_dir)); failure("主配置生成或校验未通过，未切换 ACTIVE") end
  local candidate_sha=out:match("CANDIDATE_SHA256=([0-9a-f]+)")
  if not candidate_sha or #candidate_sha~=64 then command_ok("rm -rf "..shell_quote(stage_dir)); failure("Candidate 摘要无效，主配置未更新") end
  if not command_ok(list_committed.." >"..shell_quote(after_path)) then command_ok("rm -rf "..shell_quote(stage_dir)); failure("无法建立 Candidate 事务后置清单") end
  local find="awk 'FILENAME==ARGV[1] {seen[$0]=1; next} !seen[$0]' "..shell_quote(before_path).." "..shell_quote(after_path).." 2>/dev/null"
  local matches={}; local found=io.popen(find)
  if found then for line in found:lines() do
    local receipt=read_file(line,8192)
    local wrapped=receipt and ("\n"..receipt.."\n") or ""
    if wrapped:find("\nTARGET="..target.."\n",1,true) and wrapped:find("\nCANDIDATE_SHA256="..candidate_sha.."\n",1,true) then table.insert(matches,line) end
  end; found:close() end
  command_ok("rm -rf "..shell_quote(stage_dir))
  if #matches~=1 then failure("本次 Candidate 事务绑定不唯一，主配置未更新") end
  local candidate=matches[1]:gsub("/COMMITTED$","/candidate.yaml")
  if not read_file(candidate,1048576) or sha(candidate)~=candidate_sha then failure("Candidate 文件摘要不匹配，主配置未更新") end
  local ok,reason=validate_yaml(candidate,true); if not ok then failure(reason) end
  local pipe2=io.popen(shell_quote(custom_transaction).." replace "..target.." "..shell_quote(candidate).." stage-main 2>/dev/null")
  local out2=pipe2 and pipe2:read("*a") or ""; local closed2=pipe2 and pipe2:close()
  if not closed2 or not out2:match("CUSTOM_TRANSACTION=PASS") then failure("主配置定制重放或原子替换失败，原文件保持不变") end
  reply({ok=true,message="主配置文件已更新并重放定制项；未 reload、未写 UCI、未重启",sha256=sha(config_root..main)})
elseif request.action == "update_maying" or request.action == "update_nexitally" then
  local name=request.action=="update_maying" and "Maying" or "Nexitally"
  if not command_ok("/usr/share/openclash/openclash.sh "..shell_quote(name).." >/dev/null 2>/dev/null") then failure(name.." 更新未通过，OpenClash 已执行自身失败恢复") end
  reply({ok=true,message=name.." 机场文件更新完成"})
elseif request.action == "rollback" then
  local pipe2=io.popen(shell_quote(custom_transaction).." rollback-latest "..target.." 2>/dev/null")
  local out2=pipe2 and pipe2:read("*a") or ""; local closed2=pipe2 and pipe2:close()
  if not closed2 or not out2:match("CUSTOM_TRANSACTION=PASS") then failure("主配置回滚或定制重放失败，原文件保持不变") end
  reply({ok=true,message="主配置已回滚并重放定制项；未 reload、未写 UCI、未重启"})
elseif request.action == "custom_read" then
  local pipe=io.popen(shell_quote(custom_transaction).." inspect "..target.." 2>/dev/null")
  local out=pipe and pipe:read("*a") or ""; local closed=pipe and pipe:close()
  if not closed then failure("读取定制项失败") end
  local parsed=parse_custom_inspect(out); if not parsed then failure("定制项响应格式无效") end
  reply({ok=true,groups=parsed.groups,rules=parsed.rules,fake_ip_filter=parsed.fake_ip_filter,state_sha256=parsed.state_sha256,message="已读取当前定制项"})
elseif request.action == "custom_apply" then
  local manifest=custom_request(request.customization); if not manifest then failure("定制请求格式无效") end
  local expected=request.expected_state_sha256
  if type(expected)~="string" or #expected~=64 or not expected:match("^[0-9a-f]+$") then failure("缺少读取时的定制状态摘要") end
  local root=make_temp_dir("/tmp/openclash-web-custom.XXXXXX","^/tmp/openclash%-web%-custom%.[A-Za-z0-9]+$")
  if not root then failure("定制临时目录创建失败") end
  local request_path=root.."/request.state"
  if not fs.writefile(request_path,manifest) or not command_ok("chmod 600 "..shell_quote(request_path)) then command_ok("rm -rf "..shell_quote(root)); failure("定制请求写入失败") end
  local pipe=io.popen(shell_quote(custom_transaction).." apply "..target.." "..shell_quote(request_path).." "..expected.." 2>/dev/null")
  local out=pipe and pipe:read("*a") or ""; local closed=pipe and pipe:close()
  command_ok("rm -rf "..shell_quote(root))
  if not closed or not out:match("CUSTOM_TRANSACTION=PASS") then failure("定制项未完成或已自动恢复；请重新读取当前定制后重试") end
  if out:find("SERVICE_RESTARTED=true",1,true) then
    reply({ok=true,message="定制项已保存，OpenClash 已受控重启并通过运行态检查；未修改 ACTIVE/UCI"})
  else
    reply({ok=true,message="定制状态已保存；主配置内容未变化，因此未重启 OpenClash"})
  end
else
  failure("动作不在白名单")
end
