-- Execute the real Lua agent with in-memory filesystem/process/JSON adapters.
-- No shell command, network operation, or router file access is performed.
local source_path = assert(arg[1], "agent source path required")
local source_file = assert(io.open(source_path, "rb"))
local source = source_file:read("*a"); source_file:close()
source = source:gsub("^#[^\n]*", "") -- loadfile-compatible shebang handling
local main = "/etc/openclash/config/ProviderBase-ProviderSource.yaml"
local candidate_sha, config_sha, state_sha = string.rep("a",64), string.rep("b",64), string.rep("c",64)
local stage_receipt = table.concat({
  "ROUTER_STAGE=PASS", "TARGET=router_a", "DNS_RESOLVER_REACHABILITY=PASS",
  "CANDIDATE_SHA256="..candidate_sha, "ACTIVE_CHANGED=false", "UCI_CHANGED=false", "SERVICE_RESTARTED=false", ""
}, "\n")
local function commit(restarted, marker)
  return table.concat({(marker or "CUSTOM_TRANSACTION").."=PASS", "CONFIG_SHA256="..config_sha,
    "STATE_SHA256="..state_sha, "ACTIVE_CHANGED=false", "UCI_CHANGED=false",
    "SERVICE_RESTARTED="..tostring(restarted), "BACKUP_RETENTION=PASS", ""}, "\n")
end
local function run(options)
  local s = options or {}
  local calls, reply = {transactions=0,health=0,lists=0,unlinks=0,cleanup=0,updates={}}, nil
  local action=s.action or "stage_main"
  local stage_dir="/tmp/openclash-web-stage.ABC123"
  local custom_dir="/tmp/openclash-web-custom.ABC123"
  local write_path="/etc/openclash/config/.openclash-web-ABC123"
  local route_path="/tmp/openclash-web-route.ABC123"
  local files, fds, serial = {}, {}, 0
  local function add(path, bytes, digest, kind)
    serial=serial+1
    files[path]={bytes=bytes or "", digest=digest or candidate_sha,
      info={dev=1,ino=serial,size=#(bytes or ""),mtime=1,ctime=1,nlink=1,
        type=kind or "reg",uid=0,gid=0,modestr=kind=="dir" and "rwx------" or "rw-------"}}
    return files[path]
  end
  add(main,"config",config_sha)
  add(stage_dir,"",nil,"dir"); add(custom_dir,"",nil,"dir"); add(write_path,"",nil); add(route_path,"",nil)
  local paths={}
  for i=1,(s.receipt_count or 1) do
    local path="/etc/openclash/publisher-v4/stage/synthetic-"..i.."/COMMITTED"
    paths[#paths+1]=path
    add(path,s.receipt or stage_receipt)
    add(path:gsub("/COMMITTED$","/candidate.yaml"),"candidate",s.candidate_digest or candidate_sha)
  end
  local fs={
    lstat=function(path) return files[path] and files[path].info end,
    readlink=function(path) assert(path=="/proc/123/exe"); return "/mock/clash_meta" end,
    writefile=function(path,bytes) add(path,bytes); return true end,
    unlink=function(path) calls.unlinks=calls.unlinks+1; files[path]=nil; return true end
  }
  local nixio={getpid=function() return 4242 end}
  nixio.open=function(path,mode)
    assert(mode=="r")
    local entry=files[path]; if not entry then return nil end
    local fd=100+serial; serial=serial+1; fds["/proc/4242/fd/"..fd]=entry
    local offset=0
    return {
      stat=function() return entry.info end,
      fileno=function() return fd end,
      seek=function(_,n,whence) assert(n==0 and whence=="set"); offset=0; return 0 end,
      read=function(_,n) local chunk=entry.bytes:sub(offset+1,offset+n); offset=offset+#chunk; return chunk end,
      close=function() return true end
    }
  end
  local function pipe(bytes,closed)
    return {
      read=function(_,mode) return mode=="*l" and bytes:match("([^\n]*)") or bytes end,
      close=function() if closed==false then return nil end; return true end,
      lines=function() return bytes:gmatch("([^\n]+)") end
    }
  end
  local function framed_pipe(kind,bytes)
    local status=tostring(s[kind.."_exit"] or 0)
    local mode=s[kind.."_frame"]
    local output=bytes.."\nOPENCLASH_PIPE_STATUS="..status.."\n"
    if mode=="missing" then output=bytes
    elseif mode=="duplicate" then output=output.."OPENCLASH_PIPE_STATUS=0\n"
    elseif mode=="malformed" then output=bytes.."\nOPENCLASH_PIPE_STATUS=not-a-status\n"
    elseif mode=="trailing" then output=output.."unexpected\n"
    elseif mode=="embedded" then output="OPENCLASH_PIPE_STATUS=0\n"..output
    elseif mode=="noncanonical" then output=bytes.."\nOPENCLASH_PIPE_STATUS=00\n" end
    return pipe(output,s[kind.."_closed"])
  end
  local fake_io={read=function() return "{}" end,write=function() end}
  fake_io.popen=function(wrapped)
    local prefix="(\n"
    local suffix="\n); openclash_pipe_status=$?; printf '\nOPENCLASH_PIPE_STATUS=%s\n' \"$openclash_pipe_status\""
    assert(wrapped:sub(1,#prefix)==prefix and wrapped:sub(-#suffix)==suffix,"unframed popen")
    local command=wrapped:sub(#prefix+1,-#suffix-1)
    local sha_path=command:match("^sha256sum '([^']+)' 2>/dev/null$")
    if sha_path then
      local entry=fds[sha_path] or files[sha_path]
      assert(entry,"unexpected sha path: "..sha_path)
      return framed_pipe("sha",entry.digest.."  synthetic\n")
    elseif command:find("umask 077; mktemp -d ",1,true)==1 then
      return framed_pipe("temp_dir",s.temp_stdout or (action=="stage_main" and stage_dir or custom_dir).."\n")
    elseif command:find("umask 077; mktemp ",1,true)==1 then
      return framed_pipe("temp_file",s.temp_stdout or (action=="route_check" and route_path or write_path).."\n")
    elseif command=="'/etc/openclash/publisher-v4/bin/openclash_router_stage_client.sh' router_a 2>/dev/null" then
      return framed_pipe("stage",s.stage_stdout or stage_receipt)
    elseif command:find("awk 'FILENAME==ARGV[1]",1,true)==1 then
      return framed_pipe("find",table.concat(paths,"\n").."\n")
    elseif command=="pidof clash_meta 2>/dev/null" then return framed_pipe("pid",s.pid_stdout or "123\n")
    elseif command=="uci -q get openclash.config.config_path 2>/dev/null" then
      return framed_pipe("uci",s.uci_stdout or main.."\n")
    elseif command:find("'/etc/openclash/publisher-v4/web/openclash_custom_transaction.sh' ",1,true)==1 then
      calls.transactions=calls.transactions+1
      files[main].digest=s.final_digest or config_sha
      if s.final_symlink then files[main].info.type="lnk" end
      local output=commit(action=="stage_main" or action=="custom_apply" or action=="converter_apply",
        action=="custom_preview" and "CUSTOM_PREVIEW" or nil)
      if action=="custom_read" then output="STATE_SHA256\t"..state_sha.."\nCONFIG_SHA256\t"..config_sha.."\n" end
      return framed_pipe("transaction",s.transaction_stdout or output)
    elseif command=="ruby '/etc/openclash/publisher-v4/web/openclash_customizer.rb' node-health '/etc/openclash/ProviderBase-ProviderSource.yaml' 2>/dev/null" then
      calls.health=calls.health+1
      if s.health_changes_config then files[main].digest=state_sha end
      return framed_pipe("health",s.health or "HEALTH\tMAYING\t2\t3\nHEALTH\tNEXITALLY\t0\t0\n")
    elseif command=="ruby '/etc/openclash/publisher-v4/web/openclash_customizer.rb' route-check '/etc/openclash/ProviderBase-ProviderSource.yaml' '"..route_path.."' 2>/dev/null" then
      return framed_pipe("route","ROUTE\tDIRECT\tDIRECT\tUNKNOWN\tDOMAIN\tEXACT\n")
    end
    error("unmocked popen: "..command)
  end
  local exit={}
  local env={arg={"router_a"},assert=assert,error=error,ipairs=ipairs,pairs=pairs,next=next,
    tonumber=tonumber,tostring=tostring,type=type,math=math,string=string,table=table,io=fake_io}
  env.os={exit=function(code) assert(code==0); error(exit) end,execute=function(command)
    if command:find("/usr/share/openclash/openclash.sh ",1,true)==1 then
      calls.updates[#calls.updates+1]=command
      return (s.update_exit or 0)*256 -- Lua 5.1 os.execute returns a numeric wait status.
    end
    if command:find("find /etc/openclash/publisher-v4/stage ",1,true)==1 then
      assert(not command:find("|",1,true),"find failure must not be masked by a pipeline")
      calls.lists=calls.lists+1
      local status=s[calls.lists==1 and "list_before_exit" or "list_after_exit"] or 0
      return status*256
    end
    if command:find("rm -rf ",1,true)==1 then calls.cleanup=calls.cleanup+1 end
    assert(command:find("/etc/init.d/openclash running ",1,true)==1 or
      command:find("rm -rf '/tmp/openclash-web-",1,true)==1 or
      command:find("ruby -e ",1,true)==1 or command:find("'/mock/clash_meta' -t ",1,true)==1 or
      command:find("chmod 600 ",1,true)==1,"unmocked execute: "..command)
    return 0
  end}
  local request={target="router_a",action=action,name=main:match("([^/]+)$"),content="config",value="example.test",source_ip="192.0.2.1",
    expected_sha256=config_sha,expected_state_sha256=state_sha,expected_config_sha256=config_sha,
    customization=s.customization or {rules={},fake_ip_filter={},supplemental_rules={},supplemental_fake_ip_filter={}}}
  if s.request_name~=nil then request.name=s.request_name end
  local json={parse=function(raw) assert(raw=="{}"); return request end,stringify=function(value) reply=value; return "{}" end}
  env.require=function(name)
    if name=="luci.jsonc" then return json elseif name=="nixio" then return nixio elseif name=="nixio.fs" then return fs end
    error("unmocked module: "..name)
  end
  local agent=assert(loadstring(source,"@"..source_path)); setfenv(agent,env)
  local ok,reason=pcall(agent)
  assert(ok or reason==exit,reason)
  assert(type(reply)=="table","missing agent reply")
  return reply,calls
end

local count=0
local function check(name,fn)
  fn(); count=count+1; io.write("PASS ",name,"\n")
end
local function rejected(options,expected_calls,unknown)
  local result,calls=run(options)
  assert(result.ok==false,"expected rejection")
  if expected_calls~=nil then assert(calls.transactions==expected_calls,"unexpected transaction count") end
  if unknown then assert(result.message:find("UNKNOWN",1,true),"ambiguous writes must report UNKNOWN") end
end
-- Provider updates use configured YAML stems, never caller-selected names.
for _,provider in ipairs({
  {action="update_maying",stem="ProviderBase",other="ProviderSource.yaml"},
  {action="update_nexitally",stem="ProviderSource",other="ProviderBase.yaml"}
}) do
  local function assert_update(options,success)
    local result,calls=run(options)
    local expected="/usr/share/openclash/openclash.sh '"..provider.stem.."' >/dev/null 2>/dev/null"
    assert(#calls.updates==1,"expected exactly one provider update")
    assert(calls.updates[1]==expected,"update must use the configured YAML stem")
    assert(calls.transactions==0 and calls.health==0,"provider update must not stage the main config")
    assert(result.ok==success,"update result must reflect the process exit status")
    local message=success and provider.stem.." 机场文件更新完成" or
      provider.stem.." 更新未通过，OpenClash 已执行自身失败恢复"
    assert(result.message==message,"update message must identify the managed target and its actual result")
  end
  check(provider.action..": configured YAML stem succeeds",function()
    assert_update({action=provider.action},true)
  end)
  for _,status in ipairs({1,3,127,255}) do
    check(provider.action..": exit "..status.." cannot report update success",function()
      assert_update({action=provider.action,update_exit=status},false)
    end)
  end
  for _,name in ipairs({
    {label="other managed provider",value=provider.other},
    {label="unmanaged filename",value="Unmanaged.yaml"},
    {label="path traversal",value="../../Unmanaged.yaml"},
    {label="shell metacharacters",value="Unmanaged'; :; #.yaml"},
    {label="empty string",value=""},
    {label="non-string",value={filename="Unmanaged.yaml"}},
    {label="false",value=false}
  }) do
    check(provider.action..": request.name cannot redirect "..name.label,function()
      for _,status in ipairs({0,3}) do
        assert_update({action=provider.action,request_name=name.value,update_exit=status},status==0)
      end
    end)
  end
end
check("valid stage result binds final config and health",function()
  local result,calls=run()
  assert(result.ok and result.sha256==config_sha and result.service_restarted==true)
  assert(result.node_health.maying.passed==2 and result.node_health.nexitally.total==0)
  assert(calls.transactions==1 and calls.health==1)
end)
check("valid unchanged config does not claim restart",function()
  local result=run({transaction_stdout=commit(false)})
  assert(result.ok and result.service_restarted==false)
end)
for _,case in ipairs({{name="lost stdout",stage_stdout="",stage_closed=false},
  {name="malformed stdout",stage_stdout="ROUTER_STAGE=PASS\nCANDIDATE_SHA256=broken\n"}}) do
  check("trusted receipt recovery: "..case.name,function()
    local result=run(case); assert(result.ok and result.message:find("COMMITTED",1,true))
  end)
end
check("no receipt cannot commit",function() rejected({receipt_count=0},0) end)
check("ambiguous receipts cannot commit",function() rejected({receipt_count=2},0) end)
check("failed diff cannot commit",function() rejected({find_closed=false},0) end)
check("candidate bytes must match receipt",function() rejected({candidate_digest=config_sha},0) end)
check("stdout and receipt digest must agree",function()
  rejected({stage_stdout=stage_receipt:gsub(candidate_sha,config_sha)},0)
end)
for _,field in ipairs({"ROUTER_STAGE","TARGET","DNS_RESOLVER_REACHABILITY","CANDIDATE_SHA256",
  "ACTIVE_CHANGED","UCI_CHANGED","SERVICE_RESTARTED"}) do
  check("duplicate stage field rejected: "..field,function()
    local line=stage_receipt:match(field.."=([^\n]+)")
    rejected({receipt=stage_receipt..field.."="..line.."\n"},0)
  end)
  check("invalid stage field rejected: "..field,function()
    rejected({receipt=stage_receipt:gsub(field.."=[^\n]+",field.."=invalid")},0)
  end)
end
for _,field in ipairs({"CUSTOM_TRANSACTION","CONFIG_SHA256","STATE_SHA256","ACTIVE_CHANGED","UCI_CHANGED","SERVICE_RESTARTED"}) do
  check("duplicate transaction field rejected: "..field,function()
    local bytes=commit(true); local value=bytes:match(field.."=([^\n]+)")
    rejected({transaction_stdout=bytes..field.."="..value.."\n"},1,true)
  end)
  check("invalid transaction field rejected: "..field,function()
    rejected({transaction_stdout=commit(true):gsub(field.."=[^\n]+",field.."=invalid")},1,true)
  end)
end
check("success substring does not prove commit",function()
  rejected({transaction_stdout=commit(true):gsub("CUSTOM_TRANSACTION=PASS","NOT_CUSTOM_TRANSACTION=PASS")},1,true)
end)
check("failed process cannot prove commit",function() rejected({transaction_closed=false},1,true) end)
check("postcommit digest mismatch is UNKNOWN",function() rejected({final_digest=state_sha},1,true) end)
check("postcommit symlink is UNKNOWN",function() rejected({final_symlink=true},1,true) end)
check("config drift during node health is UNKNOWN",function() rejected({health_changes_config=true},1,true) end)
for _,health in ipairs({
  "", "HEALTH\tMAYING\t1\t1\n", "HEALTH\tMAYING\t1\t1\nHEALTH\tNEXITALLY\t1\t1\nHEALTH\tMAYING\t1\t1\n",
  "HEALTH\tMAYING\t1\t1\nHEALTH\tNEXITALLY\t1\t1\nHEALTH\tNEXITALLY\t1\t1\n",
  "HEALTH\tMAYING\t2\t1\nHEALTH\tNEXITALLY\t0\t0\n",
  "HEALTH\tMAYING\t0\t100001\nHEALTH\tNEXITALLY\t0\t0\n",
  "HEALTH\tMAYING\t0\t"..string.rep("9",400).."\nHEALTH\tNEXITALLY\t0\t0\n"
}) do
  check("invalid node health "..(count+1),function() rejected({health=health},1,true) end)
end
check("failed health command is UNKNOWN",function() rejected({health_closed=false},1,true) end)
check("upper health boundary is accepted",function()
  local result=run({health="HEALTH\tMAYING\t100000\t100000\nHEALTH\tNEXITALLY\t0\t0\n"}); assert(result.ok)
end)
check("retention HOLD is a warning, not a failed commit",function()
  local result=run({transaction_stdout=commit(true):gsub("BACKUP_RETENTION=PASS","BACKUP_RETENTION=HOLD")})
  assert(result.ok and result.message:find("旧备份已保留",1,true))
end)
for _,action in ipairs({"write","rollback","custom_apply","converter_apply"}) do
  check(action..": valid receipt",function()
    local result=run({action=action}); assert(result.ok)
  end)
  check(action..": malformed receipt is UNKNOWN",function()
    rejected({action=action,transaction_stdout="CUSTOM_TRANSACTION=PASS\n"},1,true)
  end)
  check(action..": final digest mismatch is UNKNOWN",function()
    rejected({action=action,final_digest=state_sha},1,true)
  end)
end
check("converter apply proves activation separately from save",function()
  local result=run({action="converter_apply"})
  assert(result.ok and result.service_restarted and result.runtime_verified and result.state_sha256==state_sha)
end)
check("converter apply no-change does not claim runtime verification",function()
  local result=run({action="converter_apply",transaction_stdout=commit(false)})
  assert(result.ok and not result.service_restarted and not result.runtime_verified)
end)
for _,action in ipairs({"write","rollback"}) do
  check(action..": unexpected restart rejected",function()
    rejected({action=action,transaction_stdout=commit(true)},1,true)
  end)
end
check("custom preview uses its own complete receipt",function()
  local result=run({action="custom_preview"}); assert(result.ok)
end)
check("custom preview cannot accept success substring",function()
  rejected({action="custom_preview",transaction_stdout=commit(false,"NOT_CUSTOM_PREVIEW")},1)
end)
check("custom preview cannot accept restart",function()
  rejected({action="custom_preview",transaction_stdout=commit(true,"CUSTOM_PREVIEW")},1)
end)
-- Lua 5.1 closes a pipe successfully even when its child exits nonzero.
for _,action in ipairs({"stage_main","write","converter_apply","rollback","custom_apply","custom_preview","custom_read"}) do
  check(action..": valid stdout with exit 3 cannot prove success",function()
    rejected({action=action,transaction_exit=3},1,action~="custom_preview" and action~="custom_read")
  end)
end
check("stage exit 3 uses durable receipt recovery, never stdout success",function()
  local result=run({stage_exit=3})
  assert(result.ok and result.message:find("COMMITTED",1,true))
end)
check("stage exit 3 without receipt cannot commit",function() rejected({stage_exit=3,receipt_count=0},0) end)
check("stage exit 3 with untrusted receipt cannot commit",function() rejected({stage_exit=3,receipt="ROUTER_STAGE=PASS\n"},0) end)
check("sha256sum exit 3 rejects a syntactically valid digest",function() rejected({action="read",sha_exit=3},0) end)
check("sha256sum failure blocks candidate activation",function() rejected({sha_exit=3},0) end)
check("node-health exit 3 is UNKNOWN",function() rejected({health_exit=3},1,true) end)
check("awk exit 3 rejects its valid candidate paths",function() rejected({find_exit=3},0) end)
check("find failure before staging blocks activation",function() rejected({list_before_exit=3},0) end)
check("find failure after staging blocks activation",function() rejected({list_after_exit=3},0) end)
for _,action in ipairs({"write","converter_apply","stage_main","custom_apply","route_check"}) do
  check(action..": mktemp failure cannot authorize file use or cleanup",function()
    local result,calls=run({action=action,temp_file_exit=3,temp_dir_exit=3})
    assert(not result.ok and calls.transactions==0 and calls.unlinks==0 and calls.cleanup==0)
  end)
  check(action..": untrusted mktemp path is never deleted",function()
    local result,calls=run({action=action,temp_stdout="/untrusted/not-a-temp-file\n"})
    assert(not result.ok and calls.transactions==0 and calls.unlinks==0 and calls.cleanup==0)
  end)
end
for _,action in ipairs({"read","status","custom_read","route_check"}) do
  check(action..": valid read-only result still accepted",function() assert(run({action=action}).ok) end)
end
check("uci exit 3 rejects an otherwise valid ACTIVE path",function() rejected({action="status",uci_exit=3},0) end)
check("pidof exit 3 blocks activation",function() rejected({pid_exit=3},0) end)
check("pidof malformed PID blocks activation",function() rejected({pid_stdout="123\n456\n"},0) end)
check("route-check exit 3 rejects an otherwise valid result",function() rejected({action="route_check",route_exit=3},0) end)
for _,mode in ipairs({"missing","duplicate","malformed","trailing","embedded","noncanonical"}) do
  check("transaction frame rejected: "..mode,function() rejected({transaction_frame=mode},1,true) end)
  check("sha frame rejected: "..mode,function() rejected({action="read",sha_frame=mode},0) end)
  check("candidate diff frame rejected: "..mode,function() rejected({find_frame=mode},0) end)
end
check("custom policy controls rejected before transaction",function()
  for byte=0,159 do
    if byte<32 or byte>=127 then
      local control=byte<128 and string.char(byte) or string.char(194,byte)
      rejected({action="custom_preview",customization={rules={{type="DOMAIN",value="example.test",policy="Group"..control.."X"}},fake_ip_filter={},supplemental_rules={},supplemental_fake_ip_filter={}}},0)
    end
  end
end)
check("custom Unicode policy remains accepted",function()
  local result=run({action="custom_preview",customization={rules={{type="DOMAIN",value="example.test",policy="业务组🙂"}},fake_ip_filter={},supplemental_rules={},supplemental_fake_ip_filter={}}})
  assert(result.ok)
end)
io.write("LUA_AGENT_BEHAVIOR=PASS\nLUA_AGENT_CASES=",count,"\n")
