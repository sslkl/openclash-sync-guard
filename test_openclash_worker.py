#!/usr/bin/env python3
import base64
import json
import hashlib
import os
import io
import sys
import urllib.parse

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from openclash_worker import FetchResult, Worker, emit_result, main  # noqa: E402


def b64url(value): return base64.urlsafe_b64encode(value).rstrip(b"=")
def uri(server=b"a.example.invalid", password=b"secret", name=b"Synthetic", port=443):
    payload = server + b":" + str(port).encode() + b":origin:aes-256-cfb:plain:" + b64url(password) + b"/?remarks=" + b64url(name)
    return b"ssr://" + b64url(payload)
SOURCE = base64.b64encode(uri() + b"\n")
PROXY = {"name":"Synthetic","type":"ssr","server":"a.example.invalid","port":443,"cipher":"aes-256-cfb","protocol":"origin","obfs":"plain","password":"secret","tfo":True}
CONVERTED = yaml.safe_dump({"proxies":[PROXY],"proxy-groups":[]}, allow_unicode=True).encode()
ADDRESS = "http://192.0.2.20:25500/sub?" + urllib.parse.urlencode({
    "target":"clash", "url":"https://source.example.invalid/sub", "new_name":"true", "emoji":"true",
    "udp":"true", "tfo":"false", "fdn":"true", "list":"false", "scv":"false", "sort":"false",
})
SOURCE_HOST_SHA256 = hashlib.sha256(b"source.example.invalid").hexdigest()

class Fake:
    def __init__(self, sequence=None): self.calls=[]; self.sequence=list(sequence or [SOURCE,CONVERTED,SOURCE])
    def __call__(self,url,maximum,timeout): self.calls.append((url,maximum,timeout)); return FetchResult(self.sequence.pop(0),200)

tests=[]
def test(name):
    def wrap(fn): tests.append((name,fn)); return fn
    return wrap
def request(address=ADDRESS): return json.dumps({"schema":"publisher-v4-worker-request-v1","address":address}).encode()
def worker(fetcher, policy="strict-v1"): return Worker(expected_source_host_sha256=SOURCE_HOST_SHA256, normalization_policy=policy, fetcher=fetcher)

@test("pass is prepare-only and secret-free receipt")
def _():
    fake=Fake(); result=worker(fake).run(request())
    assert result["decision"]=="PASS" and result["authorization_effect"]=="PREPARE_ONLY"
    assert result["normalization"]["decision"]=="PASS" and len(fake.calls)==3
    assert all(result[x] is False for x in ("active_config_changed","uci_changed","service_restarted"))
    receipt={k:v for k,v in result.items() if k!="converted_yaml_base64"}
    assert result["secret_fields_emitted_in_receipt"] is False
    assert '"password":"secret"' not in json.dumps(receipt,separators=(",",":")) and "source.example.invalid" not in json.dumps(receipt)
    returned=yaml.safe_load(base64.b64decode(result["converted_yaml_base64"]))
    assert returned["proxies"][0]["tfo"] is False and returned["proxies"][0]["udp"] is True and returned["proxy-groups"]==[]

@test("source drift holds without converted output")
def _():
    result=worker(Fake([SOURCE,CONVERTED,SOURCE+b"x"])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="SOURCE_DRIFT" and "converted_yaml_base64" not in result

@test("normalization mismatch holds")
def _():
    changed=yaml.safe_dump({"proxies":[dict(PROXY,password="changed")],"proxy-groups":[]}).encode()
    result=worker(Fake([SOURCE,changed,SOURCE])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="NORMALIZATION"
    assert result["normalization"]["decision"]=="HOLD" and "converted_yaml_base64" not in result

@test("explicit converter udp false holds")
def _():
    changed=yaml.safe_dump({"proxies":[dict(PROXY,udp=False)],"proxy-groups":[]}).encode()
    result=worker(Fake([SOURCE,changed,SOURCE])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="NORMALIZATION"
    assert result["normalization"]["output_reject_reason_counts"]=={"OUTPUT_PROXY_INVALID":1}

@test("unknown normalization policy holds")
def _():
    result=worker(Fake(),"unknown-policy").run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="NORMALIZATION_POLICY"

@test("converter name authority is explicit and closed")
def _():
    collision_a=uri(name=b"Original A")
    collision_b=uri(name=b"Original B")
    singleton=uri(server=b"b.example.invalid",password=b"bravo",name=b"Original C",port=8443)
    source_bytes=base64.b64encode(collision_a+b"\n"+collision_b+b"\n"+singleton+b"\n")
    renamed={"name":"Renamed C","type":"ssr","server":"b.example.invalid","port":8443,"cipher":"aes-256-cfb","protocol":"origin","obfs":"plain","password":"bravo","tfo":True}
    converted=yaml.safe_dump({"proxies":[renamed],"proxy-groups":[]},allow_unicode=True).encode()
    strict=worker(Fake([source_bytes,converted,source_bytes])).run(request())
    assert strict["decision"]=="HOLD" and strict["reason"]=="NORMALIZATION"
    approved=worker(Fake([source_bytes,converted,source_bytes]),"converter-name-authority-v1").run(request())
    assert approved["decision"]=="PASS" and approved["normalization"]["policy"]=="converter-name-authority-v1"
    assert approved["normalization"]["collision_group_count"]==1
    returned=yaml.safe_load(base64.b64decode(approved["converted_yaml_base64"]))
    assert len(returned["proxies"])==1 and returned["proxies"][0]["name"]=="Renamed C"

@test("outer and query policies are strict")
def _():
    bad=[ADDRESS.replace("192.0.2.20","example.invalid"),ADDRESS.replace("tfo=false","tfo=true"),ADDRESS.replace("fdn=true","fdn=false"),ADDRESS.replace("list=false","list=true"),ADDRESS.replace("scv=false","scv=true"),ADDRESS.replace("sort=false","sort=true"),ADDRESS+"&url=https%3A%2F%2Fx.invalid",ADDRESS+"&unknown=x",ADDRESS+"&config=https%3A%2F%2Fconfig.invalid",ADDRESS.replace("https%3A","http%3A"),ADDRESS.replace("&emoji=true","")]
    for address in bad:
        result=worker(Fake()).run(request(address)); assert result["decision"]=="HOLD" and result["reason"]=="REQUEST"

@test("request and converted shapes fail closed")
def _():
    invalid=[b"",b"not-json",json.dumps({"schema":"publisher-v4-worker-request-v1"}).encode(),json.dumps({"schema":"wrong","address":ADDRESS}).encode()]
    for item in invalid: assert worker(Fake()).run(item)["decision"]=="HOLD"
    result=worker(Fake([SOURCE,b"not: [yaml",SOURCE])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="CONVERTED_YAML"
    anchored=b"proxies: &p []\nproxy-groups: *p\n"
    result=worker(Fake([SOURCE,anchored,SOURCE])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="CONVERTED_YAML"

@test("network failure is redacted")
def _():
    def fail(*_): raise OSError("SYNTHETIC_SECRET")
    result=worker(fail).run(request())
    assert result["reason"]=="NETWORK" and "SYNTHETIC_SECRET" not in json.dumps(result)

@test("stream protocol separates YAML and redacted receipt")
def _():
    result=worker(Fake()).run(request())
    binary=io.BytesIO(); text=io.StringIO(); error=io.StringIO()
    assert emit_result(result,stream=True,stdout_binary=binary,stdout_text=text,stderr_text=error)==0
    yaml_bytes=binary.getvalue(); receipt=error.getvalue()
    assert yaml.safe_load(yaml_bytes)["proxies"][0]["tfo"] is False
    assert '"password":"secret"' not in receipt and "source.example.invalid" not in receipt
    assert result["decision"]=="PASS" and result["secret_fields_emitted_in_receipt"] is False
    assert text.getvalue()=="" and "converted_yaml_base64" not in receipt

@test("stream HOLD keeps stdout empty")
def _():
    result=worker(Fake([SOURCE,CONVERTED,SOURCE+b"x"])).run(request())
    binary=io.BytesIO(); text=io.StringIO(); error=io.StringIO()
    assert emit_result(result,stream=True,stdout_binary=binary,stdout_text=text,stderr_text=error)==1
    assert binary.getvalue()==b"" and text.getvalue()=="" and json.loads(error.getvalue())["reason"]=="SOURCE_DRIFT"

@test("malformed stream invocation stays on stream error channel")
def _():
    old_argv,old_stdin,old_stdout,old_stderr=sys.argv,sys.stdin,sys.stdout,sys.stderr
    class Input:
        buffer=io.BytesIO(b"")
    class Output(io.StringIO):
        def __init__(self): super().__init__(); self.buffer=io.BytesIO()
    output,error=Output(),io.StringIO()
    try:
        sys.argv=["worker","--stream",SOURCE_HOST_SHA256]
        sys.stdin,sys.stdout,sys.stderr=Input(),output,error
        assert main()==1 and output.getvalue()=="" and output.buffer.getvalue()==b""
        assert json.loads(error.getvalue())["reason"]=="SOURCE_ANCHOR"
    finally:
        sys.argv,sys.stdin,sys.stdout,sys.stderr=old_argv,old_stdin,old_stdout,old_stderr

failures=[]
for name,fn in tests:
    try: fn(); print("PASS "+name)
    except Exception as error:
        line = error.__traceback__.tb_next.tb_lineno if error.__traceback__ and error.__traceback__.tb_next else 0
        failures.append((name,type(error).__name__,line)); print(f"FAIL {name} TYPE={type(error).__name__} LINE={line}")
print(f"WORKER_TESTS={len(tests)} PASS={len(tests)-len(failures)} FAIL={len(failures)}")
raise SystemExit(1 if failures else 0)
