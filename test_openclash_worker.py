#!/usr/bin/env python3
import base64
import hashlib
import io
import json
import os
import sys
import urllib.parse

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from openclash_worker import FetchResult, Worker, WorkerPolicyHold, emit_result, main


def b64url(value): return base64.urlsafe_b64encode(value).rstrip(b"=")
def uri(server=b"a.example.invalid", password=b"secret", name=b"Synthetic", port=443):
    payload = server + b":" + str(port).encode() + b":origin:aes-256-cfb:plain:" + b64url(password) + b"/?remarks=" + b64url(name)
    return b"ssr://" + b64url(payload)
SOURCE = base64.b64encode(uri() + b"\n")
PROXY = {"name":"Synthetic","type":"ssr","server":"a.example.invalid","port":443,"cipher":"aes-256-cfb","protocol":"origin","obfs":"plain","password":"secret","tfo":True}
METADATA = {"allow-lan":True,"external-controller":"127.0.0.1:9090","log-level":"info","mode":"Rule","port":7890,"socks-port":7891}
def converter_document(proxies=None, rules=None, **extra):
    return {**METADATA,"proxies":proxies if proxies is not None else [PROXY],"proxy-groups":[],"rules":rules if rules is not None else ["MATCH,DIRECT"],**extra}
CONVERTED_DOCUMENT = converter_document()
CONVERTED = yaml.safe_dump(CONVERTED_DOCUMENT, allow_unicode=True).encode()
ADDRESS = "http://192.0.2.20:25500/sub?" + urllib.parse.urlencode({
    "target":"clash", "url":"https://source.example.invalid/sub", "new_name":"true", "emoji":"true",
    "udp":"true", "tfo":"false", "fdn":"true", "list":"false", "scv":"false", "sort":"false",
})
SOURCE_HOST_SHA256 = hashlib.sha256(b"source.example.invalid").hexdigest()

def shape_contract(source=1, proxies=1, groups=0, rules=1):
    def bounds(minimum, maximum=None, baseline=None):
        maximum = minimum if maximum is None else maximum
        baseline = minimum if baseline is None else baseline
        return {"minimum":minimum,"maximum":maximum,"baseline":baseline}
    return {
        "schema":"publisher-v4-maying-converter-shape-contract-v2",
        "source_format":"BASE64_SSR_URI_LIST",
        "allowed_top_level_keys":["allow-lan","external-controller","log-level","mode","port","proxies","proxy-groups","rules","socks-port"],
        "required_top_level_keys":["allow-lan","external-controller","log-level","mode","port","proxies","proxy-groups","rules","socks-port"],
        "ignored_metadata_top_level_keys":["allow-lan","external-controller","log-level","mode","port","socks-port"],
        "ignored_metadata_types":{"allow-lan":"BOOL","external-controller":"STRING","log-level":"STRING","mode":"STRING","port":"INT","socks-port":"INT"},
        "ignored_metadata_semantic_sha256":Worker._semantic_sha256(METADATA),
        "source_uri_count":bounds(source),
        "converted_proxy_count":bounds(proxies),
        "converted_group_count":bounds(groups),
        "converted_rule_count":bounds(rules),
        "converted_dns_present":False,
        "converted_udp_absent_count":bounds(0,proxies,proxies),
        "converted_udp_true_count":bounds(0,proxies,0),
        "converted_udp_false_count":bounds(0),
        "normalized_udp_true_count":bounds(proxies),
        "normalized_tfo_false_count":bounds(proxies),
    }
TEST_CONTRACT = shape_contract()

class Fake:
    def __init__(self, sequence=None): self.calls=[]; self.sequence=list(sequence or [SOURCE,CONVERTED,SOURCE])
    def __call__(self,url,maximum,timeout): self.calls.append((url,maximum,timeout)); return FetchResult(self.sequence.pop(0),200)

tests=[]
def test(name):
    def wrap(fn): tests.append((name,fn)); return fn
    return wrap
def request(address=ADDRESS): return json.dumps({"schema":"publisher-v4-worker-request-v1","address":address}).encode()
def worker(fetcher, policy="strict-v1", contract=TEST_CONTRACT):
    return Worker(expected_source_host_sha256=SOURCE_HOST_SHA256, normalization_policy=policy, shape_contract=contract, fetcher=fetcher)

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
    assert set(returned)=={"proxies","proxy-groups"}
    assert returned["proxies"][0]["tfo"] is False and returned["proxies"][0]["udp"] is True and returned["proxy-groups"]==[]
    assert result["converter_udp_absent_count"]==result["worker_udp_materialized_count"]==1
    assert result["converter_udp_true_count"]==result["converter_udp_false_count"]==0
    assert result["normalized_udp_true_count"]==result["normalized_tfo_false_count"]==1
    assert result["udp_policy"]=="request-bound-true-v1" and result["converter_dns_present"] is False
    assert result["ignored_rule_count"]==1 and len(result["ignored_rules_sha256"])==64
    assert result["ignored_metadata_key_count"]==6 and result["ignored_metadata_types_validated"] is True
    assert len(result["ignored_metadata_semantic_sha256"])==64 and result["ignored_top_level_key_count"]==7
    assert result["normalization"]["source_udp_capability_declared"] is False
    assert result["normalization"]["runtime_udp_capability_verified"] is False

@test("source drift holds without converted output")
def _():
    result=worker(Fake([SOURCE,CONVERTED,SOURCE+b"x"])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="SOURCE_DRIFT" and "converted_yaml_base64" not in result

@test("normalization mismatch holds")
def _():
    changed=yaml.safe_dump(converter_document(proxies=[dict(PROXY,password="changed")])).encode()
    result=worker(Fake([SOURCE,changed,SOURCE])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="NORMALIZATION"
    assert result["normalization"]["decision"]=="HOLD" and "converted_yaml_base64" not in result

@test("explicit converter udp false holds")
def _():
    changed=yaml.safe_dump(converter_document(proxies=[dict(PROXY,udp=False)])).encode()
    result=worker(Fake([SOURCE,changed,SOURCE])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="CONVERTER_UDP_FALSE"
    assert result["converter_udp_false_count"]==1 and result["worker_udp_materialized_count"]==0
    assert "converted_yaml_base64" not in result

@test("non-boolean converter udp holds before normalization")
def _():
    for value in ("true",None,1,[]):
        changed=yaml.safe_dump(converter_document(proxies=[dict(PROXY,udp=value)])).encode()
        result=worker(Fake([SOURCE,changed,SOURCE])).run(request())
        assert result["decision"]=="HOLD" and result["reason"]=="CONVERTER_UDP_TYPE"

@test("UDP HOLD accounting enumerates the complete converter set")
def _():
    proxies=[dict(PROXY,name="Absent"),dict(PROXY,name="False",udp=False),dict(PROXY,name="Invalid",udp="true"),dict(PROXY,name="True",udp=True)]
    changed=yaml.safe_dump(converter_document(proxies=proxies)).encode()
    result=worker(Fake([SOURCE,changed,SOURCE]),contract=shape_contract(proxies=4)).run(request())
    assert result["reason"]=="CONVERTER_UDP_TYPE"
    assert [result[key] for key in ("converter_udp_absent_count","converter_udp_true_count","converter_udp_false_count","converter_udp_type_invalid_count","worker_udp_materialized_count")]==[1,1,1,1,0]

@test("explicit converter udp true is accepted without materialization")
def _():
    changed=yaml.safe_dump(converter_document(proxies=[dict(PROXY,udp=True)])).encode()
    result=worker(Fake([SOURCE,changed,SOURCE])).run(request())
    assert result["decision"]=="PASS" and result["converter_udp_true_count"]==1 and result["worker_udp_materialized_count"]==0

@test("unexpected converter DNS holds with semantic hash only")
def _():
    changed=dict(CONVERTED_DOCUMENT,dns={"nameserver":["https://sensitive.example.invalid/dns-query"]})
    result=worker(Fake([SOURCE,yaml.safe_dump(changed).encode(),SOURCE])).run(request())
    assert result["decision"]=="HOLD" and result["reason"]=="MAYING_DNS_UNEXPECTED"
    assert result["dns_present"] is True and result["converter_dns_present"] is True and len(result["dns_semantic_sha256"])==64
    assert "sensitive.example.invalid" not in json.dumps(result)

@test("converter top-level and count drift hold closed")
def _():
    extra=dict(CONVERTED_DOCUMENT,unknown_field=True)
    assert worker(Fake([SOURCE,yaml.safe_dump(extra).encode(),SOURCE])).run(request())["reason"]=="MAYING_DOCUMENT_SHAPE"
    metadata_drift=dict(CONVERTED_DOCUMENT,mode="rule")
    result=worker(Fake([SOURCE,yaml.safe_dump(metadata_drift).encode(),SOURCE])).run(request())
    assert result["reason"]=="MAYING_DOCUMENT_SHAPE" and result["ignored_metadata_types_validated"] is True
    changed=dict(CONVERTED_DOCUMENT,rules=["MATCH,DIRECT","DOMAIN,example.invalid,DIRECT"])
    result=worker(Fake([SOURCE,yaml.safe_dump(changed).encode(),SOURCE])).run(request())
    assert result["reason"]=="MAYING_DOCUMENT_SHAPE"
    assert result["ignored_rule_count"]==2 and len(result["ignored_rules_sha256"])==64

@test("normalizer UDP receipt counts must close against normalized output")
def _():
    receipt={"source_format":"BASE64_SSR_URI_LIST","input_uri_count":1,"udp_policy_validated":True,
             "source_udp_capability_declared":False,"runtime_udp_capability_verified":False,
             "udp_true_validated_count":0,"tfo_false_enforced_count":1}
    try:
        worker(Fake())._validate_normalized_contract(TEST_CONTRACT,receipt,1,1,1,{"converter_udp_absent_count":1,"converter_udp_true_count":0,"converter_udp_false_count":0,"worker_udp_materialized_count":1})
    except WorkerPolicyHold as error:
        assert error.reason=="UDP_COUNT_MISMATCH"
        return
    raise AssertionError("receipt mismatch accepted")

@test("shape contract artifact records the redacted baseline")
def _():
    with open(os.path.join(HERE,"maying-converter-shape-contract.json"),encoding="utf-8") as handle:
        contract=json.load(handle)
    assert contract["source_format"]=="BASE64_SSR_URI_LIST"
    assert [contract[key]["baseline"] for key in ("source_uri_count","converted_proxy_count","converted_group_count","converted_rule_count")]==[110,108,13,10231]
    assert contract["converted_dns_present"] is False
    assert contract["schema"]=="publisher-v4-maying-converter-shape-contract-v2"
    assert contract["ignored_metadata_top_level_keys"]==["allow-lan","external-controller","log-level","mode","port","socks-port"]
    assert len(contract["ignored_metadata_semantic_sha256"])==64

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
    converted=yaml.safe_dump(converter_document(proxies=[renamed]),allow_unicode=True).encode()
    collision_contract=shape_contract(source=3)
    strict=worker(Fake([source_bytes,converted,source_bytes]),contract=collision_contract).run(request())
    assert strict["decision"]=="HOLD" and strict["reason"]=="NORMALIZATION"
    approved=worker(Fake([source_bytes,converted,source_bytes]),"converter-name-authority-v1",collision_contract).run(request())
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
    anchored=b"proxies: &p []\nproxy-groups: *p\nrules: []\n"
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
