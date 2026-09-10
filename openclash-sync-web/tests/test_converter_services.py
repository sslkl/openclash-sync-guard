"""Synthetic service protocols: no real token, third-party writes or DNS."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import converter_services as s
from converter_fetch import Fetched
from subscription_converter import ConverterError, validate as form

TOKEN='synthetic_token_for_offline_only'
ID='a'*32
LINK=form({'sources':['https://example.test/subscription'],'options':{'target':'clash'}}).link()

def request(action,**values):
    return dict(action=action,confirm_external=True,**({'token':TOKEN} if action.startswith('gist_') else {}),**values)

def row(**values):
    return dict(id=ID,public=False,description='Synthetic',files={'config.ini':{'truncated':False,'content':'[custom]\n'}},**values)

def fetcher(value,status=200):
    f=mock.Mock();f.fetch.return_value=Fetched(json.dumps(value).encode(),'application/json',0,status);return f

class ServicesTests(unittest.TestCase):
    def test_missing_confirmation_and_unknown_fields_do_not_fetch(self):
        for value in [{},request('unknown'),dict(request('gist_list'),confirm_external=False),request('gist_list',host='https://other.test')]:
            f=mock.Mock()
            with self.assertRaises(ConverterError):s.run(value,fetcher=f)
            f.fetch.assert_not_called()

    def test_request_shapes_surrogates_token_injection_and_types(self):
        values=[request('gist_list',page=True),request('gist_list',page=101),request('gist_get',id='../etc',filename='a'),request('gist_get',id=ID,filename='../a'),request('gist_create',filename='a',content='x',public='false'),request('gist_create',filename='a',content='\ud800',public=False),request('gist_create',filename='a',content='x',public=False,description='\ud800')]
        values += [dict(request('gist_list'),token=x) for x in [None,'short','x\r\nAuthorization: bad','\ud800']]
        for value in values:
            with self.subTest(action=value['action']),self.assertRaises(ConverterError):s.validate(value)

    def test_short_provider_https_only_and_valid_subscription_required(self):
        for api in ['http://example.test/short','https://example.test:8443/short','https://user:synthetic@example.test/short']:
            with self.assertRaises(ConverterError):s.validate(request('shorten',link=LINK,api=api))
        with self.assertRaises(ConverterError):s.validate(request('shorten',link='https://example.test/not-sub'))

    def test_short_request_uses_explicit_provider_multipart_no_redirect_no_retry(self):
        f=fetcher({'Code':1,'ShortUrl':'https://short.example.test/a'})
        result=s.run(request('shorten',link=LINK),fetcher=f)
        self.assertEqual(result['link'],'https://short.example.test/a');f.fetch.assert_called_once()
        url=f.fetch.call_args.args[0];k=f.fetch.call_args.kwargs
        self.assertEqual(url,s.SHORT_API);self.assertEqual(k['_method'],'POST');self.assertFalse(k['_redirects'])
        self.assertIn(b'name="longUrl"',k['_body']);self.assertNotIn(LINK.encode(),k['_body']);self.assertNotIn('Authorization',k['_headers'])
        s.validate_result(result,s.validate(request('shorten',link=LINK)))

    def test_gist_reads_fixed_origin_and_scoped_fields(self):
        f=fetcher([row()]);result=s.run(request('gist_list'),fetcher=f)
        self.assertEqual(f.fetch.call_args.args[0],'https://api.github.com/gists?per_page=30&page=1')
        self.assertNotIn(TOKEN,json.dumps(result));self.assertEqual(result['items'][0]['filenames'],['config.ini'])
        k=f.fetch.call_args.kwargs;self.assertEqual(k['_headers']['Authorization'],'Bearer '+TOKEN);self.assertFalse(k['_redirects'])
        self.assertEqual(k['_headers']['X-GitHub-Api-Version'],'2022-11-28')
        s.validate_result(result,s.validate(request('gist_list')))

    def test_gist_get_only_complete_requested_content_no_raw_url_fetch(self):
        f=fetcher(row());data=request('gist_get',id=ID,filename='config.ini');result=s.run(data,fetcher=f)
        self.assertEqual(result['content'],'[custom]\n');f.fetch.assert_called_once();s.validate_result(result,data)
        for value in [dict(row(),id='b'*32),dict(row(),files={'config.ini':{'truncated':True,'content':'x','raw_url':'https://other.test'}}),dict(row(),files={})]:
            f=fetcher(value)
            with self.assertRaises(ConverterError) as e:s.run(data,fetcher=f)
            self.assertEqual(e.exception.code,'SERVICE_RESULT');f.fetch.assert_called_once()

    def test_gist_create_update_delete_only_exact_scope(self):
        for action,method in [('gist_create','POST'),('gist_update','PATCH'),('gist_delete','DELETE')]:
            data=request(action,**({'id':ID} if action!='gist_create' else {}),**({'filename':'config.ini','content':'[custom]\n'} if action!='gist_delete' else {}),**({'public':False,'description':'Synthetic'} if action=='gist_create' else {}))
            f=fetcher(row(),201 if action=='gist_create' else 204 if action=='gist_delete' else 200)
            result=s.run(data,fetcher=f);k=f.fetch.call_args.kwargs
            self.assertEqual(k['_method'],method);self.assertFalse(k['_redirects']);f.fetch.assert_called_once()
            if action=='gist_delete':self.assertIsNone(k['_body']);self.assertTrue(result['deleted'])
            else:
                body=json.loads(k['_body']);self.assertEqual(set(body['files']),{'config.ini'})
                self.assertEqual(set(body),{'files','description','public'} if action=='gist_create' else {'files'})
            s.validate_result(result,s.validate(data))

    def test_mutation_response_loss_malformed_duplicate_or_redirect_is_uncertain(self):
        for error in [ConverterError('FETCH_TIMEOUT'),ConverterError('FETCH_REDIRECT'),ValueError('synthetic')]:
            f=mock.Mock();f.fetch.side_effect=error
            with self.assertRaises(ConverterError) as e:s.run(request('gist_delete',id=ID),fetcher=f)
            self.assertEqual(e.exception.code,'SERVICE_UNCERTAIN');f.fetch.assert_called_once()
        f=fetcher({});f.fetch.return_value=Fetched(b'{"Code":1,"Code":1}', 'application/json',0,200)
        with self.assertRaises(ConverterError) as e:s.run(request('shorten',link=LINK),fetcher=f)
        self.assertEqual(e.exception.code,'SERVICE_UNCERTAIN')

    def test_worker_never_relays_unknown_fields_or_sensitive_failure(self):
        req=s.validate(request('gist_list'))
        valid={'ok':True,'action':'gist_list','router_changed':False,'items':[],'page':1,'has_next':False}
        self.assertEqual(s.validate_result(valid,req),valid)
        for result in [dict(valid,token=TOKEN),dict(valid,action='gist_delete'),dict(valid,page=True),dict(valid,has_next=True),dict(valid,router_changed=True),dict(valid,items=[{'token':TOKEN}])]:
            with self.assertRaises(ConverterError):s.validate_result(result,req)

    def test_execute_stdin_memory_no_argv_credentials_and_strict_framing(self):
        value={'ok':True,'action':'gist_list','router_changed':False,'items':[],'page':1,'has_next':False}
        process=mock.Mock(returncode=0);process.communicate.return_value=(json.dumps(value).encode(),None)
        with mock.patch.object(s.subprocess,'Popen',return_value=process) as popen:
            self.assertEqual(s.execute(request('gist_list')),value)
        args=popen.call_args.args[0];self.assertNotIn(TOKEN,str(args));self.assertIn('-I',args);self.assertIn('-B',args)
        self.assertIn(TOKEN.encode(),process.communicate.call_args.args[0]);self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertEqual(popen.call_args.kwargs['stderr'],subprocess.DEVNULL)
        for raw in [b'{}',b'[]',b'{"ok":true,"ok":false}',json.dumps(dict(value,token=TOKEN)).encode(),b'{"ok":false,"code":"sensitive-raw-message"}']:
            process.communicate.return_value=(raw,None)
            with mock.patch.object(s.subprocess,'Popen',return_value=process),self.assertRaises(ConverterError) as e:s.execute(request('gist_list'))
            self.assertEqual(e.exception.code,'SERVICE_RESULT');self.assertNotIn('sensitive',str(e.exception))

    def test_mutation_worker_timeout_kills_group_without_retry(self):
        process=mock.Mock();process.communicate.side_effect=subprocess.TimeoutExpired(['redacted'],25)
        with mock.patch.object(s.subprocess,'Popen',return_value=process) as popen,mock.patch.object(s,'os_kill_group') as kill:
            with self.assertRaises(ConverterError) as e:s.execute(request('gist_delete',id=ID))
        self.assertEqual(e.exception.code,'SERVICE_UNCERTAIN');kill.assert_called_once_with(process);popen.assert_called_once()

    def test_real_worker_rejects_malformed_json_without_network(self):
        p=subprocess.run([sys.executable,'-I','-B',s.__file__,'--worker'],input=b'{"action":"gist_list","action":"gist_delete"}',capture_output=True,timeout=5,check=False)
        self.assertEqual(p.returncode,0);self.assertEqual(json.loads(p.stdout),{'ok':False,'code':'SERVICE_RESULT'});self.assertEqual(p.stderr,b'')

    def test_expand_parsed_lan_link_is_text_only_never_contacted(self):
        with mock.patch.object(s,'resolve_public',side_effect=AssertionError('network')):
            self.assertEqual(s.resolve_link(LINK),LINK)

    def test_expand_public_redirect_stops_before_lan_backend(self):
        response=mock.Mock(status=302);response.headers.get_all.return_value=[LINK]
        connection=mock.Mock();connection.getresponse.return_value=response
        f=mock.Mock();f.time_left.return_value=10
        with mock.patch.object(s,'resolve_public',return_value=['93.184.216.34']) as dns,mock.patch.object(s,'PinnedConnection',return_value=connection) as pinned:
            self.assertEqual(s.resolve_link('https://short.example.test/a',fetcher=f),LINK)
        dns.assert_called_once();pinned.assert_called_once();connection.request.assert_called_once();response.close.assert_called_once();connection.close.assert_called_once()
        self.assertNotIn('Authorization',connection.request.call_args.kwargs['headers'])

    def test_expand_rejects_private_hops_cycles_and_non_subscription_downgrade(self):
        f=mock.Mock();f.time_left.return_value=10
        with mock.patch.object(s,'resolve_public',side_effect=ConverterError('FETCH_ADDRESS')):
            with self.assertRaises(ConverterError):s.resolve_link('http://127.0.0.1/secret',fetcher=f)
        for location in ['https://short.example.test/a','http://public.example.test/not-sub']:
            response=mock.Mock(status=302);response.headers.get_all.return_value=[location]
            connection=mock.Mock();connection.getresponse.return_value=response
            with mock.patch.object(s,'resolve_public',return_value=['93.184.216.34']),mock.patch.object(s,'PinnedConnection',return_value=connection):
                with self.assertRaises(ConverterError):s.resolve_link('https://short.example.test/a',fetcher=f)
