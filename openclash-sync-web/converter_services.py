"""Explicit short-link/Gist operations, never part of automatic conversion.

Credential input stays in a killable unprivileged worker's stdin/memory. No disk,
logs, cookies, proxy environment, automatic mutation retry or redirect replay.
"""
from __future__ import annotations
import base64
import http.client
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
from urllib.parse import urljoin, urlsplit, urlunsplit
if __name__ == '__main__': sys.path.insert(0, str(Path(__file__).resolve().parent))
from subscription_converter import ConverterError, http_url, parse_link, text
from converter_fetch import (MAX_JOB_BYTES, TIMEOUT, PublicFetcher, PinnedConnection,
                             resolve_public, os_kill_group)

SHORT_API = 'https://suo.yt/short'
MAX_WIRE = 2 * MAX_JOB_BYTES
ACTIONS = frozenset({'shorten', 'expand', 'gist_list', 'gist_get', 'gist_create', 'gist_update', 'gist_delete'})
MUTATIONS = frozenset({'shorten', 'gist_create', 'gist_update', 'gist_delete'})


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result or key in {'__proto__', 'constructor', 'prototype'}: raise ConverterError('SERVICE_RESULT')
        result[key] = value
    return result


def content(value):
    try: size = len(value.encode('utf-8')) if isinstance(value, str) else 0
    except UnicodeError: raise ConverterError('CONTENT') from None
    if not isinstance(value, str) or not value or '\0' in value or size > MAX_JOB_BYTES:
        raise ConverterError('CONTENT')
    return value


def filename(value):
    value = text(value, 128)
    if value in {'.', '..'} or any(c in value for c in '/\\'): raise ConverterError('REQUEST')
    return value


def validate(data):
    if not isinstance(data, dict) or not isinstance(data.get('action'), str) or data['action'] not in ACTIONS:
        raise ConverterError('REQUEST')
    action = data['action']
    keys = {'shorten': {'link', 'api'}, 'expand': {'link'}, 'gist_list': {'token', 'page'},
            'gist_get': {'token', 'id', 'filename'}, 'gist_create': {'token', 'filename', 'content', 'description', 'public'},
            'gist_update': {'token', 'id', 'filename', 'content'}, 'gist_delete': {'token', 'id'}}[action]
    if set(data) - (keys | {'action', 'confirm_external'}) or data.get('confirm_external') is not True:
        raise ConverterError('SERVICE_CONFIRM')
    value = dict(data)
    if action in {'shorten', 'expand'}:
        value['link'] = http_url(data.get('link'))
        if action == 'shorten':
            parse_link(value['link'])
            value['api'] = http_url(data.get('api', SHORT_API))
            parts = urlsplit(value['api'])
            if parts.scheme != 'https' or (parts.port or 443) != 443: raise ConverterError('FETCH_PORT')
    else:
        token = text(data.get('token'), 512)
        if not re.fullmatch(r'[A-Za-z0-9_\-]{16,512}', token): raise ConverterError('SERVICE_AUTH')
        if action in {'gist_get', 'gist_update', 'gist_delete'}:
            if not isinstance(data.get('id'), str) or not re.fullmatch(r'[0-9a-f]{20,40}', data['id']): raise ConverterError('REQUEST')
        if action == 'gist_list':
            page=data.get('page',1)
            if type(page) is not int or not 1 <= page <= 100: raise ConverterError('REQUEST')
            value['page']=page
        if 'filename' in keys: value['filename'] = filename(data.get('filename'))
        if 'content' in keys: value['content'] = content(data.get('content'))
        if action == 'gist_create':
            value['description'] = text(data.get('description',''),256,empty=True)
            if type(data.get('public')) is not bool: raise ConverterError('REQUEST')
    return value


def resolve_link(value, *, fetcher=None):
    """Follow only public headers; stop before contacting a final /sub URL.

    A final LAN backend is acceptable as parsed link text, never as a fetch.
    Meta refresh/HTML scripts are not executed and produce a safe failure.
    """
    fetcher = fetcher or PublicFetcher(timeout=TIMEOUT)
    url=value; seen=set()
    for hop in range(5):
        try:
            return parse_link(url).link()
        except ConverterError: pass
        if url in seen: raise ConverterError('FETCH_REDIRECT')
        seen.add(url);parts=urlsplit(http_url(url));port=parts.port or (443 if parts.scheme=='https' else 80)
        if port not in (80,443): raise ConverterError('FETCH_PORT')
        addresses=resolve_public(parts.hostname,fetcher.time_left())
        connection=None;response=None
        try:
            # No application request is retried after being sent.
            connection=PinnedConnection(parts.hostname,port,addresses[0],parts.scheme=='https',min(fetcher.time_left(),6))
            connection.connect()
            connection.request('GET',urlunsplit(('','',parts.path or '/',parts.query,'')),headers={'User-Agent':'OpenClash-Sync-Converter/1','Accept-Encoding':'identity','Connection':'close'})
            response=connection.getresponse()
            locations=response.headers.get_all('Location',[])
            if response.status not in (301,302,303,307,308) or len(locations)!=1: raise ConverterError('SERVICE_RESULT')
            next_url=http_url(urljoin(url,text(locations[0],16384)))
            if parts.scheme=='https' and urlsplit(next_url).scheme!='https':
                # A final parsed LAN/HTTP subscription is returned as text only.
                try: return parse_link(next_url).link()
                except ConverterError: raise ConverterError('FETCH_DOWNGRADE') from None
            url=next_url
        except ConverterError: raise
        except (OSError,ValueError,http.client.HTTPException): raise ConverterError('FETCH_CONNECT') from None
        finally:
            if response is not None: response.close()
            if connection is not None: connection.close()
    raise ConverterError('FETCH_REDIRECT')


def gist_meta(row):
    if not isinstance(row,dict) or not isinstance(row.get('id'),str) or not re.fullmatch(r'[0-9a-f]{20,40}',row['id']) or type(row.get('public')) is not bool:
        raise ConverterError('SERVICE_RESULT')
    files=row.get('files')
    if not isinstance(files,dict) or len(files)>100: raise ConverterError('SERVICE_RESULT')
    return {'id':row['id'],'public':row['public'],'description':text(row.get('description') or '',256,empty=True),
            'filenames':[filename(name) for name in files], 'url':'https://gist.github.com/'+row['id']}


def run(data, *, fetcher=None):
    data=validate(data);action=data['action'];fetcher=fetcher or PublicFetcher(timeout=TIMEOUT)
    if action=='expand':
        return {'ok':True,'action':action,'link':resolve_link(data['link'],fetcher=fetcher),'router_changed':False}
    method='GET';body=None;headers={}
    if action=='shorten':
        url=data['api'];method='POST';boundary='ocs-'+secrets.token_hex(16)
        body=('--'+boundary+'\r\nContent-Disposition: form-data; name="longUrl"\r\n\r\n'+base64.b64encode(data['link'].encode()).decode()+'\r\n--'+boundary+'--\r\n').encode()
        headers['Content-Type']='multipart/form-data; boundary='+boundary
    else:
        url='https://api.github.com/gists'+('/'+data['id'] if 'id' in data else '')
        if action=='gist_list': url+='?per_page=30&page='+str(data['page'])
        headers={'Authorization':'Bearer '+data['token'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
        if action in {'gist_create','gist_update'}:
            method='POST' if action=='gist_create' else 'PATCH'
            value={'files':{data['filename']:{'content':data['content']}}}
            if action=='gist_create': value.update(description=data['description'],public=data['public'])
            body=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode();headers['Content-Type']='application/json'
        elif action=='gist_delete': method='DELETE'
    try:
        fetched=fetcher.fetch(url,_method=method,_body=body,_headers=headers,_statuses=(200,201,204),_redirects=False,_allow_empty=action=='gist_delete')
        if action=='gist_delete':
            if fetched.status!=204: raise ConverterError('SERVICE_RESULT')
            return {'ok':True,'action':action,'id':data['id'],'deleted':True,'router_changed':False}
        parsed=json.loads(fetched.body,object_pairs_hook=unique_object)
        if action=='shorten':
            if not isinstance(parsed,dict) or type(parsed.get('Code')) is not int or parsed['Code']!=1: raise ConverterError('SERVICE_RESULT')
            link=http_url(parsed.get('ShortUrl'))
            return {'ok':True,'action':action,'link':link,'router_changed':False}
        if action=='gist_list':
            if not isinstance(parsed,list) or len(parsed)>30: raise ConverterError('SERVICE_RESULT')
            return {'ok':True,'action':action,'items':[gist_meta(row) for row in parsed],'page':data['page'],'has_next':len(parsed)==30,'router_changed':False}
        metadata = gist_meta(parsed)
        if 'id' in data and metadata['id'] != data['id']: raise ConverterError('SERVICE_RESULT')
        result={'ok':True,'action':action,'gist':metadata,'router_changed':False}
        if action=='gist_get':
            file=parsed['files'].get(data['filename'])
            if not isinstance(file,dict) or file.get('truncated') is not False: raise ConverterError('SERVICE_RESULT')
            result['content']=content(file.get('content')); result['filename']=data['filename']
        return result
    except (ConverterError, ValueError, TypeError, RecursionError, UnicodeError):
        # The provider may have committed a write before response loss/parsing.
        # Never report a definitive rollback and never retry automatically.
        raise ConverterError('SERVICE_UNCERTAIN' if action in MUTATIONS else 'SERVICE_RESULT') from None


def validate_result(result, request):
    """The parent never relays arbitrary worker JSON or accidental token fields."""
    try:
        action = request['action']
        fields = {'shorten': {'link'}, 'expand': {'link'},
                  'gist_list': {'items', 'page', 'has_next'}, 'gist_get': {'gist', 'content', 'filename'},
                  'gist_create': {'gist'}, 'gist_update': {'gist'}, 'gist_delete': {'id', 'deleted'}}[action]
        if set(result) != fields | {'ok', 'action', 'router_changed'} or result['ok'] is not True or result['action'] != action or result['router_changed'] is not False:
            raise ValueError
        def metadata(value):
            if not isinstance(value, dict) or set(value) != {'id', 'public', 'description', 'filenames', 'url'}: raise ValueError
            if not isinstance(value['filenames'], list) or len(value['filenames']) > 100 or len(set(value['filenames'])) != len(value['filenames']): raise ValueError
            checked = gist_meta(dict(value, files={name: {} for name in value['filenames']}))
            if checked != value: raise ValueError
        if action in {'shorten', 'expand'}:
            http_url(result['link'])
            if action == 'expand': parse_link(result['link'])
        elif action == 'gist_list':
            if not isinstance(result['items'], list) or len(result['items']) > 30 or type(result['page']) is not int or result['page'] != request['page'] or type(result['has_next']) is not bool or result['has_next'] != (len(result['items']) == 30): raise ValueError
            for item in result['items']: metadata(item)
        elif action == 'gist_delete':
            if result['id'] != request['id'] or result['deleted'] is not True: raise ValueError
        else:
            metadata(result['gist'])
            if 'id' in request and result['gist']['id'] != request['id']: raise ValueError
            if action == 'gist_get':
                content(result['content'])
                if result['filename'] != request['filename']: raise ValueError
        return result
    except (ConverterError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise ConverterError('SERVICE_UNCERTAIN' if request['action'] in MUTATIONS else 'SERVICE_RESULT') from None


def execute(data):
    data=validate(data)
    encoded=json.dumps(data,ensure_ascii=False,separators=(',',':')).encode()
    if len(encoded)>MAX_WIRE: raise ConverterError('FETCH_SIZE')
    try:
        process=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--worker'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,env={'PATH':'/usr/bin:/bin'})
        try: raw,_=process.communicate(encoded,timeout=TIMEOUT+1)
        except subprocess.TimeoutExpired:
            os_kill_group(process)
            raise ConverterError('SERVICE_UNCERTAIN' if data['action'] in MUTATIONS else 'FETCH_TIMEOUT') from None
        if process.returncode or not raw or len(raw)>MAX_WIRE: raise ValueError
        result=json.loads(raw,object_pairs_hook=unique_object)
        if not isinstance(result,dict) or type(result.get('ok')) is not bool: raise ValueError
        if result['ok'] is not True:
            code=result.get('code')
            raise ConverterError(code if code in {'SERVICE_UNCERTAIN','SERVICE_RESULT','FETCH_TIMEOUT','FETCH_ADDRESS','FETCH_DNS','FETCH_REDIRECT','FETCH_DOWNGRADE','FETCH_CONNECT','FETCH_PORT'} else 'SERVICE_RESULT')
        return validate_result(result, data)
    except ConverterError: raise
    except (OSError, ValueError, TypeError, RecursionError):
        raise ConverterError('SERVICE_UNCERTAIN' if data['action'] in MUTATIONS else 'SERVICE_RESULT') from None


if __name__=='__main__':
    import resource
    if sys.platform.startswith('linux'): resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(10,10));resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_WIRE,MAX_WIRE))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    try:
        raw=sys.stdin.buffer.read(MAX_WIRE+1)
        if len(raw)>MAX_WIRE: raise ConverterError('FETCH_SIZE')
        result=run(json.loads(raw,object_pairs_hook=unique_object))
    except ConverterError as exc: result={'ok':False,'code':exc.code}
    except Exception: result={'ok':False,'code':'SERVICE_RESULT'}
    sys.stdout.write(json.dumps(result,ensure_ascii=False,separators=(',',':')))
