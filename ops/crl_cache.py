#!/usr/bin/python3
"""Maintain signed, fresh OpenVPN CRLs without changing routes or trust roots."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

ROOT=Path('/opt/aimili-crl')
SYSTEM=Path('/etc/ssl/certs')
ALLOWED={'client','tls-client','proto','remote','remote-random','remote-random-hostname','resolv-retry','nobind','persist-key',
 'cipher','auth','data-ciphers','data-ciphers-fallback','tls-cipher','tls-ciphersuites','tls-version-min','tls-version-max',
 'ca','cert','key','pkcs12','tls-auth','tls-crypt','tls-crypt-v2','key-direction','comp-lzo','compress','float',
 'remote-cert-ku','remote-cert-eku','verify-x509-name','peer-fingerprint','sndbuf','rcvbuf','mssfix','tun-mtu','link-mtu'}
BLOCKS={'ca','cert','key','tls-auth','tls-crypt','tls-crypt-v2','extra-certs','pkcs12'}

def run(args,timeout=12,check=True):
    return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=check)

def safe_profile(source):
    lines=[];block=None
    for line in source.read_text().splitlines():
        text=line.strip()
        if block:
            lines.append(line)
            if text=='</'+block+'>':block=None
            continue
        if not text or text.startswith(('#',';')):continue
        if text.startswith('<') and text.endswith('>') and text[1:-1] in BLOCKS:
            block=text[1:-1];lines.append(line);continue
        fields=shlex.split(text)
        if fields and fields[0] in ALLOWED:lines.append(line)
    if block:raise ValueError('Unclosed inline certificate block')
    return '\n'.join(lines)+'\n'

def capture(profile,auth,work):
    work.mkdir(mode=0o700,parents=True,exist_ok=True)
    peers=work/'peers';peers.mkdir(mode=0o700)
    config=work/'capture.ovpn';config.write_text(safe_profile(profile))
    hook=work/'capture.py'
    hook.write_text('#!/usr/bin/python3\nimport os,shutil,sys\nfrom pathlib import Path\n'
      +'depth=int(sys.argv[1]);target=Path('+repr(str(peers))+')/("peer-"+str(depth)+".pem")\n'
      +'shutil.copyfile(os.environ["peer_cert"],target);target.chmod(0o600)\n'
      +'raise SystemExit(1 if depth==0 else 0)\n')
    hook.chmod(0o700)
    command=['openvpn','--config',str(config),'--dev','null','--route-nopull','--route-noexec','--ifconfig-noexec',
      '--script-security','2','--remote-cert-tls','server','--auth-user-pass',str(auth),'--auth-nocache',
      '--capath',str(SYSTEM),'--tls-export-cert',str(peers),'--tls-verify',str(hook),
      '--data-ciphers','AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305',
      '--connect-retry-max','1','--connect-timeout','5','--hand-window','10','--tls-exit','--verb','3','--log',str(work/'capture.log')]
    process=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+17
        while time.monotonic()<deadline:
            if process.poll() is not None:break
            time.sleep(.1)
    finally:
        if process.poll() is None:process.terminate()
        try:process.wait(timeout=2)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
    chain=sorted(peers.glob('peer-*.pem'),key=lambda p:int(p.stem.split('-')[-1]))
    if len(chain)<2 or not (peers/'peer-0.pem').exists():raise RuntimeError('No complete verified peer chain captured')
    intermediates=work/'intermediates.pem';intermediates.write_bytes(b''.join(p.read_bytes() for p in chain[1:]))
    run(['openssl','verify','-purpose','sslserver','-CAfile',str(SYSTEM/'ca-certificates.crt'),'-untrusted',str(intermediates),str(chain[0])])
    return chain

def safe_crl_url(url):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http','https') or not (parsed.hostname or '').endswith('.c.lencr.org'):
        raise ValueError('CRL endpoint outside supported CA domains')
    if parsed.username or parsed.password or parsed.port not in (None,80,443):raise ValueError('Invalid CRL URL')
    return url

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        safe_crl_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def signed_crl(raw,issuer,work):
    if not raw or len(raw)>8*1024*1024:raise ValueError('Invalid CRL size')
    der=work/'download.der';pem=work/'download.pem';der.write_bytes(raw)
    run(['openssl','crl','-inform','DER','-in',str(der),'-out',str(pem)])
    checked=run(['openssl','crl','-in',str(pem),'-noout','-verify','-CAfile',str(issuer),'-no-CApath','-no-CAstore'])
    # OpenSSL 3.0 can print "verify failure" while returning exit status 0.
    # Require its affirmative signature result in addition to the exit status.
    verdict=(checked.stdout+'\n'+checked.stderr).splitlines()
    if 'verify OK' not in verdict or 'verify failure' in verdict:
        raise ValueError('CRL signature verification did not succeed')
    details=run(['openssl','crl','-in',str(pem),'-noout','-hash','-lastupdate','-nextupdate']).stdout.splitlines()
    value=lambda name:next(line.split('=',1)[1] for line in details if line.startswith(name+'='))
    def date(name):return dt.datetime.strptime(value(name),'%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt.timezone.utc)
    now=dt.datetime.now(dt.timezone.utc);until=date('nextUpdate')
    if date('lastUpdate')>now+dt.timedelta(minutes=5) or until<=now+dt.timedelta(hours=12):
        raise ValueError('CRL is not current with a 12-hour safety margin')
    name_hash=next(line.rsplit('=',1)[-1].strip() for line in details if re.fullmatch('[a-f0-9]{8}',line.rsplit('=',1)[-1].strip()))
    return pem.read_bytes(),name_hash,until.isoformat()

def build_store(chain,generation):
    generation.mkdir(mode=0o700,parents=True)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),SafeRedirect())
    rows=[];counters={}
    for depth,cert in enumerate(chain[:-1]):
        text=run(['openssl','x509','-in',str(cert),'-noout','-ext','crlDistributionPoints']).stdout
        match=re.search(r'URI:(https?://\S+)',text)
        if not match:raise ValueError('Certificate has no supported CRL endpoint')
        url=safe_crl_url(match[1])
        with opener.open(url,timeout=12) as response:raw=response.read(8*1024*1024+1)
        pem,name_hash,until=signed_crl(raw,chain[depth+1],generation)
        slot=counters.get(name_hash,0);counters[name_hash]=slot+1
        filename=name_hash+'.r'+str(slot);(generation/filename).write_bytes(pem)
        rows.append({'url':url,'file':filename,'next_update':until,'sha256':hashlib.sha256(pem).hexdigest()})
    for cert in SYSTEM.iterdir():
        if re.fullmatch(r'[a-f0-9]{8}\.\d+',cert.name):(generation/cert.name).symlink_to(cert)
    crls=generation/'all-crls.pem';crls.write_bytes(b''.join((generation/r['file']).read_bytes() for r in rows))
    intermediate=generation/'chain.pem';intermediate.write_bytes(b''.join(p.read_bytes() for p in chain[1:]))
    verified=run(['openssl','verify','-purpose','sslserver','-crl_check_all','-CAfile',str(SYSTEM/'ca-certificates.crt'),
      '-untrusted',str(intermediate),'-CRLfile',str(crls),str(chain[0])],check=False)
    (generation/'manifest.json').write_text(json.dumps({'crls':rows,'peer_revocation_ok':verified.returncode==0},indent=2))
    (generation/'peer-0.pem').write_bytes(chain[0].read_bytes())
    for name in ['download.der','download.pem','chain.pem']:(generation/name).unlink(missing_ok=True)
    return rows,verified.returncode==0

def active_profile():
    group=run(['systemctl','show','aimilivpn','-p','ControlGroup','--value']).stdout.strip()
    for pid in (Path('/sys/fs/cgroup')/group.lstrip('/')/'cgroup.procs').read_text().split():
        proc=Path('/proc')/pid
        if (proc/'comm').read_text().strip()!='openvpn':continue
        args=(proc/'cmdline').read_bytes().decode().strip('\0').split('\0')
        profile=Path(args[args.index('--config')+1]);auth=Path(args[args.index('--auth-user-pass')+1])
        return profile if profile.is_absolute() else (proc/'cwd').resolve()/profile,auth
    raise RuntimeError('No active OpenVPN process; previous valid CRLs retained')

def refresh():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')
    generation=ROOT/'generations'/stamp
    try:
        profile,auth=active_profile()
        with tempfile.TemporaryDirectory(prefix='peer-',dir=ROOT) as temporary:
            chain=capture(profile,auth,Path(temporary))
            rows,ok=build_store(chain,generation)
        link=ROOT/'store.new';link.unlink(missing_ok=True);link.symlink_to(generation);os.replace(link,ROOT/'store')
        result={'updated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'status':'healthy' if ok else 'revocation_failed',
                'crls':rows,'peer_revocation_ok':ok}
        temporary=ROOT/'status.new';temporary.write_text(json.dumps(result,indent=2));os.replace(temporary,ROOT/'status.json')
        for old in sorted((ROOT/'generations').iterdir(),reverse=True)[3:]:shutil.rmtree(old)
        if not ok:raise RuntimeError('Peer failed strict revocation check; signed CRLs installed for enforcement')
        print(json.dumps(result),flush=True)
    except Exception as exc:
        store=ROOT/'store'
        if generation.exists() and (not store.exists() or store.resolve()!=generation.resolve()):
            shutil.rmtree(generation)
        status=ROOT/'status.json'
        previous=json.loads(status.read_text()) if status.exists() else {}
        previous.update({'status':'refresh_failed','last_attempt_at':dt.datetime.now(dt.timezone.utc).isoformat(),
                         'error':str(exc)[:300]})
        temporary=ROOT/'status.new';temporary.write_text(json.dumps(previous,indent=2));os.replace(temporary,status)
        print('[CRL ALERT] Refresh failed; prior CRLs are retained: '+str(exc),flush=True)
        raise

if __name__=='__main__':
    os.umask(0o077)
    import fcntl
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    lock=(ROOT/'refresh.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    refresh()
