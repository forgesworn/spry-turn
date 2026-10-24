"""Generated, stdin-only FIPS fixture controller; never a network API."""
import ipaddress,json,os,signal,subprocess,sys,time
from pathlib import Path
root=Path('/tmp/fips');root.mkdir()
config={'node':{'identity':{'persistent':True},'discovery':{'lan':{'enabled':False},'nostr':{'enabled':False}}},'tun':{'enabled':True,'name':'fips0','mtu':1280},'dns':{'enabled':True,'bind_addr':'::1','port':5354},'transports':{'tcp':{'bind_addr':'0.0.0.0:8443'},'udp':{'bind_addr':'0.0.0.0:2121'}},'peers':[]}
(root/'fips.yaml').write_text(json.dumps(config))
log=open('/tmp/fips.log','w')
p=subprocess.Popen(['/fixture/fips','-c',str(root/'fips.yaml')],stdout=log,stderr=log)
def stop(*_):raise SystemExit()
signal.signal(signal.SIGTERM,stop)
try:
 deadline=time.monotonic()+15
 while True:
  if p.poll() is not None:raise RuntimeError(Path('/tmp/fips.log').read_text()[-3000:])
  lines=Path('/proc/net/if_inet6').read_text().splitlines()
  addresses=[str(ipaddress.IPv6Address(int(line.split()[0],16))) for line in lines if line.split()[-1]=='fips0' and int(line.split()[0],16) >> 121 == 0x7e]
  pub=root/'fips.pub'
  if addresses and pub.exists():break
  if time.monotonic()>deadline:raise TimeoutError(Path('/tmp/fips.log').read_text()[-3000:])
  time.sleep(.05)
 print(json.dumps({'address':addresses[0],'public':pub.read_text().strip()}),flush=True)
 for line in sys.stdin:
  value=json.loads(line)
  if value.get('action')=='connect':
   result=subprocess.run(['/fixture/fipsctl','connect',value['npub'],value['address'],'tcp'],capture_output=True,text=True,timeout=10)
   print(json.dumps({'ok':result.returncode==0,'reply':result.stdout[-200:]}),flush=True)
  else:
   result=subprocess.run(['/fixture/fipsctl','show','status'],capture_output=True,text=True,timeout=3)
   print(json.dumps({'ok':result.returncode==0,'status':json.loads(result.stdout)}),flush=True)
finally:
 p.terminate()
 try:p.wait(timeout=3)
 except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
 log.close()
