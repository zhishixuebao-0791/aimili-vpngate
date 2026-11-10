"""OpenVPN startup failures: no network, routes, or service processes are used."""
import ast
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
import types
import unittest

ROOT=Path(os.environ.get('AIMILI_TEST_SOURCE_ROOT',str(Path(__file__).resolve().parents[1])))

def functions(file,names,extras=None):
    tree=ast.parse((ROOT/file).read_text(encoding='utf-8'))
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert len(nodes)==len(names)
    future=ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)
    module=ast.fix_missing_locations(ast.Module(body=[future]+nodes,type_ignores=[]))
    namespace=dict(extras or {})
    exec(compile(module,file,'exec'),namespace)
    return namespace

class OpenVPNTests(unittest.TestCase):
    def setUp(self):
        self.utils=types.SimpleNamespace(**{k:v for k,v in functions('vpn_utils.py',['diagnose_openvpn_failure','openvpn_startup_transport_failure']).items() if callable(v)})
    def test_no_route_and_network_unreachable_are_node_errors(self):
        for value in ['No route to host','Network is unreachable']:
            code,msg=self.utils.diagnose_openvpn_failure(['TCP: connect to [AF_INET]192.0.2.1:443 failed: '+value,'Exiting due to fatal error'])
            self.assertEqual(code,2004);self.assertIn('ERR_OVPN_NODE_UNREACHABLE',msg)
    def test_auth_and_tun_errors_keep_existing_classification(self):
        for line,expected in [('AUTH_FAILED',2005),('cannot ioctl TUNSETIFF',2009),('Connection refused',2004)]:
            self.assertEqual(self.utils.diagnose_openvpn_failure([line])[0],expected)
    def test_only_conclusive_tcp_startup_failure_matches(self):
        for why in ['No route to host','Network is unreachable','Connection refused','Connection timed out']:
            self.assertTrue(self.utils.openvpn_startup_transport_failure('TCP: connect to [AF_INET]192.0.2.1:443 failed: '+why))
        for line in ['VERIFY WARNING: unable to get certificate CRL','Options error: dhcp-option','Authenticate/Decrypt packet error: bad packet ID','UDP read error: Connection refused','Initialization Sequence Completed']:
            self.assertFalse(self.utils.openvpn_startup_transport_failure(line))
    def run_startup(self,lines,blocked=False):
        stopped=threading.Event();calls=[]
        class Stream:
            def __iter__(self):
                yield from (v+'\n' for v in lines)
                if blocked:
                    stopped.wait(2)
                    yield 'Exiting due to fatal error\n'
        process=types.SimpleNamespace(stdout=Stream(),poll=lambda:None)
        def stop(*args,**kwargs):calls.append(True);stopped.set()
        ns={'queue':queue,'threading':threading,'time':time,'ROOT_DIR':ROOT,'OPENVPN_TEST_TIMEOUT_SECONDS':4,
            'subprocess':types.SimpleNamespace(Popen=lambda *a,**kw:process,PIPE=subprocess.PIPE,STDOUT=subprocess.STDOUT),
            'openvpn_command':lambda *a:['openvpn','--connect-retry-max','1'],
            'update_handshake_status':lambda *a:None,'log_to_json':lambda *a:None,'stop_process':stop,
            'vpn_utils':self.utils,'is_probe_timeout_message':lambda s:any(v in s.lower() for v in ['timeout','timed out'])}
        f=functions('vpngate_manager.py',['run_openvpn_until_ready'],ns)['run_openvpn_until_ready']
        started=time.monotonic()
        result=f('fake.ovpn',False,True,timeout=4,keep_process=True)
        return result,time.monotonic()-started,calls
    def test_supervisor_skips_retry_sleep_and_preserves_error_code(self):
        for why in ['No route to host','Connection refused','Connection timed out']:
            result,elapsed,stops=self.run_startup(['TCP: connect to [AF_INET]192.0.2.1:443 failed: '+why],True)
            self.assertFalse(result[0]);self.assertIn('错误代码 2004',result[1]);self.assertLess(elapsed,1)
            self.assertTrue(stops)
    def test_success_after_ignorable_warnings_keeps_process(self):
        result,elapsed,stops=self.run_startup(['VERIFY WARNING: unable to get certificate CRL',"Options error: option 'dhcp-option' cannot be used in this context",'Initialization Sequence Completed'])
        self.assertTrue(result[0]);self.assertIsNotNone(result[2]);self.assertFalse(stops)

if __name__=="__main__":unittest.main()
