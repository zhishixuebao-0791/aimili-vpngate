"""Network boundary tests; no real interfaces, routes or credentials are changed."""
import ast
import errno
import importlib.util
import io
import os
from pathlib import Path
import socket
import unittest
from unittest.mock import Mock, patch

ROOT=Path(os.environ.get('AIMILI_TEST_SOURCE_ROOT',str(Path(__file__).resolve().parents[1])))
spec=importlib.util.spec_from_file_location('proxy_under_test',ROOT/'proxy_server.py')
proxy=importlib.util.module_from_spec(spec);spec.loader.exec_module(proxy)


class IPv6CapabilityTests(unittest.TestCase):
    def capacity(self,addresses,routes):
        def source(path,**kwargs):
            return io.StringIO(addresses if path.endswith('if_inet6') else routes)
        with patch('builtins.open',side_effect=source):return proxy.tun0_supports_ipv6()

    def test_link_local_address_does_not_enable_ipv6(self):
        self.assertFalse(self.capacity('fe800000000000000000000000000001 02 40 20 80 tun0\n',
            '0'*32+' 00 '+'0'*32+' 00 '+'0'*32+' 00000001 00000000 00000000 00000001 tun0\n'))

    def test_connected_subnet_does_not_count_as_internet_route(self):
        self.assertFalse(self.capacity('20010db8000000000000000000000001 02 40 00 80 tun0\n',
            '20010db8000000000000000000000000 40 '+'0'*32+' 00 '+'0'*32+' 00000001 00000000 00000000 00000001 tun0\n'))

    def test_global_address_and_default_route_enable_ipv6(self):
        self.assertTrue(self.capacity('20010db8000000000000000000000001 02 40 00 80 tun0\n',
            '0'*32+' 00 '+'0'*32+' 00 '+'0'*32+' 00000001 00000000 00000000 00000001 tun0\n'))

    def test_rejected_or_other_interface_route_is_not_usable(self):
        address='20010db8000000000000000000000001 02 40 00 80 tun0\n'
        for flags,device in [('00000201','tun0'),('00000001','eth0')]:
            with self.subTest(flags=flags,device=device):
                self.assertFalse(self.capacity(address,'0'*32+' 00 '+'0'*32+' 00 '+'0'*32+
                    ' 00000001 00000000 00000000 '+flags+' '+device+'\n'))

    def test_missing_or_malformed_kernel_state_fails_closed(self):
        with patch('builtins.open',side_effect=FileNotFoundError):self.assertFalse(proxy.tun0_supports_ipv6())
        self.assertFalse(self.capacity('not a kernel record','not a route'))


class ProxyConnectionTests(unittest.TestCase):
    def test_ipv4_domain_does_not_query_aaaa(self):
        with patch.object(proxy,'dns_query_over_tun0',return_value='192.0.2.1') as dns:
            self.assertEqual(proxy.resolve_dns_over_tun0('example.test'),'192.0.2.1')
            self.assertEqual(dns.call_args.args[1],1);self.assertEqual(dns.call_count,1)

    def test_ipv4_only_tunnel_does_not_request_unusable_aaaa(self):
        with patch.object(proxy,'dns_query_over_tun0',return_value=None) as dns,patch.object(proxy,'tun0_supports_ipv6',return_value=False):
            self.assertIsNone(proxy.resolve_dns_over_tun0('example.test'))
            self.assertEqual([c.args[1] for c in dns.call_args_list],[1])

    def test_working_ipv6_tunnel_keeps_aaaa_support(self):
        with patch.object(proxy,'dns_query_over_tun0',side_effect=[None,'2001:db8::1']) as dns,patch.object(proxy,'tun0_supports_ipv6',return_value=True):
            self.assertEqual(proxy.resolve_dns_over_tun0('example.test'),'2001:db8::1')
            self.assertEqual([c.args[1] for c in dns.call_args_list],[1,28])

    def test_unsupported_ipv6_literal_fails_before_socket_or_dns(self):
        with patch.object(proxy,'tun0_supports_ipv6',return_value=False),patch.object(proxy,'dns_query_over_tun0') as dns,patch.object(proxy.socket,'socket') as create:
            with self.assertRaises(OSError) as error:proxy.create_connection(('2001:db8::1',443))
            self.assertEqual(error.exception.errno,errno.EAFNOSUPPORT);dns.assert_not_called();create.assert_not_called()

    def test_system_dns_fallback_stays_ipv4_and_bound_to_tunnel(self):
        sock=Mock();addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.2',443))]
        with patch.object(proxy,'resolve_dns_over_tun0',return_value=None),patch.object(proxy,'tun0_supports_ipv6',return_value=False),patch.object(proxy.socket,'getaddrinfo',return_value=addresses) as dns,patch.object(proxy.socket,'socket',return_value=sock),patch.object(proxy.socket,'SO_BINDTODEVICE',25,create=True):
            self.assertIs(proxy.create_connection(('example.test',443)),sock)
            self.assertEqual(dns.call_args.args[2],socket.AF_INET)
            sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET,25,b'tun0')
            sock.connect.assert_called_once_with(('192.0.2.2',443))

    def test_failed_socket_is_closed_before_next_address(self):
        first,second=Mock(),Mock();first.connect.side_effect=OSError(errno.EHOSTUNREACH,'unreachable')
        records=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.2',443))]
        with patch.object(proxy,'resolve_dns_over_tun0',return_value=None),patch.object(proxy,'tun0_supports_ipv6',return_value=False),patch.object(proxy.socket,'getaddrinfo',return_value=records),patch.object(proxy.socket,'socket',side_effect=[first,second]),patch.object(proxy.socket,'SO_BINDTODEVICE',25,create=True):
            self.assertIs(proxy.create_connection(('example.test',443)),second);first.close.assert_called_once()

    def test_socks_reports_unsupported_address_family(self):
        client=Mock()
        chunks=[bytes([1]),bytes([0]),bytes([5,1,0,4]),socket.inet_pton(socket.AF_INET6,'2001:db8::1'),(443).to_bytes(2,'big')]
        with patch.object(proxy,'recv_exact',side_effect=chunks),patch.object(proxy,'proxy_auth_enabled',return_value=False),patch.object(proxy,'create_connection',side_effect=OSError(errno.EAFNOSUPPORT,'unsupported')),patch.object(proxy,'throttled_print'):
            with self.assertRaises(OSError):proxy.socks5_client(client,bytes([5]))
        self.assertEqual(client.sendall.call_args_list[-1].args[0][:2],bytes([5,8]));client.close.assert_called_once()


class CertificateCommandTests(unittest.TestCase):
    def command(self,version):
        tree=ast.parse((ROOT/'vpngate_manager.py').read_text(encoding='utf-8'))
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='openvpn_command')
        ns={'split_openvpn_command':lambda:['openvpn'],'AUTH_FILE':Path('unused-auth'),
            'get_openvpn_version':lambda:version,'os':__import__('os'),'Path':Path,
            'vpn_utils':Mock(is_config_tcp=Mock(return_value=False)), 'upstream_proxy_auth_file':lambda:None}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'command','exec'),ns)
        with patch('os.path.exists',return_value=True):return ns['openvpn_command']('unused-profile',True)

    def test_modern_and_legacy_commands_require_server_certificate_role(self):
        for version in [2.4,2.5,2.6]:
            with self.subTest(version=version):
                command=self.command(version)
                self.assertEqual(command[command.index('--remote-cert-tls')+1],'server')
                self.assertIn('--capath',command);self.assertIn('--route-nopull',command)
                self.assertNotIn('--verify-client-cert',command)


if __name__=='__main__':unittest.main()
