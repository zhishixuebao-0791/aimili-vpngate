"""CRL trust and cache failure tests, without real network or VPN processes."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('crl_cache',ROOT/'ops/crl_cache.py')
cache=importlib.util.module_from_spec(spec);spec.loader.exec_module(cache)


class CRLCacheTests(unittest.TestCase):
    def test_signature_failure_with_zero_exit_status_is_rejected(self):
        # Reproduce OpenSSL 3.0: -verify prints failure but exits successfully.
        with tempfile.TemporaryDirectory() as directory:
            result=subprocess.CompletedProcess(['openssl'],0,'','verify failure\n')
            with patch.object(cache,'run',return_value=result) as command:
                with self.assertRaisesRegex(ValueError,'signature'):cache.signed_crl(b'DER','issuer.pem',Path(directory))
            self.assertIn('-no-CApath',command.call_args.args[0])
            self.assertIn('-no-CAstore',command.call_args.args[0])

    def test_empty_or_oversized_crl_never_reaches_openssl(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(cache,'run') as command:
            for raw in [b'',b'x'*(8*1024*1024+1)]:
                with self.assertRaises(ValueError):cache.signed_crl(raw,'issuer.pem',Path(directory))
            command.assert_not_called()

    def test_unapproved_urls_and_redirects_cannot_fetch_other_hosts(self):
        for url in ['file:///etc/passwd','http://127.0.0.1/a','https://yr2.c.lencr.org.evil/a',
                    'http://user:password@yr2.c.lencr.org/a','http://yr2.c.lencr.org:8000/a']:
            with self.subTest(url=url),self.assertRaises(ValueError):cache.safe_crl_url(url)
        with self.assertRaises(ValueError):cache.SafeRedirect().redirect_request(None,None,302,'',{},'http://127.0.0.1/')
        self.assertEqual(cache.safe_crl_url('http://yr2.c.lencr.org/105.crl'),'http://yr2.c.lencr.org/105.crl')

    def test_capture_profile_excludes_scripts_routes_and_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'profile.ovpn'
            source.write_text('client\nremote 192.0.2.1 443\ndev tun0\nroute 0.0.0.0 0.0.0.0\nup /evil\nscript-security 2\n<ca>\nPUBLIC-CA\n</ca>\n')
            value=cache.safe_profile(source)
            self.assertIn('remote 192.0.2.1 443',value);self.assertIn('PUBLIC-CA',value)
            for line in ['dev tun0','route 0.0.0.0','up /evil','script-security']:self.assertNotIn(line,value)
            source.write_text('<ca>\nPUBLIC-CA\n')
            with self.assertRaises(ValueError):cache.safe_profile(source)

    def test_failed_refresh_preserves_prior_state_without_switching_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'status.json').write_text(json.dumps({'status':'healthy','updated_at':'known-good'}))
            (root/'store').mkdir();(root/'store/marker').write_text('prior-valid-cache')
            with patch.object(cache,'ROOT',root),patch.object(cache,'active_profile',side_effect=TimeoutError('probe failed')):
                with self.assertRaises(TimeoutError):cache.refresh()
            self.assertEqual((root/'store/marker').read_text(),'prior-valid-cache')
            state=json.loads((root/'status.json').read_text())
            self.assertEqual(state['updated_at'],'known-good');self.assertEqual(state['status'],'refresh_failed')


if __name__=='__main__':unittest.main()
