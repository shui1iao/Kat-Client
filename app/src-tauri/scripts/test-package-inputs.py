#!/usr/bin/env python3
"""Defensive tests for unsigned input handling. Never read a key, sign, compile, or run a PE."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from types import SimpleNamespace
from package_inputs import APP, ASSETS, AUTH, FILES, INPUTS, ROLES, ROOT, RUNTIME, SETUP_AUTH, snapshot, transfer

signer = runpy.run_path(str(ROOT/'scripts/sign-update-manifest.py'))


stager = runpy.run_path(str(ROOT/'scripts/stage-package.py'))


class PackageInputs(unittest.TestCase):
    def test_old_handoff_wire_shape_and_independent_full_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp); (payload/'network').mkdir()
            for n in ASSETS + ROLES:
                (payload/n).write_bytes(n.encode())
            bridge = stager['bridge_descriptor']('a'*40, {n: transfer(payload/n)[0] for n in ROLES})
            # Exact keys understood by the shipping v0.2.28 deny_unknown_fields reader.
            self.assertEqual(set(bridge), set('schema product key_id os arch app_version stdio_protocol service_protocol record_schema workspace_schema source_revision components'.split()))
            self.assertEqual((bridge['schema'], bridge['product']), (1, 'kat-client-package'))
            self.assertCountEqual(bridge['components'], ROLES)
            raw = json.dumps(bridge).encode(); sig = b'ab'*64+b'\n'  # preparer fixture only; NOT valid release authorization
            (payload/AUTH[0]).write_bytes(raw); (payload/AUTH[1]).write_bytes(sig)
            stager['describe_setup'](SimpleNamespace(payload=payload))
            full = (payload/SETUP_AUTH[0]).read_bytes(); setup = json.loads(full)
            self.assertEqual(setup['bridge'], bridge)
            self.assertCountEqual(setup['assets'], ASSETS + AUTH)
            self.assertEqual(setup['assets'][AUTH[0]], hashlib.sha256(raw).hexdigest())
            self.assertEqual(setup['assets'][AUTH[1]], hashlib.sha256(sig).hexdigest())
            for data, kind in [(raw, 'package'), (full, 'setup')]: signer['validate'](data, kind)
            for data, kind in [(raw, 'setup'), (full, 'package')]:
                with self.assertRaises(signer['Invalid']): signer['validate'](data, kind)
            for n in ROLES + ASSETS + AUTH:
                other = copy.deepcopy(setup); del (other['bridge']['components'] if n in ROLES else other['assets'])[n]
                with self.assertRaises(signer['Invalid']): signer['validate'](json.dumps(other).encode(), 'setup')
            self.assertCountEqual(ROLES + ASSETS + AUTH, APP + RUNTIME)
            self.assertTrue(set(SETUP_AUTH).isdisjoint(FILES))

    def test_snapshot_includes_setup_only_authority_and_installed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); payload = root/'payload'; (payload/'network').mkdir(parents=True)
            for name in INPUTS:
                (payload/name).write_bytes(('fixture: ' + name).encode())
            (payload/'not-installed').write_text('not part of setup')
            dest = root/'snapshot'; rows = snapshot(payload, dest)
            self.assertCountEqual([r['path'] for r in rows], INPUTS)
            self.assertFalse((dest/'not-installed').exists())
            for row in rows:
                data = (dest/row['path']).read_bytes()
                self.assertEqual(data, (payload/row['path']).read_bytes())
                self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (row['bytes'], row['sha256']))
            (payload/SETUP_AUTH[1]).unlink()
            with self.assertRaises(FileNotFoundError): snapshot(payload, root/'missing-sig')
            (payload/SETUP_AUTH[1]).write_bytes(b'fixture')
            (payload/'Restore-User-Proxy.cmd').unlink()
            with self.assertRaises(FileNotFoundError): snapshot(payload, root/'missing')
            (payload/'Restore-User-Proxy.cmd').symlink_to('not-installed')
            with self.assertRaises(OSError): snapshot(payload, root/'link')
            with self.assertRaises(ValueError): transfer(payload/'Kat-Uninstall.exe', maximum=1)


if __name__ == '__main__':
    unittest.main()
