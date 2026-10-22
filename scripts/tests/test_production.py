"""Operational safety regressions; no Docker daemon or deployment credentials needed."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import production


class OperationsTests(unittest.TestCase):
    def test_generated_configuration_is_private_unique_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            one, two = Path(directory) / 'one.env', Path(directory) / 'two.env'
            production.initialize(one)
            production.initialize(two)
            self.assertEqual(one.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(one.read_text(), two.read_text())
            self.assertIn('MFA_ENFORCED_ROLES=admin', one.read_text())
            original = one.read_bytes()
            with self.assertRaises(FileExistsError):
                production.initialize(one)
            self.assertEqual(one.read_bytes(), original)

    def test_tampering_and_wrong_keys_are_rejected_before_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, key = Path(directory) / 'dump.enc', Path(directory) / 'key'
            archive.write_bytes(os.urandom(256))
            key.write_text('a' * 64)
            key.chmod(0o600)
            metadata = {'format': 1, 'hmac_sha256': production.archive_mac(archive, key)}
            Path(str(archive) + '.json').write_text(json.dumps(metadata))
            for corrupt in ('key', 'archive'):
                with self.subTest(corrupt=corrupt):
                    if corrupt == 'key':
                        key.write_text('b' * 64)
                    else:
                        key.write_text('a' * 64)
                        archive.write_bytes(b'tampered')
                    with patch.object(production, 'run') as docker:
                        with self.assertRaisesRegex(ValueError, 'authentication failed'):
                            production.restore_drill(archive, key)
                        docker.assert_not_called()

    def test_preflight_rejects_mutable_images_and_missing_security(self):
        values = {'SECRET_KEY': 'a' * 64, 'INTEGRATIONS_KEY': 'b' * 64,
                      'GUARDIANO_ADMIN_PASSWORD': 'c' * 32, 'POSTGRES_PASSWORD': 'd' * 32,
                      'PUBLIC_URL': 'https://example.test', 'MFA_ENFORCED_ROLES': 'admin',
                      'METRICS_ENABLED': 'true', 'METRICS_TOKEN': 'e' * 32}
        cfg = {'services': {name: {'image': 'image@sha256:' + 'a' * 64,
                                   'environment': values.copy()}
                            for name in ('backend', 'worker', 'frontend', 'db')}}
        with patch.object(production, 'config', return_value=cfg):
            production.preflight('unused')
            for key, value in [('SECRET_KEY', 'short'), ('INTEGRATIONS_KEY', 'a' * 64),
                               ('PUBLIC_URL', 'http://example.test'), ('COOKIE_SECURE', 'false'),
                               ('MFA_ENFORCED_ROLES', ''), ('METRICS_TOKEN', '')]:
                with self.subTest(key=key):
                    cfg['services']['backend']['environment'] = values | {key: value}
                    with self.assertRaises(ValueError):
                        production.preflight('unused')
            cfg['services']['backend']['environment'] = values
            cfg['services']['frontend']['image'] = 'image:latest'
            with self.assertRaisesRegex(ValueError, 'digest'):
                production.preflight('unused')

    def test_backup_does_not_remove_another_in_progress_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            target, key = Path(directory) / 'backup.enc', Path(directory) / 'key'
            key.write_text('a' * 64)
            key.chmod(0o600)
            partial = Path(str(target) + '.partial')
            partial.write_bytes(b'other backup in progress')
            cfg = {'services': {'backend': {'environment': {}}, 'db': {'environment': {
                'POSTGRES_USER': 'test', 'POSTGRES_DB': 'test'}}}}
            with (
                patch.object(production, 'config', return_value=cfg),
                self.assertRaises(FileExistsError),
            ):
                production.backup('unused', target, key)
            self.assertEqual(partial.read_bytes(), b'other backup in progress')

    def test_backup_key_must_be_private(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'key'
            key.write_text('a' * 64)
            key.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'chmod 600'):
                production.backup_key(key)
            key.chmod(0o600)
            self.assertEqual(production.backup_key(key), b'a' * 64)

    def test_upgrade_failure_keeps_writes_stopped(self):
        with patch.object(production, 'preflight'), patch.object(production, 'run') as run, \
                patch.object(production, 'backup', side_effect=RuntimeError('backup failed')):
            with self.assertRaisesRegex(RuntimeError, 'backup failed'):
                production.deploy('unused.env', True, 'archive', 'key')
            calls = [call.args[0] for call in run.call_args_list]
            self.assertTrue(any('stop' in call for call in calls))
            self.assertFalse(any('up' in call for call in calls))

    def test_image_gate_blocks_critical_and_fixable_high_without_hiding_unfixed(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('image_audit', production.ROOT / 'scripts/image-audit.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        critical = {'Severity': 'CRITICAL'}
        fixable = {'Severity': 'HIGH', 'FixedVersion': '2'}
        unfixed = {'Severity': 'HIGH'}
        report = {'Results': [{'Vulnerabilities': [critical, fixable, unfixed, {'Severity': 'LOW'}]}]}
        blocking, review = module.evaluate(report)
        self.assertEqual(blocking, [critical, fixable])
        self.assertEqual(review, [unfixed])


if __name__ == '__main__':
    unittest.main()
