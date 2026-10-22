#!/usr/bin/env python3
"""Production operations. No shell interpolation, no plaintext database dumps on disk."""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def compose(env):
    os.environ['GUARDIANO_ENV_FILE'] = str(Path(env).resolve())
    return ['docker', 'compose', '--env-file', str(Path(env).resolve()), '-f',
            str(ROOT / 'docker-compose.yml'), '-f', str(ROOT / 'docker-compose.production.yml')]


def config(env):
    result = run(compose(env) + ['config', '--format', 'json'], capture_output=True, text=True)
    return json.loads(result.stdout)


def preflight(env, immutable=True):
    cfg = config(env)
    services = cfg['services']
    values = services['backend']['environment']
    for key in ('SECRET_KEY', 'INTEGRATIONS_KEY', 'GUARDIANO_ADMIN_PASSWORD', 'POSTGRES_PASSWORD'):
        value = str(values.get(key, ''))
        if len(value) < 20 or value in ('ChangeMe-Admin-2026!', 'guardiano') or 'change-me' in value:
            raise ValueError(f'{key} must be a unique secret of at least 20 characters')
    if values['SECRET_KEY'] == values['INTEGRATIONS_KEY']:
        raise ValueError('INTEGRATIONS_KEY must be independent of SECRET_KEY')
    if not values.get('PUBLIC_URL', '').startswith('https://'):
        raise ValueError('PUBLIC_URL must use HTTPS')
    if values.get('COOKIE_SECURE', 'true').lower() != 'true':
        raise ValueError('Secure cookies must be enabled')
    if values.get('LOCAL_LOGIN', 'true').lower() == 'true' and 'admin' not in {
            role.strip() for role in values.get('MFA_ENFORCED_ROLES', '').split(',')}:
        raise ValueError('Enforce admin MFA or configure OIDC with MFA at the identity provider')
    if values.get('METRICS_ENABLED', '').lower() != 'true' or len(values.get('METRICS_TOKEN', '')) < 20:
        raise ValueError('Enable metrics and set a strong METRICS_TOKEN')
    if len(values['SECRET_KEY']) < 32:
        raise ValueError('SECRET_KEY must contain at least 32 characters')
    network = ipaddress.ip_network(services['frontend']['environment'].get('REAL_IP_FROM', '127.0.0.1/32'))
    if network.prefixlen == 0:
        raise ValueError('REAL_IP_FROM must not trust all addresses')
    if values.get('DATABASE_URL'):
        raise ValueError('This deployment/backup workflow supports the bundled database only')
    for name in ('backend', 'worker', 'frontend', 'db'):
        if immutable and not re.fullmatch(r'.+@sha256:[0-9a-f]{64}', services[name]['image']):
            raise ValueError(f'{name}: production images must use a digest')
    if services['db'].get('ports'):
        raise ValueError('Database ports must not be published')
    print('Production preflight passed')


def initialize(path):
    content = (ROOT / '.env.example').read_text()
    values = {'ENV': 'production', 'SECRET_KEY': secrets.token_hex(32),
              'INTEGRATIONS_KEY': secrets.token_hex(32), 'POSTGRES_PASSWORD': secrets.token_hex(24),
              'GUARDIANO_ADMIN_PASSWORD': secrets.token_urlsafe(30), 'MFA_ENFORCED_ROLES': 'admin',
              'METRICS_ENABLED': 'true', 'METRICS_TOKEN': secrets.token_hex(32)}
    for key, value in values.items():
        content = '\n'.join(f'{key}={value}' if line.startswith(key + '=') else line
                            for line in content.split('\n'))
    content += '\nGUARDIANO_ENV_FILE=' + str(Path(path).resolve()) + '\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(content)
    print(f'Created {path}; set PUBLIC_URL, admin email, proxy CIDR and image digests before deployment')


def backup_key(keyfile):
    with open(keyfile, 'rb') as source:
        if os.fstat(source.fileno()).st_mode & 0o077:
            raise ValueError('Backup key file must not be readable by group or other users (chmod 600)')
        key = source.read().strip()
    if len(key) < 32 or b'\n' in key or b'\r' in key:
        raise ValueError('Backup key must be one line containing at least 32 random characters')
    return key


def archive_mac(archive, keyfile):
    key = backup_key(keyfile)
    signing = hmac.new(key, b"guardiano-backup-authentication-v1", hashlib.sha256).digest()
    digest = hmac.new(signing, digestmod=hashlib.sha256)
    with open(archive, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup(env, target, keyfile):
    target = Path(target)
    backup_key(keyfile)
    if target.exists() or Path(str(target) + '.json').exists():
        raise ValueError('Backup destination already exists')
    # Metadata/configuration secrets are deliberately backed up separately in the secrets vault.
    deployment = config(env)
    if deployment['services']['backend']['environment'].get('DATABASE_URL'):
        raise ValueError('External DATABASE_URL requires a database-specific backup procedure')
    cfg = deployment['services']['db']['environment']
    dump = compose(env) + ['exec', '-T', 'db', 'pg_dump', '-U', cfg['POSTGRES_USER'],
                          '-d', cfg['POSTGRES_DB'], '-Fc', '--no-owner', '--no-acl']
    partial = target.with_name(target.name + '.partial')
    partial_owned = False
    try:
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        partial_owned = True
        with os.fdopen(fd, 'wb') as output:
            producer = subprocess.Popen(dump, stdout=subprocess.PIPE)
            try:
                run(['openssl', 'enc', '-aes-256-cbc', '-salt', '-pbkdf2', '-iter', '600000',
                     '-pass', f'file:{keyfile}'], stdin=producer.stdout, stdout=output)
            finally:
                producer.stdout.close()
                code = producer.wait()
            if code:
                raise RuntimeError('pg_dump failed; backup discarded')
            output.flush()
            os.fsync(output.fileno())
        container_ids = run(compose(env) + ['ps', '--all', '-q'], capture_output=True, text=True).stdout.split()
        observed = []
        if container_ids:
            observed = run(['docker', 'inspect', '--format',
                            '{{.Name}} {{.Config.Image}} {{.Image}}', *container_ids],
                           capture_output=True, text=True).stdout.splitlines()
        manifest = {'format': 1, 'observed_container_images': observed, 'hmac_sha256': archive_mac(partial, keyfile),
                    'created_unix': time.time(),
                    'images': {name: service.get('image') for name, service in
                               config(env)['services'].items()}}
        metadata = Path(str(target) + '.json')
        fd = os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(manifest, output, indent=2)
        # Exclusive hard-link publication cannot overwrite another backup with the same name.
        os.link(partial, target)
        partial.unlink()
    except BaseException:
        if partial_owned:
            partial.unlink(missing_ok=True)
        raise
    print(f'Encrypted backup: {target}')


def restore_drill(archive, keyfile, env=None, application_check=False):
    manifest = json.loads(Path(str(archive) + '.json').read_text())
    if manifest['format'] != 1 or not hmac.compare_digest(
            manifest['hmac_sha256'], archive_mac(archive, keyfile)):
        raise ValueError('Backup authentication failed; refusing restore')
    postgres_image = (config(env)['services']['db']['image']
                      if env and Path(env).is_file() else 'postgres:16-alpine')
    name = 'guardiano-restore-' + uuid.uuid4().hex[:12]
    # Fresh, isolated container: never connects to the deployment database.
    run(['docker', 'run', '-d', '--name', name, '--network', 'none',
         '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_DB=restore_test', postgres_image],
        stdout=subprocess.DEVNULL)
    try:
        for _ in range(60):
            if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Restore database did not start')
        decoder = subprocess.Popen(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '600000',
                                    '-pass', f'file:{keyfile}', '-in', str(archive)], stdout=subprocess.PIPE)
        try:
            run(['docker', 'exec', '-i', name, 'pg_restore', '-U', 'postgres', '-d', 'restore_test',
                 '--exit-on-error', '--no-owner', '--no-acl'], stdin=decoder.stdout)
        finally:
            decoder.stdout.close()
            code = decoder.wait()
        if code:
            raise RuntimeError('Backup decryption failed')
        run(['docker', 'exec', name, 'psql', '-U', 'postgres', '-d', 'restore_test', '-v', 'ON_ERROR_STOP=1',
             '-c', ('SELECT * FROM alembic_version; SELECT count(*) FROM users; '
                    'SELECT count(*) FROM findings; SELECT count(*) FROM assets;')])
        if application_check:
            if not env:
                raise ValueError('Application restore checks require the original --env-file')
            deployment = config(env)['services']['backend']
            payload = {'environment': deployment['environment']}
            # Secrets travel on stdin rather than command arguments or Docker environment metadata.
            run(['docker', 'run', '--rm', '-i', '--network', 'container:' + name,
                 deployment['image'], 'python', '-c', APPLICATION_CHECK],
                input=json.dumps(payload), text=True)
        print('Isolated restore passed' + (' including application/MFA/inventory checks' if application_check
                                         else '; application checks still required'))
    finally:
        run(['docker', 'rm', '-fv', name], stdout=subprocess.DEVNULL)


def smoke(url):
    for path in ('/', '/nginx-health', '/api/v1/meta'):
        with urllib.request.urlopen(url.rstrip('/') + path, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(f'Smoke failed: {path}')
            if path.endswith('/meta') and json.load(response)['docs_enabled']:
                raise RuntimeError('API is not running in production mode')
    print('Public frontend/API smoke passed')


# Runs only inside the isolated restored database network; never writes to the source installation.
APPLICATION_CHECK = r"""
import json, os, sys, time
payload = json.load(sys.stdin)
os.environ.update({k: str(v) for k, v in payload['environment'].items() if v is not None})
os.environ['DATABASE_URL'] = 'postgresql+psycopg://postgres@127.0.0.1:5432/restore_test'
os.environ['LOG_LEVEL'] = 'ERROR'
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.main import app
from app.core.db import SessionLocal
from app.core.crypto import decrypt
from app.core.totp import code_at, current_step
from app.models import User, Integration, Webhook
with SessionLocal() as db:
    for user in db.scalars(select(User).where(User.mfa_secret.is_not(None))):
        decrypt(user.mfa_secret)
    for integration in db.scalars(select(Integration)):
        decrypt(integration.secret_encrypted)
    for webhook in db.scalars(select(Webhook)):
        webhook.secret
    admin = db.scalar(select(User).where(User.email == os.environ['GUARDIANO_ADMIN_EMAIL']))
    assert admin is not None, 'Initial administrator absent; use recovery staging for your chosen account'
    secret = decrypt(admin.mfa_secret) if admin.mfa_enabled else None
    last_step = admin.mfa_last_step or 0
with TestClient(app, base_url='https://restore.test') as client:
    assert client.get('/readyz').status_code == 200
    response = client.post('/api/v1/auth/login', json={
        'email': os.environ['GUARDIANO_ADMIN_EMAIL'], 'password': os.environ['GUARDIANO_ADMIN_PASSWORD']})
    assert response.status_code == 200, 'Restored administrator login failed'
    session = response.json()
    if secret:
        step = current_step(time.time())
        if step <= last_step:
            time.sleep(max(0, (last_step + 1) * 30 - time.time()) + 1)
        response = client.post('/api/v1/auth/login/mfa', json={
            'mfa_token': session['mfa_token'], 'code': code_at(secret, current_step(time.time()))})
        assert response.status_code == 200, 'Restored MFA login failed'
        session = response.json()
    headers = {'Authorization': 'Bearer ' + session['access_token']}
    response = client.get('/api/v1/findings', headers=headers)
    assert response.status_code == 200, 'Restored inventory is inaccessible'
    print('Restored application readiness, MFA decryption/login and inventory passed')
"""


def deploy(env, upgrade, archive, keyfile):
    preflight(env)
    if upgrade and (not archive or not keyfile):
        raise ValueError('Upgrade requires --archive and --key-file for a verified recovery point')
    commands = compose(env)
    run(commands + ['pull'])
    if upgrade:
        print('Entering maintenance: pause external scanners and user writes before this command', flush=True)
        run(commands + ['stop', 'frontend', 'worker', 'backend'])
        # On any failure leave writes stopped; never guess at a schema rollback.
        backup(env, archive, keyfile)
        restore_drill(archive, keyfile)
    run(commands + ['up', '-d', '--no-build', '--wait', '--wait-timeout', '180'])
    smoke(config(env)['services']['backend']['environment']['PUBLIC_URL'])
    print('Deployment passed readiness and HTTPS smoke; verify login and integrations before resuming writes')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', default='.env.production')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init-env')
    deployment = commands.add_parser('deploy')
    deployment.add_argument('--upgrade', action='store_true')
    deployment.add_argument('--archive')
    deployment.add_argument('--key-file')
    check = commands.add_parser('preflight')
    check.add_argument('--allow-local-build', action='store_true', help='Staging/CI only')
    for command in ('backup', 'restore-drill'):
        sub = commands.add_parser(command)
        sub.add_argument('archive')
        sub.add_argument('--key-file', required=True)
        if command == 'restore-drill':
            sub.add_argument('--application-check', action='store_true')
    sub = commands.add_parser('smoke')
    sub.add_argument('url')
    args = parser.parse_args()
    if args.command == 'init-env':
        initialize(args.env_file)
    elif args.command == 'preflight':
        preflight(args.env_file, not args.allow_local_build)
    elif args.command == 'deploy':
        deploy(args.env_file, args.upgrade, args.archive, args.key_file)
    elif args.command == 'backup':
        backup(args.env_file, args.archive, args.key_file)
    elif args.command == 'restore-drill':
        restore_drill(args.archive, args.key_file, args.env_file, args.application_check)
    else:
        smoke(args.url)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
