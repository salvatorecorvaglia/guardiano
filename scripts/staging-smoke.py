#!/usr/bin/env python3
"""Destructive smoke for a fresh, disposable staging stack only; enrolls admin MFA."""
import argparse
import base64
import hashlib
import hmac
import json
import struct
import time
import urllib.error
import urllib.request
import uuid

from production import ROOT, config, smoke


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', required=True)
    parser.add_argument('--url', required=True)
    parser.add_argument('--disposable-staging', action='store_true', required=True)
    args = parser.parse_args()
    values = config(args.env_file)['services']['backend']['environment']
    smoke(args.url)
    token = ''

    def request(path, body=None, content_type='application/json', method=None, expected=200):
        data = json.dumps(body).encode() if isinstance(body, dict) else body
        headers = {'Content-Type': content_type}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(args.url + '/api/v1' + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                assert response.status == expected, (path, response.status)
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            if error.code == expected:
                return None
            raise RuntimeError(f'{path}: expected {expected}, got {error.code}') from None

    session = request('/auth/login', {'email': values['GUARDIANO_ADMIN_EMAIL'],
                                      'password': values['GUARDIANO_ADMIN_PASSWORD']})
    token = session['access_token']
    assert session['user']['mfa_enrollment_required']
    request('/assets', expected=403)
    setup = request('/auth/mfa/setup', {})
    secret = base64.b32decode(setup['secret'] + '=' * (-len(setup['secret']) % 8))
    digest = hmac.new(secret, struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    code = str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
    enrolled = request('/auth/mfa/enable', {'code': code})
    token = enrolled['session']['access_token']
    credential = request('/tokens', {'name': 'staging-smoke', 'scopes': ['ingest'], 'expires_in_days': 1},
                         expected=201)
    session_token = token
    token = credential['token']
    boundary = uuid.uuid4().hex
    fields = {'asset_name': 'production-smoke', 'branch': 'main', 'close_missing': 'true'}
    payload = b''
    for key, value in fields.items():
        payload += f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
    payload += (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="smoke.sarif"\r\n'
                'Content-Type: application/json\r\n\r\n').encode()
    payload += (ROOT / 'backend/tests/fixtures/reports/semgrep.sarif').read_bytes()
    payload += f'\r\n--{boundary}--\r\n'.encode()
    request('/scans', payload, 'multipart/form-data; boundary=' + boundary, expected=201)
    token = session_token
    inventory = request('/findings')
    assert inventory['total'] > 0
    request('/tokens/' + str(credential['id']), method='DELETE', expected=204)
    token = credential['token']
    request('/scans', payload, 'multipart/form-data; boundary=' + boundary, expected=401)
    print('MFA enforcement/enrollment, token scope, SARIF ingestion, inventory and revocation passed')


if __name__ == '__main__':
    main()
