# keygen.py — keep this on your machine only
import base64
import json
import os
import sys
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

PRIV_FILE = 'private_key.pem'
PUB_FILE  = 'public_key.txt'


def _load_or_create_keys():
    if os.path.isfile(PRIV_FILE) and os.path.isfile(PUB_FILE):
        with open(PRIV_FILE, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUB_FILE, 'r') as f:
            pub_b64 = f.read().strip()
        return priv, pub_b64

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(PRIV_FILE, 'wb') as f:
        f.write(priv_pem)

    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode('ascii')
    with open(PUB_FILE, 'w') as f:
        f.write(pub_b64)

    print('=== NEW KEYPAIR GENERATED ===')
    print('PRIVATE KEY saved to:', PRIV_FILE)
    print('PUBLIC  KEY saved to:', PUB_FILE)
    print('Embed this PUBLIC KEY in license.py as PUBLIC_KEY_B64:')
    print(pub_b64)
    print('=' * 40)
    return priv, pub_b64


def make_license(serial: str, customer: str = '', days: int = 365, max_users: int = 0) -> str:
    """
    serial   : the hardware serial shown by license.hardware_serial()
    customer : free-text label (company name)
    days     : validity in days from today; 0 = never expires
    max_users: optional cap; 0 = unlimited
    """
    priv, _ = _load_or_create_keys()

    expires = ''
    if days and days > 0:
        expires = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')

    payload = {
        'serial': serial.strip().upper(),
        'customer': customer,
        'expires': expires,
        'max_users': int(max_users),
        'issued': datetime.now().strftime('%Y-%m-%d'),
    }
    payload_bytes = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    payload_b64 = base64.b64encode(payload_bytes)
    sig = priv.sign(payload_b64)
    sig_b64 = base64.b64encode(sig)
    return payload_b64.decode('ascii') + '.' + sig_b64.decode('ascii')


def main():
    _load_or_create_keys()
    print()
    print('--- License Generator ---')
    serial = input('Hardware serial (from customer app): ').strip()
    customer = input('Customer name (optional): ').strip()
    days = input('Validity days (0 = permanent) [365]: ').strip() or '365'
    max_users = input('Max users (0 = unlimited) [0]: ').strip() or '0'
    try:
        days = int(days)
        max_users = int(max_users)
    except ValueError:
        print('Invalid number'); sys.exit(1)

    key = make_license(serial, customer, days, max_users)
    print()
    print('=== LICENSE KEY (give this to the customer) ===')
    print(key)
    print('=' * 48)
    # Save to a file for convenience
    out = f'license_{serial[:8]}.key'
    with open(out, 'w', encoding='utf-8') as f:
        f.write(key)
    print('Saved to:', out)


if __name__ == '__main__':
    main()