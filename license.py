# license.py
import os
import sys
import uuid
import json
import base64
import hashlib
import subprocess
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# ============================================================
# PUBLIC KEY (safe to embed in the app).
# Replace this with the public key printed by keygen.py.
# The matching PRIVATE KEY stays on your machine — never ship it.
# ============================================================
PUBLIC_KEY_B64 = "87U3vPuQTif5YS4NZ/pPRGVErPaIfZXGOdMXCbUX2rQ="

# License file is stored next to the executable / app.py
def _base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

LICENSE_FILE = os.path.join(_base_dir(), 'license.key')


# ============================================================
# HARDWARE FINGERPRINT (stable per machine)
# ============================================================
def _run(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                      stdin=subprocess.DEVNULL, timeout=5)
        return out.decode(errors='ignore').strip()
    except Exception:
        return ''


def _cpu_id():
    """Stable CPU identifier on Windows."""
    out = _run('wmic cpu get ProcessorId')
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines[1] if len(lines) > 1 else ''


def _baseboard_serial():
    out = _run('wmic baseboard get SerialNumber')
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines[1] if len(lines) > 1 else ''


def _disk_serial():
    """Serial of the primary physical disk (C:)."""
    out = _run('wmic diskdrive where "Index=0" get SerialNumber')
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines[1] if len(lines) > 1 else ''


def _mac_address():
    """MAC of the first physical adapter (ignore virtual ones)."""
    try:
        return str(uuid.getnode())
    except Exception:
        return ''


def hardware_serial() -> str:
    """Return a short human-readable serial like A1B2-C3D4-E5F6-7890."""
    parts = [
        _cpu_id(),
        _baseboard_serial(),
        _disk_serial(),
        _mac_address(),
    ]
    raw = '|'.join(parts)
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest().upper()
    # Format as XXXX-XXXX-XXXX-XXXX (16 hex chars = 64 bits, plenty unique)
    short = digest[:16]
    return '-'.join(short[i:i+4] for i in range(0, 16, 4))


# ============================================================
# LICENSE VERIFICATION
# ============================================================
def _load_public_key():
    try:
        raw = base64.b64decode(PUBLIC_KEY_B64)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def _read_license():
    if not os.path.isfile(LICENSE_FILE):
        return None
    try:
        with open(LICENSE_FILE, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except Exception:
        return None


def _parse_license(text: str):
    """
    License format (base64 of JSON) + '.' + (base64 of signature)
    Example:
        eyJzZXJpYWwiOiAuLi4sImV4cGlyZXMiOiIyMDI3LTEyLTMxIn0=.MEUCIQ...
    """
    if not text or '.' not in text:
        return None, None
    payload_b64, sig_b64 = text.rsplit('.', 1)
    try:
        payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))
        sig = base64.b64decode(sig_b64)
        return payload, sig
    except Exception:
        return None, None


def verify_license():
    """
    Returns (ok: bool, message: str, info: dict)
    Call this on startup. Refuse to run if not ok.
    """
    pub = _load_public_key()
    if pub is None:
        return False, 'المفتاح العام غير مُهيّأ (راجع المبرمج)', {}

    text = _read_license()
    if not text:
        return False, f'ملف الترخيص غير موجود: {LICENSE_FILE}', {'serial': hardware_serial()}

    payload, sig = _parse_license(text)
    if payload is None:
        return False, 'صيغة ملف الترخيص غير صحيحة', {'serial': hardware_serial()}

    # 1) verify signature — يُوقَّع keygen.py على نص الـ payload_b64 نفسه، لذا نتحقق من نفس النص
    try:
        pub.verify(sig, text.rsplit('.', 1)[0].encode('utf-8'))
    except Exception:
        return False, 'التوقيع الرقمي غير صحيح (ملف معدَّل؟)', {'serial': hardware_serial()}

    # 2) verify machine serial
    machine_serial = hardware_serial()
    if str(payload.get('serial', '')).upper() != machine_serial.upper():
        return False, 'الترخيص لا يخص هذا الجهاز', {
            'serial': machine_serial,
            'licensed_serial': payload.get('serial', ''),
        }

    # 3) expiry
    expires = payload.get('expires', '')
    if expires:
        try:
            exp = datetime.strptime(expires, '%Y-%m-%d')
            if datetime.now() > exp:
                return False, f'انتهت صلاحية الترخيص في {expires}', payload
        except Exception:
            return False, 'تاريخ الانتهاء في الترخيص غير صالح', payload

    # 4) optional limits
    max_users = int(payload.get('max_users', 0) or 0)
    info = {
        'serial': machine_serial,
        'customer': payload.get('customer', ''),
        'expires': expires or 'دائم',
        'max_users': max_users,
    }
    return True, 'الترخيص سليم', info


def license_summary():
    """Convenience for a UI/route: returns (ok, message, info)."""
    return verify_license()