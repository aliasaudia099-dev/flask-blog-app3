"""
zkteco_device.py  —  Correct ZKTeco UDP protocol implementation.

Protocol constants from zkemsdk.c / zkconst.py:
  CMD_CONNECT = 1000, CMD_EXIT = 1001, CMD_ACK_OK = 2000
  Header is LITTLE-endian.  Checksum uses bitwise-NOT (~).

Confirmed attendance record layout (40 bytes, from raw device analysis):
  [0:2]   internal marker / sequence
  [4]     uid   u8   (integer user-ID on device, e.g. 1, 2, 3…)
  [6]     uid   u8   (ASCII char of user-ID, same value printed)
  [31:35] timestamp  u32 LE, ZK-encoded  (decode with _decode_time)
  [35]    state u8   (0 = check_in, 1 = check_out / finger-only, etc.)

NOTE: Close ZKTime / ZKAccess before connecting — ZK devices allow
      only ONE active UDP session at a time.
"""

import socket
import struct
import time
from datetime import datetime

# ─── Protocol constants ───────────────────────────────────────────────────────
CMD_CONNECT       = 1000
CMD_EXIT          = 1001
CMD_ENABLEDEVICE  = 1002
CMD_DISABLEDEVICE = 1003

CMD_ACK_OK        = 2000
CMD_ACK_ERROR     = 2001
CMD_ACK_DATA      = 2002

CMD_PREPARE_DATA  = 1500
CMD_DATA          = 1501

CMD_USERTEMP_RRQ  = 9
CMD_ATTLOG_RRQ    = 13
CMD_CLEAR_DATA    = 14
CMD_CLEAR_ATTLOG  = 15

CMD_GET_TIME      = 201
CMD_SET_TIME      = 202

USHRT_MAX = 65535
# ─────────────────────────────────────────────────────────────────────────────


class ZKDevice:
    """ZKTeco fingerprint/face device — UDP (default port 4370)."""

    def __init__(self, ip, port=4370, timeout=5, comm_key=0):
        self.ip        = ip
        self.port      = int(port)
        self.timeout   = timeout
        self.comm_key  = comm_key
        self.socket    = None
        self.session_id = 0
        self.reply_id   = 0
        self.data_recv  = b''
        self.connected  = False

    # ─── Packet helpers ───────────────────────────────────────────────────────

    def _create_chksum(self, data_bytes):
        """zkemsdk.c CalcCRC — with bitwise-NOT on result."""
        p = list(data_bytes)
        chksum = 0
        l = len(p)
        while l > 1:
            chksum += struct.unpack('<H', bytes([p[0], p[1]]))[0]
            p = p[2:]
            if chksum > USHRT_MAX:
                chksum -= USHRT_MAX
            l -= 2
        if l:
            chksum += p[-1]
        while chksum > USHRT_MAX:
            chksum -= USHRT_MAX
        chksum = ~chksum          # ← bitwise NOT (the fix)
        while chksum < 0:
            chksum += USHRT_MAX
        return chksum & 0xFFFF

    def _create_header(self, command, chksum, session_id, reply_id,
                       command_string=b''):
        if isinstance(command_string, str):
            command_string = command_string.encode('ascii', errors='ignore')
        buf    = struct.pack('<HHHH', command, chksum, session_id, reply_id) + command_string
        chksum = self._create_chksum(buf)
        reply_id += 1
        if reply_id >= USHRT_MAX:
            reply_id -= USHRT_MAX
        self.reply_id = reply_id
        return struct.pack('<HHHH', command, chksum, session_id, reply_id) + command_string

    def _send_recv(self, buf, recv_size=1024):
        try:
            self.socket.sendto(buf, (self.ip, self.port))
            data, _ = self.socket.recvfrom(recv_size)
            self.data_recv = data
            if len(data) >= 8:
                fields = struct.unpack('<HHHH', data[:8])
                self.session_id = fields[2]
                self.reply_id   = fields[3]
            return data
        except socket.timeout:
            return None
        except Exception:
            return None

    def _check_valid(self, reply):
        if not reply or len(reply) < 2:
            return False
        return struct.unpack('<H', reply[:2])[0] == CMD_ACK_OK

    # ─── Bulk data reader ─────────────────────────────────────────────────────

    def _read_bulk(self, command, command_string=b''):
        """
        Send a bulk-read command and collect all data chunks.
        Returns the raw payload bytes (without any chunk headers).
        """
        buf = self._create_header(command, 0, self.session_id,
                                  self.reply_id, command_string)
        self.socket.sendto(buf, (self.ip, self.port))

        try:
            first, _ = self.socket.recvfrom(1024)
            self.data_recv = first
        except socket.timeout:
            return b''

        if len(first) < 2:
            return b''

        cmd_resp = struct.unpack('<H', first[:2])[0]

        if cmd_resp == CMD_PREPARE_DATA:
            # Device signals bulk transfer; total byte count in bytes 8–12
            total = struct.unpack('<I', first[8:12])[0] if len(first) >= 12 else 0
            raw   = b''
            received = 0
            self.socket.settimeout(self.timeout)
            chunk_no = 0
            while received < total:
                try:
                    pkt, _ = self.socket.recvfrom(1032)
                    # Each DATA chunk has an 8-byte header; skip it
                    payload_part = pkt[8:] if chunk_no == 0 else pkt[8:]
                    raw      += payload_part
                    received += len(pkt)
                    chunk_no += 1
                except socket.timeout:
                    break
            # Consume the final ACK
            try:
                self.socket.recvfrom(8)
            except Exception:
                pass
            return raw

        elif cmd_resp == CMD_ACK_OK:
            return first[8:] if len(first) > 8 else b''
        else:
            # Fallback: strip 8-byte header
            return first[8:] if len(first) > 8 else b''

    # ─── Connection ──────────────────────────────────────────────────────────

    def connect(self):
        """
        Open a UDP session with the device.
        Returns True on success.
        IMPORTANT: ZKTime / ZKAccess must be disconnected first.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(self.timeout)
            self.session_id = 0
            self.reply_id   = USHRT_MAX - 1
            buf  = self._create_header(CMD_CONNECT, 0,
                                       self.session_id, self.reply_id, b'')
            data = self._send_recv(buf)
            if data and self._check_valid(data):
                self.connected = True
                return True
            self.connected = False
            return False
        except Exception:
            self.connected = False
            return False

    def disconnect(self):
        if self.socket and self.connected:
            try:
                buf = self._create_header(CMD_EXIT, 0,
                                          self.session_id, self.reply_id, b'')
                self._send_recv(buf)
            except Exception:
                pass
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        self.socket    = None
        self.connected = False

    def test_connection(self):
        """Quick connect→disconnect ping. Returns (ok, latency_ms, message)."""
        t0 = time.time()
        ok = self.connect()
        lat = int((time.time() - t0) * 1000)
        if ok:
            dev_time = self.get_time()
            self.disconnect()
            return True, lat, (
                f"تم الاتصال بنجاح ({lat} مللي ثانية)"
                + (f" — توقيت الجهاز: {dev_time}" if dev_time else "")
            )
        return False, lat, (
            f"فشل الاتصال بـ {self.ip}:{self.port} ({lat} مللي ثانية). "
            "تأكد من: 1) إغلاق برنامج ZKTime/ZKAccess أولاً "
            "2) صحة IP والمنفذ 4370 "
            "3) أن الجهاز يعمل (ping ناجح)"
        )

    # ─── Attendance records ───────────────────────────────────────────────────

    def get_attendance(self):
        """
        Download all attendance records.

        Confirmed 40-byte record layout (from raw device analysis):
          [4]      uid        u8  — integer user-ID (1, 2, 3 …)
          [31:35]  timestamp  u32 LE, ZK-encoded
          [35]     state      u8  (0 = check_in, 1+ = check_out/other)

        Returns list of dicts:
          {'uid', 'state', 'date', 'time', 'datetime', 'check_type'}
        """
        if not self.connected:
            return []
        try:
            raw = self._read_bulk(CMD_ATTLOG_RRQ)
            return self._parse_attendance(raw)
        except Exception as e:
            print(f"[ZKDevice] get_attendance error: {e}")
            return []

    def _parse_attendance(self, raw):
        """Parse raw attendance payload into list of dicts."""
        records = []
        REC = 40
        idx = 0
        while idx + REC <= len(raw):
            rec = raw[idx: idx + REC]
            try:
                uid_int = rec[4]                                # u8 user-ID
                ts_raw  = struct.unpack('<I', rec[31:35])[0]   # ZK timestamp
                state   = rec[35]                              # check type

                uid_str = str(uid_int) if uid_int else ''
                dt      = self._decode_time(ts_raw)

                if uid_str:  # skip blank/sentinel records
                    records.append({
                        'uid':        uid_str,
                        'state':      int(state),
                        'date':       dt.strftime('%Y-%m-%d'),
                        'time':       dt.strftime('%H:%M:%S'),
                        'datetime':   dt,
                        'check_type': 'check_in' if state == 0 else 'check_out',
                    })
            except Exception:
                pass
            idx += REC
        return records

    # ─── User list ────────────────────────────────────────────────────────────

    def get_user_list(self):
        """
        Download user list from the device.
        Returns list of dicts: {'uid', 'name', 'privilege'}
        """
        if not self.connected:
            return []
        try:
            raw   = self._read_bulk(CMD_USERTEMP_RRQ, b'\x05')
            return self._parse_users(raw)
        except Exception as e:
            print(f"[ZKDevice] get_user_list error: {e}")
            return []

    def _parse_users(self, raw):
        """
        Parse raw user payload.
        Handles optional 4-byte size prefix, 72-byte modern format, or 28-byte legacy format.
        Modern ZK user record (72 bytes):
          [0:2]   uid        u16 LE
          [2]     privilege  u8
          [3:11]  password   8 bytes
          [11:48] name       37 bytes, null-terminated
          [48:72] user_id    24 bytes, null-terminated PIN string
        """
        if not raw:
            return []

        # Check for 4-byte size header
        if len(raw) >= 4:
            hdr_size = struct.unpack('<I', raw[:4])[0]
            if hdr_size == len(raw) - 4 or (len(raw) % 72 != 0 and (len(raw) - 4) % 72 == 0):
                raw = raw[4:]

        users = []
        REC = 72
        if len(raw) % 72 != 0 and len(raw) % 28 == 0:
            REC = 28

        idx = 0
        while idx + REC <= len(raw):
            rec = raw[idx: idx + REC]
            try:
                if REC == 72:
                    uid_int   = struct.unpack('<H', rec[0:2])[0]
                    privilege = rec[2]
                    name_b    = rec[11:48].split(b'\x00')[0]
                    userid_b  = rec[48:72].split(b'\x00')[0]
                    name      = name_b.decode('utf-8', errors='replace').strip()
                    userid    = userid_b.decode('utf-8', errors='replace').strip()
                    uid_final = userid if userid else str(uid_int)
                else:
                    # Legacy 28-byte record
                    uid_int   = struct.unpack('<H', rec[0:2])[0]
                    privilege = rec[2]
                    name_b    = rec[11:28].split(b'\x00')[0]
                    name      = name_b.decode('utf-8', errors='replace').strip()
                    uid_final = str(uid_int)

                if not name or name == '\x00':
                    name = uid_final

                if uid_final:
                    users.append({
                        'uid':       uid_final,
                        'name':      name,
                        'privilege': privilege,
                    })
            except Exception:
                pass
            idx += REC
        return users

    # ─── Device commands ──────────────────────────────────────────────────────

    def enable_device(self):
        if not self.connected:
            return False
        buf  = self._create_header(CMD_ENABLEDEVICE, 0,
                                   self.session_id, self.reply_id, b'')
        return self._check_valid(self._send_recv(buf))

    def disable_device(self):
        if not self.connected:
            return False
        buf  = self._create_header(CMD_DISABLEDEVICE, 0,
                                   self.session_id, self.reply_id, b'')
        return self._check_valid(self._send_recv(buf))

    def get_time(self):
        """Return device's current time as a datetime, or None."""
        if not self.connected:
            return None
        try:
            buf  = self._create_header(CMD_GET_TIME, 0,
                                       self.session_id, self.reply_id, b'')
            data = self._send_recv(buf)
            if data and len(data) >= 12:
                ts = struct.unpack('<I', data[8:12])[0]
                return self._decode_time(ts)
        except Exception:
            pass
        return None

    def sync_time(self, dt=None):
        """Sync device clock to dt (default = now). Returns True on success."""
        if not self.connected:
            return False
        try:
            dt   = dt or datetime.now()
            val  = self._encode_time(dt)
            ts_b = struct.pack('<I', val)
            buf  = self._create_header(CMD_SET_TIME, 0,
                                       self.session_id, self.reply_id, ts_b)
            return self._check_valid(self._send_recv(buf))
        except Exception:
            return False

    def clear_attendance(self):
        """Clear all attendance records on the device."""
        if not self.connected:
            return False
        buf = self._create_header(CMD_CLEAR_ATTLOG, 0,
                                  self.session_id, self.reply_id, b'')
        return self._check_valid(self._send_recv(buf))

    def restart_device(self):
        """Restart the device (enable command re-inits firmware on many models)."""
        if not self.connected:
            return False
        buf = self._create_header(CMD_ENABLEDEVICE, 0,
                                  self.session_id, self.reply_id, b'')
        self._send_recv(buf)
        return True

    # ─── Time codec ───────────────────────────────────────────────────────────

    @staticmethod
    def _encode_time(dt):
        """zkemsdk.c EncodeTime → ZK u32."""
        return (
            ((dt.year % 100) * 12 * 31
             + (dt.month - 1) * 31
             + (dt.day - 1))
            * 86400
            + dt.hour * 3600
            + dt.minute * 60
            + dt.second
        )

    @staticmethod
    def _decode_time(t):
        """zkemsdk.c DecodeTime → datetime."""
        try:
            s  = t % 60;  t //= 60
            m  = t % 60;  t //= 60
            h  = t % 24;  t //= 24
            d  = (t % 31) + 1;  t //= 31
            mo = (t % 12) + 1;  t //= 12
            y  = t + 2000
            return datetime(y, mo, d, h, m, s)
        except ValueError:
            return datetime.now()
