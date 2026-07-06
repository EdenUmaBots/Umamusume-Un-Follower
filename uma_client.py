"""
uma_client.py -- headless Umamusume API client for the Icarus Un-follower.

Talks directly to the live Cygames server (game can be closed after auth is
captured). The request crypto/framing + session (sid) handling is the SAME
protocol the Icarus career bot uses -- msgpack -> AES-CBC -> HEAD/sid/udid
framing -> base64, with the sid rotating on every response.

Only the friend endpoints are exposed here (index + un_follower); everything
else is the shared transport (`call`) + login.
"""
import base64
import hashlib
import os
import random
import struct
import time

import msgpack
from curl_cffi import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BASE_URL = "https://api.games.umamusume.com/umamusume/"
SALT = b"co!=Y;(UQCGxJ_n82"
HEAD = bytes.fromhex(
    "6b20e2ab6c311330f761d737ce3f3025750850665eea58b6372f8d2f57501eb3"
    "44bdb7270a9067f5b63cd61f152cfb986cbfbf7a"
)


# --- request crypto / session (identical scheme to the reference client) ----
def sm5(data):
    h = hashlib.md5()
    h.update(data)
    h.update(SALT)
    return h.digest()


def make_sid(vid, udid):
    return sm5((str(vid) + udid).encode())


def next_sid(sid):
    return sm5(sid.encode())


def gen_key():
    out = b""
    while len(out) < 32:
        out += format(random.randint(0, 65535), "x").encode()
    return out[:32]


def get_iv(udid):
    return udid.replace("-", "").lower()[:16].encode()


def get_raw_udid(udid):
    return bytes.fromhex(udid.replace("-", "").lower())


def pack(sid, udid_raw, auth, payload, udid):
    key = gen_key()
    p = msgpack.packb(payload, use_bin_type=True)
    body = AES.new(key, AES.MODE_CBC, get_iv(udid)).encrypt(
        pad(struct.pack("<I", len(p)) + p, 16)) + key
    h = HEAD + sid + udid_raw + os.urandom(32)
    if auth:
        h += auth
    return base64.b64encode(struct.pack("<I", len(h)) + h + body)


def unpack(text, udid):
    raw = base64.b64decode(text)
    key, cipher = raw[-32:], raw[:-32]
    p = unpad(AES.new(key, AES.MODE_CBC, get_iv(udid)).decrypt(cipher), 16)
    return msgpack.unpackb(p[4:4 + struct.unpack("<I", p[:4])[0]],
                           raw=False, strict_map_key=False)


class ApiError(Exception):
    def __init__(self, code, ep, detail=""):
        self.code = code
        self.ep = ep
        super().__init__(f"API error {code} on {ep}{(': ' + detail) if detail else ''}")


class UmaClient:
    def __init__(self, cfg):
        self.viewer_id = cfg.get("viewer_id", 0)
        self.udid_str = cfg.get("udid", "")
        self.auth_key_hex = cfg.get("auth_key", "")
        self.steam_id = str(cfg.get("steam_id", ""))
        self.steam_ticket = cfg.get("steam_session_ticket", "")
        self.device_id = cfg.get("device_id", "")
        self.device_name = cfg.get("device_name", "")
        self.graphics_device = cfg.get("graphics_device_name", "")
        self.ip_address = cfg.get("ip_address", "")
        self.platform_os = cfg.get("platform_os_version", "")
        self.locale = cfg.get("locale", "JPN")
        self.unity_ver = cfg.get("unity_ver", "2022.3.62f2")
        self.app_ver = cfg.get("app_ver", "")
        self.res_ver = cfg.get("res_ver", "")

        self.sid = bytes(16)
        self.last_servertime = None
        self.session = requests.Session()
        self.update_headers()
        self._last_call_ts = 0.0

    # -- helpers --
    def auth_bytes(self):
        if not self.auth_key_hex:
            return b""
        return bytes.fromhex(self.auth_key_hex)

    def has_auth(self):
        try:
            int(self.viewer_id)
            bytes.fromhex(str(self.auth_key_hex))
        except (TypeError, ValueError):
            return False
        return bool(self.viewer_id and self.udid_str and self.auth_key_hex)

    def common(self):
        return {
            "viewer_id": self.viewer_id, "device": 4, "device_id": self.device_id,
            "device_name": self.device_name, "graphics_device_name": self.graphics_device,
            "ip_address": self.ip_address, "platform_os_version": self.platform_os,
            "carrier": "", "keychain": 0, "locale": self.locale,
            "button_info": "", "dmm_viewer_id": None, "dmm_onetime_token": None,
            "steam_id": self.steam_id, "steam_session_ticket": self.steam_ticket,
        }

    def update_headers(self):
        self.session.headers.update({
            "User-Agent": f"UnityPlayer/{self.unity_ver} (UnityWebRequest/1.0, libcurl/8.10.1-DEV)",
            "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
            "Content-Type": "application/x-msgpack", "X-Unity-Version": self.unity_ver,
        })

    def regen_sid(self):
        self.sid = make_sid(self.viewer_id, self.udid_str)

    # -- transport --
    def call(self, ep, args=None, timeout=30, retry_net=6, retry_res=2,
             retry_208=6, retry_205=3, log=None):
        el = time.time() - self._last_call_ts
        if el < 0.14:
            time.sleep(0.14 - el)
        self._last_call_ts = time.time()

        payload = dict(args or {})
        payload.update(self.common())

        for attempt in range(max(1, retry_net)):
            body = pack(self.sid, get_raw_udid(self.udid_str), self.auth_bytes(),
                        payload, self.udid_str)
            headers = {
                "SID": self.sid.hex(), "Device": "4", "ViewerID": str(self.viewer_id),
                "APP-VER": self.app_ver, "RES-VER": self.res_ver,
            }
            try:
                resp = self.session.post(BASE_URL + ep, data=body, headers=headers, timeout=timeout)
            except Exception as e:
                if attempt < retry_net - 1:
                    time.sleep(min(15.0, 1.0 * (2 ** attempt)) + random.uniform(0, 0.5))
                    continue
                raise ApiError("net", ep, str(e))
            if 500 <= resp.status_code < 600 and attempt < retry_net - 1:
                time.sleep(min(15.0, 1.0 * (2 ** attempt)) + random.uniform(0, 0.5))
                continue
            break

        if resp.status_code != 200:
            raise ApiError(f"HTTP{resp.status_code}", ep, (resp.text or "")[:200])

        res = unpack(resp.text.strip(), self.udid_str)
        dh = res.get("data_headers", {}) or {}
        rc = dh.get("result_code", 0)
        if dh.get("servertime"):
            try:
                self.last_servertime = int(dh["servertime"])
            except (TypeError, ValueError):
                pass

        data = res.get("data", {})
        if isinstance(data, dict):
            srv = data.get("res_version")
            if srv and str(srv) != str(self.res_ver):
                self.res_ver = str(srv)

        # rotate sid on EVERY response (success or error) -- the server issues the
        # next sid in data_headers; not advancing after an error 217-cascades.
        if isinstance(dh.get("sid"), str) and dh["sid"].strip():
            self.sid = next_sid(dh["sid"])

        if rc == 214 and retry_res > 0:
            server_res = str(dh.get("resource_version") or (data or {}).get("resource_version") or "")
            if server_res and server_res != str(self.res_ver):
                if log:
                    log(f"[RES-VER] {self.res_ver} -> {server_res} after 214; retrying")
                self.res_ver = server_res
                return self.call(ep, args, timeout=timeout, retry_net=retry_net,
                                 retry_res=retry_res - 1, retry_208=retry_208, retry_205=retry_205, log=log)
        if rc != 1:
            if rc == 205 and retry_205 > 0:
                time.sleep(random.uniform(0.3, 0.7))
                return self.call(ep, args, timeout=timeout, retry_net=retry_net,
                                 retry_res=retry_res, retry_208=retry_208, retry_205=retry_205 - 1, log=log)
            if rc == 208 and retry_208 > 0:
                attempt = max(0, 6 - retry_208)
                time.sleep(min(15.0, 1.0 * (2 ** attempt)) + random.uniform(0, 0.5))
                return self.call(ep, args, timeout=timeout, retry_net=retry_net,
                                 retry_res=retry_res, retry_208=retry_208 - 1, retry_205=retry_205, log=log)
            if rc == 102 and ep == "read_info/index":
                return res
            raise ApiError(rc, ep, _err_detail(res))
        return res

    def login(self, log=None):
        if not self.has_auth():
            raise ApiError("no-auth", "login", "missing viewer_id/udid/auth_key")
        self.regen_sid()
        self.session.close()
        self.session = requests.Session()
        self.update_headers()
        if log:
            log(f"login: APP-VER={self.app_ver or '?'} RES-VER={self.res_ver or '?'}")
        self.call("tool/start_session", {"attestation_type": 0, "device_token": None}, log=log)
        res = self.call("load/index", {"adid": ""}, log=log)
        return res

    # -- friend endpoints --
    def friend_index(self, log=None):
        """Fetch the friend screen data (follower/follow/recommend lists)."""
        return self.call("friend/index", {}, log=log)

    def un_follower(self, friend_viewer_id, log=None):
        """Remove ONE follower (the un_follower action the Remove Follower button does)."""
        return self.call("friend/un_follower", {"friend_viewer_id": int(friend_viewer_id)}, log=log)


def _err_detail(res):
    data = res.get("data")
    if isinstance(data, dict):
        for k in ("error_code", "error_message", "message"):
            if k in data:
                return f"{k}={data[k]}"
    dh = res.get("data_headers") or {}
    return f"result_code={dh.get('result_code')}"
