"""
auth_capture.py -- grab a full Umamusume API config off the running game.

Attaches to the live game with Frida, hooks the Unity TLS write, and reads ONE
outgoing request: the wire header yields viewer_id / udid / auth_key /
app_ver / res_ver, and decrypting the body yields steam_id /
steam_session_ticket / device fields. That complete config lets the headless
client (uma_client.UmaClient) talk to the server with the game closed.

Same technique as the Icarus career bot (main.py JS_CODE).
"""
import json
import os
import queue
import threading
import time

import frida
import msgpack

PROCESS_NAME = "UmamusumePrettyDerby.exe"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "follower_data", "account.json")

JS_CODE = r"""
'use strict';
(function() {
    var buffers = {};
    var attached = {};
    function hex2(n) { return ('0' + (n & 255).toString(16)).slice(-2); }
    function uuidFromHex(h) {
        return h.substring(0, 8) + '-' + h.substring(8, 12) + '-' + h.substring(12, 16) + '-' + h.substring(16, 20) + '-' + h.substring(20);
    }
    function b64(s) {
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        var out = []; var buffer = 0; var bits = 0;
        for (var i = 0; i < s.length; i++) {
            var c = s.charAt(i);
            if (c === '=') break;
            var idx = chars.indexOf(c);
            if (idx < 0) continue;
            buffer = (buffer << 6) | idx; bits += 6;
            if (bits >= 8) { bits -= 8; out.push((buffer >> bits) & 255); }
        }
        return out;
    }
    var wireDiag = 0;
    function parseWire(endpoint, viewerId, body, appVer, resVer) {
        var decoded = b64(body);
        var dbg = wireDiag < 3;
        if (decoded.length < 140) { if(dbg){wireDiag++; send({type:'diag', msg:'wire '+endpoint+' REJECT declen='+decoded.length+' (<140)'});} return; }
        var headerLen = decoded[0] | (decoded[1] << 8) | (decoded[2] << 16) | (decoded[3] << 24);
        var blob1End = 4 + headerLen;
        if (dbg) { wireDiag++; send({type:'diag', msg:'wire '+endpoint+' declen='+decoded.length+' hlen='+headerLen+' blob1End='+blob1End}); }
        if (headerLen < 120 || headerLen > 2048 || decoded.length < blob1End) return;
        var udidHex = '';
        for (var i = blob1End - 96; i < blob1End - 80; i++) udidHex += hex2(decoded[i]);
        var authHex = '';
        for (var j = blob1End - 48; j < blob1End; j++) authHex += hex2(decoded[j]);
        if (dbg) send({type:'diag', msg:'wire '+endpoint+' authlen='+authHex.length+' udidlen='+udidHex.length});
        if (!viewerId || !authHex || authHex.length < 64 || udidHex.length !== 32) return;
        send({
            type: 'creds', endpoint: endpoint, viewer_id: parseInt(viewerId, 10),
            udid: uuidFromHex(udidHex), auth_key: authHex, auth_key_len: authHex.length / 2,
            app_ver: appVer, res_ver: resVer, body: body
        });
    }
    function parseHttp(text) {
        if (text.indexOf('/umamusume/') < 0) return;
        var em = text.match(/POST\s+\/umamusume\/([^\s]+)\s+HTTP/i);
        var vm = text.match(/(?:^|\r\n)(?:ViewerID|ViewerId):\s*(\d+)/i);
        var appVer = text.match(/(?:^|\r\n)APP-VER:\s*([^\r\n]+)/i);
        var resVer = text.match(/(?:^|\r\n)RES-VER:\s*([^\r\n]+)/i);
        var idx = text.indexOf('\r\n\r\n');
        if (!em) return;
        send({type:'diag', msg:'saw request ' + (em?em[1]:'?') + ' vid=' + (vm?vm[1]:'-') + ' appver=' + (appVer?'y':'n')});
        if (!vm || idx < 0) return;
        parseWire(em[1], vm[1], text.substring(idx + 4), appVer ? appVer[1].trim() : '', resVer ? resVer[1].trim() : '');
    }
    function parseChunk(key, chunk) {
        var buf = (buffers[key] || '') + chunk;
        if (buf.length > 2097152) buf = buf.substring(buf.length - 1048576);
        var start = buf.indexOf('POST ');
        if (start < 0) { buffers[key] = buf.slice(-4096); return; }
        if (start > 0) buf = buf.substring(start);
        var headerEnd = buf.indexOf('\r\n\r\n');
        if (headerEnd < 0) { buffers[key] = buf; return; }
        var headers = buf.substring(0, headerEnd);
        var lm = headers.match(/Content-Length:\s*(\d+)/i);
        var length = lm ? parseInt(lm[1], 10) : 0;
        var total = headerEnd + 4 + length;
        if (length > 0 && buf.length < total) { buffers[key] = buf; return; }
        parseHttp(length > 0 ? buf.substring(0, total) : buf);
        buffers[key] = buf.length > total ? buf.substring(total) : '';
    }
    function hookTls() {
        var ga = Process.findModuleByName('GameAssembly.dll');
        if (!ga) return false;
        var installFn = ga.findExportByName('il2cpp_unity_install_unitytls_interface');
        if (!installFn) return false;
        var rb = new Uint8Array(installFn.readByteArray(16));
        var realFn = installFn;
        if (rb[0] === 0xe9) {
            var off = rb[1] | (rb[2] << 8) | (rb[3] << 16) | (rb[4] << 24);
            if (off > 0x7fffffff) off -= 0x100000000;
            realFn = installFn.add(5 + off);
            rb = new Uint8Array(realFn.readByteArray(16));
        }
        var globalPtr = null;
        if (rb[0] === 0x48 && rb[1] === 0x89 && rb[2] === 0x0d) {
            var disp = rb[3] | (rb[4] << 8) | (rb[5] << 16) | (rb[6] << 24);
            if (disp > 0x7fffffff) disp -= 0x100000000;
            globalPtr = realFn.add(7 + disp);
        }
        if (!globalPtr) return false;
        var iface = globalPtr.readPointer();
        if (!iface || iface.isNull()) return false;
        var hookedTls = 0;
        [0xd0, 0xd8, 0xe0, 0xe8].forEach(function(off) {
            var addr = iface.add(off).readPointer();
            if (!addr || addr.isNull()) return;
            var key = 'tls_' + addr.toString();
            if (attached[key]) return;
            try {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        var len = args[2].toInt32();
                        if (len <= 0 || len > 1048576 || args[1].isNull()) return;
                        try {
                            var bytes = args[1].readByteArray(len);
                            var u8 = new Uint8Array(bytes);
                            var s = '';
                            for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
                            parseChunk(args[0].toString(), s);
                        } catch (e) {}
                    }
                });
                attached[key] = true; hookedTls++;
            } catch (e) {}
        });
        if (hookedTls > 0) send({type:'diag', msg:'TLS hooked (' + hookedTls + ' fn)'});
        return hookedTls > 0;
    }
    var tlsDone = false;
    var timer = setInterval(function() {
        try { if (!tlsDone) tlsDone = hookTls(); if (tlsDone) clearInterval(timer); } catch (e) {}
    }, 1000);
})();

// --- second hook: read the PLAINTEXT request body (Gallop.HttpHelper.CompressRequest)
// to lift steam_id / steam_session_ticket / device fields, which are NOT in the
// (encrypted) TLS header and can't be decrypted from the request wire.
(function() {
    var ga = Process.findModuleByName('GameAssembly.dll');
    if (!ga) return;
    function NF(n,r,a){ var e=ga.findExportByName(n); return e?new NativeFunction(e,r,a):null; }
    var dg=NF('il2cpp_domain_get','pointer',[]);
    var gas=NF('il2cpp_domain_get_assemblies','pointer',['pointer','pointer']);
    var aimg=NF('il2cpp_assembly_get_image','pointer',['pointer']);
    var cfn=NF('il2cpp_class_from_name','pointer',['pointer','pointer','pointer']);
    var cmfn=NF('il2cpp_class_get_method_from_name','pointer',['pointer','pointer','int']);
    var alen=NF('il2cpp_array_length','uint',['pointer']);
    var aae=ga.findExportByName('il2cpp_array_addr_with_size');
    var aad=aae?new NativeFunction(aae,'pointer',['pointer','int','uint']):null;
    if(!dg) return;
    var dom=dg(); var so=Memory.alloc(4); var asm=gas(dom,so); var n=so.readU32();
    function findClass(ns,cn){
        var nsp=Memory.allocUtf8String(ns); var cnp=Memory.allocUtf8String(cn);
        for(var i=0;i<n;i++){ var img=aimg(asm.add(i*Process.pointerSize).readPointer());
            var k=cfn(img,nsp,cnp); if(!k.isNull()) return k; }
        return null;
    }
    function readArr(arr){ var l=alen(arr); if(l<=0||l>50000000) return null;
        var d=aad?aad(arr,1,0):arr.add(0x20); return d.readByteArray(l); }
    var hh=findClass('Gallop','HttpHelper');
    if(hh){
        var cm=cmfn(hh,Memory.allocUtf8String('CompressRequest'),1);
        if(cm && !cm.isNull()){
            Interceptor.attach(cm.readPointer(),{ onEnter:function(a){
                var d=null; try{ d=readArr(a[0]); }catch(e){}
                if(!d){ try{ d=readArr(a[1]); }catch(e){} }
                if(d) send({type:'reqbody'}, d);
            }});
            send({type:'diag', msg:'CompressRequest hooked (plaintext body)'});
        }
    }
})();
"""

CONFIG_KEYS = ("viewer_id", "udid", "auth_key", "app_ver", "res_ver",
               "device_id", "device_name", "graphics_device_name",
               "ip_address", "platform_os_version", "locale",
               "steam_id", "steam_session_ticket")


BODY_KEYS = ("viewer_id", "steam_id", "steam_session_ticket", "device_id",
             "device_name", "graphics_device_name", "ip_address",
             "platform_os_version", "locale")


def _decode_req(raw):
    raw = bytes(raw)
    try:
        return msgpack.unpackb(raw, raw=False, strict_map_key=False)
    except Exception:
        pass
    if len(raw) >= 4:
        L = int.from_bytes(raw[:4], "little")
        hs = 4 + L
        if 0 < hs < len(raw):
            try:
                return msgpack.unpackb(raw[hs:], raw=False, strict_map_key=False)
            except Exception:
                pass
    return None


def capture(timeout=180, log=print):
    """Attach to the running game and capture a full API config. Combines the
    TLS-header fields (udid/auth_key/app_ver/res_ver) with the plaintext-body
    fields (steam ticket + device info). Returns the cfg dict, or raises."""
    log(f"Attaching to {PROCESS_NAME} …")
    session = frida.attach(PROCESS_NAME)
    q = queue.Queue()
    creds = {}        # from the TLS header
    body = {}         # from the CompressRequest plaintext

    def on_message(message, data):
        if message.get("type") == "error":
            log("frida error: " + str(message.get("description")))
            return
        p = message.get("payload") or {}
        t = p.get("type")
        if t == "diag":
            log("· " + str(p.get("msg")))
            return
        if t == "reqbody" and data is not None:
            dec = _decode_req(data)
            if isinstance(dec, dict):
                for k in BODY_KEYS:
                    if dec.get(k) is not None:
                        body[k] = dec[k]
                q.put("body")
            return
        if t == "creds" and p.get("app_ver") and p.get("res_ver"):
            for k in ("viewer_id", "udid", "auth_key", "app_ver", "res_ver"):
                if p.get(k) is not None:
                    creds[k] = p[k]
            q.put("creds")

    script = session.create_script(JS_CODE)
    script.on("message", on_message)
    script.load()
    log("Hooked. Navigate the game menus so it makes a request "
        "(the home screen / tapping around is enough)…")

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            q.get(timeout=1.0)
        except queue.Empty:
            continue
        if creds.get("auth_key") and creds.get("udid") \
                and body.get("steam_session_ticket"):
            break

    try:
        session.detach()
    except Exception:
        pass
    if not (creds.get("auth_key") and creds.get("udid")):
        raise RuntimeError("Could not capture auth header (udid/auth_key). Make sure "
                           "the game is at the home menu and tap around.")
    if not body.get("steam_session_ticket"):
        raise RuntimeError("Captured auth header but no request body (steam ticket). "
                           "Tap around a bit more so a request is sent.")
    cfg = {**body, **creds}   # creds (udid/auth_key/app_ver/res_ver/viewer_id) win
    log(f"Captured viewer_id {cfg.get('viewer_id')} (APP-VER {cfg.get('app_ver')}, "
        f"RES-VER {cfg.get('res_ver')}).")
    return cfg


def save_config(cfg, path=CONFIG_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def load_config(path=CONFIG_PATH):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


if __name__ == "__main__":
    c = capture()
    save_config(c)
    print("saved account.json:", {k: ("<set>" if c.get(k) else "") for k in CONFIG_KEYS})
