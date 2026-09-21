import sys
sys.path.append("/")

import requests
from flask import Flask, request, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf import my_pb2

import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

app = Flask(__name__)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'


def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid, "password": password,
        "response_type": "token", "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    try:
        r = requests.post(url, headers=headers, data=data, verify=False, timeout=20)
    except requests.RequestException as e:
        return None, {"status": 0, "message": str(e)}
    if r.status_code == 200:
        try:
            return r.json(), None
        except ValueError:
            return None, {"status": r.status_code, "message": "Upstream returned non-JSON response"}
    return None, {"status": r.status_code, "message": r.text[:500]}


def encrypt_message(key, iv, plaintext):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))


def read_varint(buf, i):
    v, shift = 0, 0
    while i < len(buf):
        b = buf[i]; i += 1
        v |= (b & 0x7f) << shift
        if not (b & 0x80):
            return v, i
        shift += 7
        if shift > 63:
            return None, i
    return None, i


def parse_protobuf(buf):
    """Parse top-level protobuf fields. Returns dict."""
    result = {}
    i, n = 0, len(buf)
    while i < n:
        tag, i = read_varint(buf, i)
        if tag is None or tag == 0:
            break
        field_num = tag >> 3
        wire      = tag & 0x7

        if wire == 0:
            v, i = read_varint(buf, i)
            if v is None: break
            result[field_num] = v
        elif wire == 2:
            ln, i = read_varint(buf, i)
            if ln is None or i + ln > n:
                break
            val = buf[i:i + ln]
            i += ln
            try:
                s = val.decode("utf-8")
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in s):
                    result[field_num] = s
                else:
                    result[field_num] = val
            except UnicodeDecodeError:
                result[field_num] = val
        elif wire == 5:
            i += 4
        elif wire == 1:
            i += 8
        else:
            break
    return result


def find_protobuf_start(buf):
    """
    Scan the buffer for the first offset where a valid protobuf message begins.
    Looks for a sequence that parses cleanly until end of buffer.
    """
    for start in range(0, min(len(buf), 200)):
        parsed = parse_protobuf(buf[start:])
        # Heuristic: we expect at least 'EUROPE' region + a JWT-like long string
        has_region = any(isinstance(v, str) and v in ("EUROPE", "IND", "SGP", "BRA", "NA", "US", "IN")
                         for v in parsed.values())
        has_jwt = any(isinstance(v, str) and v.startswith("eyJ") for v in parsed.values())
        if has_region and has_jwt:
            return start, parsed
    return None, None


def process_token(uid, password):
    token_data, token_error = get_token(password, uid)
    if not token_data:
        if token_error:
            return {"error": f"OAuth HTTP {token_error.get('status')}: {token_error.get('message')}"}
        return {"error": "Failed to retrieve OAuth token"}

    g = my_pb2.GameData()
    g.timestamp          = "2024-12-05 18:15:32"
    g.game_name          = "free fire"
    g.game_version       = 1
    g.version_code       = "1.108.3"
    g.os_info            = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    g.device_type        = "Handheld"
    g.network_provider   = "Verizon Wireless"
    g.connection_type    = "WIFI"
    g.screen_width       = 1280
    g.screen_height      = 960
    g.dpi                = "240"
    g.cpu_info           = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    g.total_ram          = 5951
    g.gpu_name           = "Adreno (TM) 640"
    g.gpu_version        = "OpenGL ES 3.0"
    g.user_id            = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    g.ip_address         = "172.190.111.97"
    g.language           = "en"
    g.open_id            = token_data.get('open_id', '')
    g.access_token       = token_data.get('access_token', '')
    g.platform_type      = 4
    g.device_form_factor = "Handheld"
    g.device_model       = "Asus ASUS_I005DA"
    g.field_60, g.field_61, g.field_62, g.field_63 = 32968, 29815, 2479, 914
    g.field_64, g.field_65, g.field_66, g.field_67 = 31213, 32968, 31213, 32968
    g.field_70, g.field_73 = 4, 2
    g.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    g.field_76 = 1
    g.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    g.field_78, g.field_79 = 6, 1
    g.os_architecture = "32"
    g.build_number = "2019117877"
    g.field_85 = 1
    g.graphics_backend  = "OpenGLES2"
    g.max_texture_units = 16383
    g.rendering_api     = 4
    g.encoded_field_89  = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    g.field_92 = 9204
    g.marketplace = "3rd_party"
    g.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    g.total_storage = 111107
    g.field_97, g.field_98 = 1, 1
    g.field_99, g.field_100 = "4", "4"

    serialized = g.SerializeToString()
    encrypted  = encrypt_message(AES_KEY, AES_IV, serialized)

    url = "https://loginbp.ppmainecoonghj.com/MajorLogin"
    headers = {
        'User-Agent': "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        'Accept': "*/*",
        'Accept-Encoding': "deflate, gzip",
        'X-Ga-Sv': "1789534056",
        'Authorization': "Bearer ",
        'X-Ga': "v1 1",
        'Releaseversion': "OB55",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.12f1"
    }

    try:
        r = requests.post(url, data=encrypted, headers=headers, verify=False, timeout=20)
    except requests.RequestException as e:
        return {"error": f"Request error: {e}"}

    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code} - {r.reason}"}

    # --- smarter: find where protobuf actually begins ---
    start, parsed = find_protobuf_start(r.content)
    if parsed is None:
        # fallback: try direct parse
        parsed = parse_protobuf(r.content)
        start = 0

    print(f"\n[PROTOBUF STARTS AT OFFSET]: {start}")
    print("[PARSED FIELDS]")
    for k in sorted(parsed.keys()):
        v = parsed[k]
        if isinstance(v, bytes):
            print(f"  field {k}: <bytes len={len(v)}>")
        else:
            sv = str(v)
            print(f"  field {k}: {sv[:80]}{'...' if len(sv) > 80 else ''}")

    # Find the JWT by scanning all string values
    jwt = "N/A"
    region = "N/A"
    lock = "N/A"
    country = "N/A"
    status = "live"
    for k, v in parsed.items():
        if isinstance(v, str):
            if v.startswith("eyJ") and jwt == "N/A":
                jwt = v
            elif v in ("EUROPE", "IND", "SGP", "BRA", "NA", "US", "IN", "SG"):
                if region == "N/A":
                    region = v
                elif lock == "N/A":
                    lock = v
                elif country == "N/A":
                    country = v
            elif v in ("live", "maintenance"):
                status = v

    return {
        "token":   jwt,
        "region":  region,
        "lock":    lock,
        "country": country,
        "status":  status,
    }


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Free Fire Token Generator</title>
<style>*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#0b0d10;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{width:100%;max-width:460px;background:#151922;border:1px solid #2a3040;border-radius:18px;padding:24px;box-shadow:0 15px 50px #0008}h1{font-size:24px;margin:0 0 8px}.muted{color:#9da5b5;font-size:13px;margin-bottom:22px}label{display:block;font-size:13px;color:#cbd1dc;margin:13px 0 7px}input{width:100%;padding:13px;border-radius:10px;border:1px solid #343b4b;background:#0e1117;color:#fff;outline:none}button{width:100%;margin-top:18px;padding:13px;border:0;border-radius:10px;background:#fff;color:#111;font-weight:700;font-size:15px}button:disabled{opacity:.6}.result{margin-top:20px;padding:14px;border-radius:12px;background:#0d1016;border:1px solid #2b3240;white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.55}.err{border-color:#713a3a;color:#ffb7b7}.small{font-size:11px;color:#788195;margin-top:14px}</style></head>
<body><main class="card"><h1>Free Fire Token Generator</h1><div class="muted">Enter UID and password, then press Generate. The URL does not need to be changed.</div>
<form id="f"><label>UID</label><input id="uid" name="uid" value="123456789" inputmode="numeric" required><label>Password</label><input id="password" name="password" value="testpassword" type="password" required><button id="btn">Generate Token</button></form>
<div id="out" class="result" style="display:none"></div><div class="small">The pre-filled values are placeholders; use your own valid test credentials.</div></main>
<script>const f=document.getElementById('f'),out=document.getElementById('out'),btn=document.getElementById('btn');f.addEventListener('submit',async e=>{e.preventDefault();btn.disabled=true;btn.textContent='Generating...';out.style.display='block';out.className='result';out.textContent='Please wait...';try{const r=await fetch('/api/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uid:document.getElementById('uid').value.trim(),password:document.getElementById('password').value})});const data=await r.json();out.className='result '+(data.error?'err':'');out.textContent=JSON.stringify(data,null,2)}catch(err){out.className='result err';out.textContent='Request failed: '+err}finally{btn.disabled=false;btn.textContent='Generate Token'}});</script></body></html>"""

@app.get('/')
def home():
    return render_template_string(PAGE)

@app.post('/api/token')
def api_token():
    data = request.get_json(silent=True) or request.form.to_dict()
    uid = str(data.get('uid', '')).strip()
    password = str(data.get('password', ''))
    if not uid or not password:
        return {"error": "UID and password are required"}, 400
    result = process_token(uid, password)
    return result, (400 if "error" in result else 200)


if __name__ == "__main__":
    print("=" * 50)
    print("  Free Fire OB55 Token Generator")
    print("=" * 50)

    uid      = input("Enter UID      : ").strip()
    password = input("Enter Password : ").strip()

    result = process_token(uid, password)

    print("\n" + "=" * 50)
    print("  RESULT")
    print("=" * 50)

    if "error" in result:
        print("ERROR   :", result["error"])
    else:
        print("TOKEN   :", result.get("token"))
        print()
        print("REGION  :", result.get("region"))
        print("LOCK    :", result.get("lock"))
        print("COUNTRY :", result.get("country"))
        print("STATUS  :", result.get("status"))
        print()
        print("Credit  : Flexbase")
        print("Telegram: @Flexbasei")

    print("=" * 50)