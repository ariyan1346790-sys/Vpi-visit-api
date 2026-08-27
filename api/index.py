#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import json
import time
from http.server import BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
#                             SYSTEM CONSTANTS
# ==============================================================================
STATIC_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
STATIC_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
BD_VISIT_URL = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

# High-Speed Optimized HTTP Session
HTTP_SESSION = requests.Session()
retries = Retry(total=1, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(pool_connections=200, pool_maxsize=200, max_retries=retries)
HTTP_SESSION.mount('https://', adapter)
HTTP_SESSION.mount('http://', adapter)

# ==============================================================================
#                  ALL-IN-ONE PROTOBUF & ENCRYPTION HELPERS
# ==============================================================================
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f',
           '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f',
           'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', '97',
           'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', '97',
           'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf',
           'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df',
           'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', '91',
           'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f',
           '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f',
           '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', 'a0', '2b', '2c', '2d', '2e', '2f',
           '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', 'a0', '3b', '3c', '3d', '3e', '3f',
           '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f',
           '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f',
           '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f',
           '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                z = (y - int(str(int(y)))) * 128
                n = (z - int(str(int(z)))) * 128
                m = (n - int(str(int(n)))) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                z = (y - int(str(int(y)))) * 128
                n = (z - int(str(int(z)))) * 128
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
        else:
            strx = int(x)
            y = (x - int(strx)) * 128
            z = (y - int(str(int(y)))) * 128
            return dec[int(z)] + dec[int(y)] + xxx[int(x)]
    else:
        strx = int(x)
        if strx == 0:
            return xxx[int((x - int(strx)) * 128)]
        else:
            return dec[int((x - int(strx)) * 128)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(STATIC_KEY, AES.MODE_CBC, STATIC_IV)
    return cipher.encrypt(pad(plain_text, AES.block_size)).hex()

# Built-in Pure Python Fast Protobuf Parser (No .pb2 dependency needed)
def read_varint(stream):
    res = 0
    shift = 0
    while True:
        b = stream.read(1)
        if not b:
            return None
        val = ord(b)
        res |= (val & 0x7F) << shift
        if not (val & 0x80):
            return res
        shift += 7

def parse_player_data(response_bytes):
    try:
        stream = io.BytesIO(response_bytes)
        nickname = None
        region = None

        while True:
            tag = read_varint(stream)
            if tag is None: break
            field_num = tag >> 3
            wire_type = tag & 0x07

            if field_num == 1 and wire_type == 2:  # AccountInfo message
                sub_len = read_varint(stream)
                sub_bytes = stream.read(sub_len)
                sub_stream = io.BytesIO(sub_bytes)

                while True:
                    sub_tag = read_varint(sub_stream)
                    if sub_tag is None: break
                    sub_field = sub_tag >> 3
                    sub_wire = sub_tag & 0x07

                    if sub_field == 3 and sub_wire == 2:  # PlayerNickname
                        n_len = read_varint(sub_stream)
                        nickname = sub_stream.read(n_len).decode('utf-8', errors='ignore')
                    elif sub_field == 5 and sub_wire == 2:  # PlayerRegion
                        r_len = read_varint(sub_stream)
                        region = sub_stream.read(r_len).decode('utf-8', errors='ignore')
                    elif sub_wire == 0:
                        read_varint(sub_stream)
                    elif sub_wire == 2:
                        l = read_varint(sub_stream)
                        sub_stream.read(l)
                    elif sub_wire == 1:
                        sub_stream.read(8)
                    elif sub_wire == 5:
                        sub_stream.read(4)
            elif wire_type == 0:
                read_varint(stream)
            elif wire_type == 2:
                length = read_varint(stream)
                stream.read(length)
            elif wire_type == 1:
                stream.read(8)
            elif wire_type == 5:
                stream.read(4)

        if nickname or region:
            return {"nickname": nickname or "Unknown", "region": region or "BD"}
    except Exception:
        pass
    return None

# ==============================================================================
#                         DISPATCH ENGINE
# ==============================================================================
def send_single_visit(target_uid, token, payload_data):
    headers = {
        "ReleaseVersion": "OB54",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {token}",
        "Host": "clientbp.ggpolarbear.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; SM-S918B)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip"
    }
    try:
        res = HTTP_SESSION.post(BD_VISIT_URL, headers=headers, data=payload_data, verify=False, timeout=3.5)
        if res.status_code == 200:
            player_info = parse_player_data(res.content)
            return True, player_info
        return False, None
    except Exception:
        return False, None

# ==============================================================================
#                       VERCEL HTTP REQUEST HANDLER
# ==============================================================================
class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        res = {
            "status": "online",
            "message": "🔥 High-Speed 50K+ Visitor Serverless API is Active (BD Server)",
            "usage": {
                "method": "POST",
                "body_format": {
                    "target_uid": "123456789",
                    "count": 5000,
                    "tokens": ["TOKEN_1", "TOKEN_2", "..."]
                }
            }
        }
        self.wfile.write(json.dumps(res, ensure_ascii=False, indent=2).encode('utf-8'))

    def do_POST(self):
        start_time = time.time()
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            body = json.loads(post_data.decode('utf-8'))

            target_uid = str(body.get("target_uid", "")).strip()
            count = int(body.get("count", 1000))
            tokens = body.get("tokens", [])

            # Validation
            if not target_uid or not target_uid.isdigit():
                self.send_error_response("Invalid or missing 'target_uid'. Must be numeric.", 400)
                return

            if not tokens or not isinstance(tokens, list):
                self.send_error_response("Missing 'tokens' array. Provide 1+ valid bearer tokens.", 400)
                return

            # Clean and sanitize tokens
            clean_tokens = [t.strip() for t in tokens if t and isinstance(t, str)]
            if not clean_tokens:
                self.send_error_response("No valid tokens found in list.", 400)
                return

            # Prepare encrypted payload once to save CPU
            encrypted_hex = encrypt_api("08" + Encrypt_ID(str(target_uid)) + "1801")
            payload_data = bytes.fromhex(encrypted_hex)

            token_count = len(clean_tokens)
            success_visits = 0
            failed_visits = 0
            player_nickname = "Unknown"
            player_region = "BD"

            def worker_task(token):
                return send_single_visit(target_uid, token, payload_data)

            # High concurrency multi-threading pool
            max_workers = min(100, max(20, count // 10))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Distribute tokens across requested count
                assigned_tokens = [clean_tokens[i % token_count] for i in range(count)]
                results = executor.map(worker_task, assigned_tokens)

                for ok, p_info in results:
                    if ok:
                        success_visits += 1
                        if player_nickname == "Unknown" and p_info and p_info.get("nickname"):
                            player_nickname = p_info.get("nickname")
                            player_region = p_info.get("region", "BD")
                    else:
                        failed_visits += 1

            execution_time = round(time.time() - start_time, 2)

            response_payload = {
                "status": "success" if success_visits > 0 else "partial_or_failed",
                "player_info": {
                    "uid": target_uid,
                    "nickname": player_nickname,
                    "region": player_region
                },
                "stats": {
                    "requested": count,
                    "delivered": success_visits,
                    "failed": failed_visits,
                    "available_tokens": token_count,
                    "time_taken_seconds": execution_time
                },
                "message": f"সফলভাবে {success_visits}/{count} টি ভিজিট পাঠানো হয়েছে!" if success_visits > 0 else "ভিজিট পাঠানো সম্ভব হয়নি।"
            }

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response_payload, ensure_ascii=False, indent=2).encode('utf-8'))

        except Exception as e:
            self.send_error_response(f"Internal Server Error: {str(e)}", 500)

    def send_error_response(self, error_msg, code=400):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        err_res = {"status": "error", "message": error_msg}
        self.wfile.write(json.dumps(err_res, ensure_ascii=False).encode('utf-8'))
