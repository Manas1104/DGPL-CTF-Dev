# app.py
# Weak-crypto CTF: issues auth cookie as MD5(username + ':' + secret)
# WARNING: Do not log the secret in production. This app is intentionally vulnerable for CTF use.

from flask import Flask, request, make_response, redirect, url_for, render_template_string, abort
import hashlib
import os

app = Flask(__name__)

# Small numeric secret (keep short for brute-force during contest)
# Default is 4 digits but you can override by setting ENV SECRET.
SECRET = os.environ.get("SECRET", "0420")  # change before publishing if you want different number

# Location of flag file (inside container)
FLAG_PATH = os.environ.get("FLAG_PATH", "flags/admin_flag.txt")

# Simple templates (inline for single-file requirement)
LOGIN_TPL = """
<!doctype html>
<title>Login</title>
<h2>Login</h2>
<form method="post" action="{{ url_for('login') }}">
  <label>Username: <input name="username" required></label><br>
  <label>Secret: <input name="secret" required></label><br>
  <button type="submit">Login</button>
</form>
<p>After login the server sets cookie <code>auth</code> = MD5(username + ':' + secret)</p>
"""

HOME_TPL = """
<!doctype html>
<title>Home</title>
<h2>Welcome</h2>
<p><a href="{{ url_for('login') }}">Login</a> — or try visiting <a href="{{ url_for('admin') }}">/admin</a></p>
"""

ADMIN_FORBIDDEN_TPL = """
<!doctype html>
<title>403</title>
<h2>Access denied</h2>
<p>You are not authorized to view this page.</p>
"""

ADMIN_OK_TPL = """
<!doctype html>
<title>Admin</title>
<h2>Admin panel</h2>
<pre>{{ flag }}</pre>
"""

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()

@app.route('/')
def index():
    return render_template_string(HOME_TPL)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_TPL)
    username = request.form.get('username', '')
    secret_guess = request.form.get('secret', '')
    # create token as md5(username + ':' + secret_guess)
    token = md5_hex(f"{username}:{secret_guess}")
    resp = make_response(redirect(url_for('index')))
    # set auth cookie (HttpOnly)
    resp.set_cookie('auth', token, httponly=True)
    return resp

@app.route('/admin')
def admin():
    # read cookie
    token = request.cookies.get('auth', '')
    expected = md5_hex(f"admin:{SECRET}")
    if token != expected:
        return render_template_string(ADMIN_FORBIDDEN_TPL), 403
    # Only when token matches, read and show the flag
    try:
        with open(FLAG_PATH, 'r') as f:
            flag = f.read().strip()
    except Exception:
        flag = "FLAG MISSING"
    return render_template_string(ADMIN_OK_TPL, flag=flag)

# small helper route to show computed hash for a given username (for players to experiment)
# NOTE: this does not leak the server SECRET. It is purely client-side using provided username+secret.
@app.route('/compute', methods=['GET'])
def compute():
    username = request.args.get('username', '')
    secret = request.args.get('secret', '')
    if not username or not secret:
        return "Usage: /compute?username=...&secret=...\n"
    return md5_hex(f"{username}:{secret}") + "\n"

if __name__ == '__main__':
    # Use simple builtin server for quick testing; in production use gunicorn as in Dockerfile.
    app.run(host='0.0.0.0', port=8000)
