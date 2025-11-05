import os, time, hmac, hashlib, base64, json
from flask import Flask, render_template_string, request, redirect, url_for, session, abort, flash
import requests

ADMIN_USER = os.getenv("ADMIN_USER", "ginger")
ADMIN_PASS = os.getenv("ADMIN_PASS", "changeme")
SECRET_KEY  = os.getenv("FLASK_SECRET_KEY", "dev-key-change-me")
PORTAL_SECRET = os.getenv("PORTAL_SECRET", "b3tterTh@nP@ssword123")
PI_UNLOCK_URL = os.getenv("PI_UNLOCK_URL", "https://webhook.twoballsandabone.com/unlock")

app = Flask(__name__)
app.secret_key = SECRET_KEY

PAGE = """
<!doctype html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Doggy Licks — Operator Portal</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 0; padding: 0; background:#f7f7fb;}
    .wrap { max-width: 520px; margin: 48px auto; background: #fff; padding: 28px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.06); }
    h1 { font-size: 22px; margin: 0 0 8px; }
    .muted { color:#666; margin:0 0 18px; }
    form { margin: 0 0 12px; }
    input[type=text], input[type=password] { width:100%; padding:12px 14px; border:1px solid #ddd; border-radius:10px; margin:8px 0 14px; font-size:16px;}
    button { padding:12px 16px; border:0; border-radius:12px; cursor:pointer; font-size:16px; }
    .btn { background:#381372; color:#fff; }
    .btn.secondary { background:#eae9f7; color:#381372; }
    .row { display:flex; gap:12px; flex-wrap:wrap; }
    .msg { background:#f0f7ff; color:#124; padding:10px 12px; border-radius:10px; margin:10px 0; font-size:14px;}
  </style>
</head>
<body>
  <div class="wrap">
    {% if not session.get('authed') %}
      <h1>Operator Login</h1>
      <p class="muted">Enter your admin credentials to control the freezer.</p>
      {% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}
      <form method="post" action="{{ url_for('login') }}">
        <input name="u" type="text" placeholder="Username" autocomplete="username" required>
        <input name="p" type="password" placeholder="Password" autocomplete="current-password" required>
        <button class="btn" type="submit">Sign in</button>
      </form>
    {% else %}
      <h1>Doggy Licks — Controls</h1>
      <p class="muted">Logged in as {{ session.get('user') }} • <a href="{{ url_for('logout') }}">Log out</a></p>
      {% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}

      <form method="post" action="{{ url_for('send_command') }}">
        <div class="row">
          <button class="btn" name="action" value="unlock" type="submit">🔓 Unlock</button>
          <button class="btn secondary" name="action" value="beep" type="submit">🔊 Test Beep</button>
        </div>
      </form>

      <p class="muted" style="margin-top:16px;">
        Each action is signed with an HMAC and sent to your Pi at:<br>
        <code>{{ pi_url }}</code>
      </p>
    {% endif %}
  </div>
</body>
</html>
"""

def _sign_payload(ts: str, payload: bytes) -> str:
    msg = (ts.encode() + b"." + payload)
    sig = hmac.new(PORTAL_SECRET.encode(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")

@app.route("/", methods=["GET"])
def home():
    return render_template_string(PAGE, pi_url=PI_UNLOCK_URL)

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("u","").strip()
    p = request.form.get("p","")
    if u == ADMIN_USER and p == ADMIN_PASS:
        session["authed"] = True
        session["user"] = u
        flash("Welcome back.")
        return redirect(url_for("home"))
    flash("Invalid credentials.")
    return redirect(url_for("home"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Signed out.")
    return redirect(url_for("home"))

@app.route("/send", methods=["POST"])
def send_command():
    if not session.get("authed"):
        abort(401)
    action = request.form.get("action","unlock")
    if action not in ("unlock","beep","lock"):
        action = "unlock"

    ts = str(int(time.time()))
    body = json.dumps({"action": action, "ts": int(ts)})
    sig = _sign_payload(ts, body.encode())

    try:
        r = requests.post(
            PI_UNLOCK_URL,
            headers={
                "Content-Type": "application/json",
                "X-Portal-Ts": ts,
                "X-Portal-Sig": sig
            },
            data=body,
            timeout=6
        )
        if r.ok:
            flash(f"Sent: {action} ✓")
        else:
            flash(f"Pi error ({r.status_code}): {r.text[:160]}")
    except Exception as e:
        flash(f"Request failed: {e}")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","8080")))
