#!/usr/bin/env python3
"""
phish_simulator.py - Lab-only phishing campaign simulator (safe)

Features (lab-only, no SMTP):
- Generates sample phishing email HTML files into ./emails/
- Runs a local Flask web app to:
    - show a simulated inbox (list of saved emails)
    - serve campaign landing pages (simulated login form)
    - log interactions to ./logs/phish_sim.log (timestamp + metadata + supplied token)
- Use only in isolated lab. Do NOT send these emails to real users.

Run:
  python3 phish_simulator.py
Open: http://127.0.0.1:5000/
"""

from flask import Flask, request, render_template_string, redirect, url_for, send_from_directory
import os, datetime, uuid, json

APP_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_DIR = os.path.join(APP_DIR, "emails")
LOG_DIR = os.path.join(APP_DIR, "logs")
os.makedirs(EMAIL_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "phish_sim.log")

app = Flask(__name__)

# Basic landing page template (simulated login). For safety, we ask users to enter a "training token".
LANDING_TPL = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>{{title}}</title></head>
<body style="font-family:system-ui;max-width:560px;margin:40px;">
  <h2>{{title}}</h2>
  <p>{{desc}}</p>
  <form method="post">
    <label>Training token (enter exactly: <code>{{token_hint}}</code>)</label><br/>
    <input name="token" autocomplete="off" autofocus style="width:100%;padding:8px;margin:8px 0"/><br/>
    <button type="submit">Submit</button>
  </form>
  <p style="color:#666;font-size:0.9em">This is a local simulation. Do not enter real credentials.</p>
</body>
</html>
"""

# Simulated inbox template
INBOX_TPL = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Simulated Inbox</title></head>
<body style="font-family: system-ui; margin: 24px;">
  <h1>Simulated Inbox</h1>
  <p>Generated emails (local only). Click to view.</p>
  <ul>
  {% for f in files %}
    <li><a href="{{ url_for('view_email', fname=f) }}">{{ f }}</a></li>
  {% endfor %}
  </ul>
  <hr/>
  <h3>Generate sample email for a campaign</h3>
  <form method="post" action="{{ url_for('generate_email') }}">
    <label>Campaign name: <input name="campaign" required/></label><br/>
    <label>Landing path (unique id, default auto): <input name="path"/></label><br/>
    <label>Title: <input name="title" value="Important: Action Required"/></label><br/>
    <label>Button label: <input name="btn" value="Proceed"/></label><br/>
    <button type="submit">Generate email</button>
  </form>
  <hr/>
  <p><a href="{{ url_for('list_campaigns') }}">List campaigns</a></p>
</body>
</html>
"""

CAMPAIGNS_TPL = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Campaigns</title></head>
<body style="font-family:system-ui;margin:24px;">
  <h1>Active Campaigns</h1>
  <ul>
  {% for c in campaigns %}
    <li>{{c['id']}} — <b>{{c['name']}}</b> — <a href="{{ url_for('serve_campaign', cid=c['id']) }}">Landing</a></li>
  {% endfor %}
  </ul>
  <p><a href="{{ url_for('inbox') }}">Back to inbox</a></p>
</body>
</html>
"""

# In-memory campaigns catalog (persisted to disk optional)
CAMPAIGNS_FILE = os.path.join(LOG_DIR, "campaigns.json")
if os.path.exists(CAMPAIGNS_FILE):
    try:
        with open(CAMPAIGNS_FILE, "r") as f:
            CAMPAIGNS = json.load(f)
    except Exception:
        CAMPAIGNS = {}
else:
    CAMPAIGNS = {}

def save_campaigns():
    with open(CAMPAIGNS_FILE, "w") as f:
        json.dump(CAMPAIGNS, f, indent=2)

def log_event(data: dict):
    data['ts'] = datetime.datetime.utcnow().isoformat() + "Z"
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

@app.route("/")
def inbox():
    files = sorted(os.listdir(EMAIL_DIR))
    return render_template_string(INBOX_TPL, files=files)

@app.route("/emails/<path:fname>")
def view_email(fname):
    # sanitize path
    safe = os.path.basename(fname)
    full = os.path.join(EMAIL_DIR, safe)
    if not os.path.exists(full):
        return "Not found", 404
    return send_from_directory(EMAIL_DIR, safe)

@app.route("/generate", methods=["POST"])
def generate_email():
    campaign = request.form.get("campaign", "demo")
    path = request.form.get("path") or str(uuid.uuid4())[:8]
    title = request.form.get("title") or "Important update"
    button = request.form.get("btn") or "Continue"

    cid = path
    landing_url = f"http://127.0.0.1:5000/landing/{cid}"
    token_hint = "TRAINME"

    # register campaign
    CAMPAIGNS[cid] = {"id": cid, "name": campaign, "title": title, "token_hint": token_hint}
    save_campaigns()

    # build simple HTML email saved locally
    email_html = f"""
    <!doctype html>
    <html><body style="font-family:system-ui;">
    <h3>{title}</h3>
    <p>Dear user, please review your account information urgently.</p>
    <p><a href="{landing_url}"><button style="padding:10px">{button}</button></a></p>
    <p style="font-size:0.9em;color:#666">This is a LOCAL SIMULATION for training only.</p>
    </body></html>
    """
    fname = f"{campaign}_{cid}.html"
    with open(os.path.join(EMAIL_DIR, fname), "w", encoding="utf-8") as f:
        f.write(email_html)

    return redirect(url_for('inbox'))

@app.route("/campaigns")
def list_campaigns():
    campaigns = list(CAMPAIGNS.values())
    return render_template_string(CAMPAIGNS_TPL, campaigns=campaigns)

@app.route("/landing/<cid>", methods=["GET","POST"])
def serve_campaign(cid):
    c = CAMPAIGNS.get(cid)
    if not c:
        return "Campaign not found", 404
    token_hint = c.get("token_hint", "TRAINME")
    if request.method == "POST":
        supplied = request.form.get("token","")
        # Log but DO NOT store raw passwords — we store only a marker whether they matched the training token
        ok = (supplied == token_hint)
        log_event({
            "event": "landing_submit",
            "campaign": cid,
            "client_ip": request.remote_addr,
            "token_match": bool(ok),
            "supplied_len": len(supplied)  # length only
        })
        # For training, show friendly response
        if ok:
            return "<h3>Good job — you entered the training token correctly.</h3><p><a href='/'>Back to inbox</a></p>"
        else:
            return "<h3>Incorrect token (this is a simulation).</h3><p><a href='/'>Back to inbox</a></p>"
    return render_template_string(LANDING_TPL, title=c.get("title","Attention"), desc="This is a simulated login. Enter the training token shown in your briefing.", token_hint=c.get("token_hint","TRAINME"))

@app.route("/logs")
def view_logs():
    if not os.path.exists(LOG_FILE):
        return "<pre>No logs yet</pre>"
    with open(LOG_FILE,"r") as f:
        data = f.read()
    return "<pre style='white-space:pre-wrap;max-height:600px;overflow:auto;'>%s</pre>" % (data,)

if __name__ == "__main__":
    print("Starting local phishing simulator on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
