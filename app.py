
from flask import Flask, render_template, request, jsonify, send_file
from datetime import datetime
from urllib.parse import urlparse
import re, json, csv, io

app = Flask(__name__)
REPORTS = []

def analyze_message(text, category="Message"):
    t = (text or "").lower()
    indicators = []
    patterns = {
        "OTP / verification request": r"\botp\b|one[- ]time password|verification code",
        "PIN / CVV request": r"\bpin\b|\bcvv\b|card number",
        "UPI / payment request": r"\bupi\b|payment request|collect request|pay now|send money",
        "KYC warning": r"\bkyc\b|know your customer",
        "Account blocked/threat": r"account (blocked|suspend|deactivate)|will be blocked|account बंद",
        "Refund scam pattern": r"refund|cashback|return your money",
        "Registration / joining fee": r"registration fee|joining fee|processing fee",
        "Security deposit": r"security deposit|deposit.*job|pay.*deposit",
        "Guaranteed job / selection": r"guaranteed job|100% job|selected.*job|guaranteed selection",
        "Fake scholarship pattern": r"scholarship.*fee|scholarship.*payment|pay.*scholarship",
        "Urgency / pressure": r"urgent|immediately|within \d+ (minutes?|hours?)|act now",
        "Suspicious link": r"https?://|www\.|bit\.ly|tinyurl|t\.co|shorturl",
    }
    for name, pat in patterns.items():
        if re.search(pat, t):
            indicators.append(name)

    score = min(100, len(indicators)*11 + (18 if re.search(r"https?://|www\.", t) else 0))
    if category in ("Bank / UPI", "Job / Internship / Scholarship") and indicators:
        score = min(100, score + 12)
    level = "HIGH RISK" if score >= 70 else "SUSPICIOUS" if score >= 35 else "LOW RISK"
    advice = {
        "HIGH RISK": "Do not share OTP/PIN/CVV or send money. Verify through the organisation's official website/app.",
        "SUSPICIOUS": "Pause before responding. Independently verify the sender, request and links.",
        "LOW RISK": "No strong scam indicators were detected. Still avoid sharing sensitive credentials."
    }[level]
    return {"score": score, "level": level, "indicators": indicators, "advice": advice, "category": category}

def url_scan(url):
    raw = (url or "").strip()
    parsed = urlparse(raw if re.match(r"^[a-zA-Z]+://", raw) else "https://" + raw)
    host = parsed.netloc.lower()
    path = (parsed.path + "?" + parsed.query).lower()
    indicators = []
    if not parsed.netloc:
        indicators.append("Invalid or incomplete URL")
    if any(x in host for x in ["bit.ly","tinyurl.com","t.co","shorturl.at","is.gd","cutt.ly"]):
        indicators.append("URL shortener detected")
    if any(x in (host+path) for x in ["login-","verify","urgent","kyc","refund","reward","prize","free-gift","account-blocked"]):
        indicators.append("Suspicious keyword pattern")
    if "@" in raw:
        indicators.append("Deceptive @ symbol pattern")
    if host.count("-") >= 3:
        indicators.append("Unusual domain pattern")
    score = min(100, len(indicators)*24)
    level = "HIGH RISK" if score >= 70 else "SUSPICIOUS" if score >= 35 else "LOW RISK"
    return {"score":score,"level":level,"indicators":indicators,
            "host":host or "—",
            "advice":"Do not enter passwords, OTPs or card details on a suspicious site." if indicators else "No obvious URL-pattern warning detected; verify the domain before signing in."}

def extract_entities(text):
    return {
        "mobile": re.findall(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)", text or ""),
        "email": re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text or ""),
        "urls": re.findall(r"https?://[^\s]+|www\.[^\s]+", text or ""),
        "locations": re.findall(r"(?:location|located at|address|near|coordinates?)\s*[:\-]?\s*([A-Za-z0-9 ,.-]{3,80})", text or "", re.I)
    }

@app.route("/")
def dashboard(): return render_template("dashboard.html", reports=REPORTS)

@app.route("/scanner")
def scanner(): return render_template("scanner.html")
@app.route("/bank")
def bank(): return render_template("bank.html")
@app.route("/jobs")
def jobs(): return render_template("jobs.html")
@app.route("/url")
def url_page(): return render_template("url.html")
@app.route("/mobile")
def mobile(): return render_template("mobile.html")
@app.route("/email")
def email(): return render_template("email.html")
@app.route("/location")
def location(): return render_template("location.html")
@app.route("/incident")
def incident(): return render_template("incident.html")
@app.route("/police")
def police(): return render_template("police.html")

@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    result = analyze_message(data.get("text",""), data.get("category","Message"))
    result["entities"] = extract_entities(data.get("text",""))
    return jsonify(result)

@app.post("/api/url")
def api_url():
    return jsonify(url_scan((request.get_json(silent=True) or {}).get("url","")))

@app.post("/api/mobile")
def api_mobile():
    number = re.sub(r"[\s()-]", "", (request.get_json(silent=True) or {}).get("number",""))
    valid = bool(re.fullmatch(r"(?:\+91)?[6-9]\d{9}", number))
    return jsonify({"valid":valid, "country":"India" if valid else "Unknown",
                    "region":"Indian mobile format" if valid else "Format could not be validated",
                    "warning":"Format validation only. This app does NOT reveal live location or identity." if valid else "Enter a valid Indian mobile number."})

@app.post("/api/email")
def api_email():
    value=(request.get_json(silent=True) or {}).get("email","").strip()
    valid=bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",value))
    domain=value.split("@",1)[1].lower() if "@" in value else "—"
    suspicious = valid and (domain.endswith(".xyz") or domain.endswith(".top") or "tempmail" in domain)
    return jsonify({"valid":valid,"domain":domain,"suspicious":suspicious,
                    "warning":"Domain pattern deserves extra verification." if suspicious else "No basic suspicious-domain pattern detected."})

@app.post("/api/location")
def api_location():
    text=(request.get_json(silent=True) or {}).get("text","")
    urls=re.findall(r"https?://(?:www\.)?(?:maps\.google\.com|goo\.gl|maps\.app\.goo\.gl)[^\s]+",text)
    coords=re.findall(r"(-?\d{1,3}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)",text)
    ent=extract_entities(text)
    return jsonify({"urls":urls,"coordinates":coords,"location_text":ent["locations"],
                    "message":"Only explicitly shared location information is processed. No phone-based tracking."})

@app.post("/api/report")
def api_report():
    data=request.get_json(silent=True) or {}
    report={"id":f"CS-{len(REPORTS)+1:04d}","date":datetime.now().strftime("%d %b %Y, %I:%M %p"),
            "category":data.get("category","Message"),"message":data.get("message",""),
            "risk":data.get("risk",{}),"entities":data.get("entities",{}),
            "action":"User review required before any external reporting."}
    REPORTS.append(report)
    return jsonify(report)

@app.get("/api/report/<rid>")
def get_report(rid):
    r=next((x for x in REPORTS if x["id"]==rid),None)
    return jsonify(r or {"error":"Not found"}), 200 if r else 404

@app.get("/download-report/<rid>")
def download_report(rid):
    r=next((x for x in REPORTS if x["id"]==rid),None)
    if not r: return "Report not found",404
    buf=io.BytesIO(json.dumps(r,indent=2).encode())
    return send_file(buf,as_attachment=True,download_name=f"{rid}.json",mimetype="application/json")

@app.get("/api/stats")
def stats():
    high=sum(1 for r in REPORTS if r["risk"].get("level")=="HIGH RISK")
    suspicious=sum(1 for r in REPORTS if r["risk"].get("level")=="SUSPICIOUS")
    cats={}
    for r in REPORTS: cats[r["category"]]=cats.get(r["category"],0)+1
    avg=round(sum(r["risk"].get("score",0) for r in REPORTS)/len(REPORTS)) if REPORTS else 0
    return jsonify({"total":len(REPORTS),"high":high,"suspicious":suspicious,
                    "low":max(0,len(REPORTS)-high-suspicious),"avgRisk":avg,"categories":cats})

if __name__=="__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
