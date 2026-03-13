import requests, feedparser, smtplib, os
from datetime import datetime, timedelta
from email.message import EmailMessage

def get_cyber_data():
    # NVD API - CVE > 9.0 (Dernières 24h)
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    res = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate={yesterday}").json()
    vulns = [f"- {v['cve']['id']}: https://nvd.nist.gov/vuln/detail/{v['cve']['id']}" for v in res.get('vulnerabilities', [])]
    
    # RSS Auto News
    feed = feedparser.parse("https://www.securityweek.com/category/verticals/automotive/feed/")
    news = [f"- {e.title}: {e.link}" for e in feed.entries[:5]]
    
    return "\n".join(["### FAILLES CRITIQUES", *vulns, "\n### SECTEUR AUTO", *news])

def send_email(body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = f"Veille Cyber du {datetime.now().strftime('%d/%m/%Y')}"
    msg['From'], msg['To'] = os.environ['SMTP_USER'], os.environ['SMTP_USER']
    
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(os.environ['SMTP_USER'], os.environ['SMTP_PASS'])
        server.send_message(msg)

if __name__ == "__main__":
    report = get_cyber_data()
    send_email(report)
