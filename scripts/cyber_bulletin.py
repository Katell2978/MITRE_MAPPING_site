import requests, feedparser, os
from datetime import datetime, timedelta

def get_cyber_data():
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    res = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate={yesterday}").json()
    vulns = [f"- {v['cve']['id']}: https://nvd.nist.gov/vuln/detail/{v['cve']['id']}" for v in res.get('vulnerabilities', [])]
    
    feed = feedparser.parse("https://www.securityweek.com/category/verticals/automotive/feed/")
    news = [f"- {e.title}: {e.link}" for e in feed.entries[:5]]
    
    return f"# Veille du {datetime.now().strftime('%d/%m/%Y')}\n\n## FAILLES CRITIQUES\n" + "\n".join(vulns) + "\n\n## SECTEUR AUTO\n" + "\n".join(news)

if __name__ == "__main__":
    content = get_cyber_data()
    os.makedirs("reports", exist_ok=True)
    with open(f"reports/bulletin_{datetime.now().strftime('%Y-%m-%d')}.md", "w", encoding="utf-8") as f:
        f.write(content)
