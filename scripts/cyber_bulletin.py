import requests, feedparser, os, sys
from datetime import datetime, timedelta

def get_cyber_data():
    report = [f"# Veille du {datetime.now().strftime('%d/%m/%Y')}\n"]
    
    # 1. NVD API (CVE > 9.0)
    try:
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.000')
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate={yesterday}"
        res = requests.get(url, timeout=10).json()
        vulns = [f"- {v['cve']['id']}: https://nvd.nist.gov/vuln/detail/{v['cve']['id']}" for v in res.get('vulnerabilities', [])]
        report.append("## FAILLES CRITIQUES\n" + ("\n".join(vulns) if vulns else "Aucune faille critique publiée."))
    except Exception as e:
        report.append(f"## FAILLES CRITIQUES\nErreur NVD: {e}")

    # 2. RSS Auto
    try:
        feed = feedparser.parse("https://www.securityweek.com/category/verticals/automotive/feed/")
        news = [f"- {e.title}: {e.link}" for e in feed.entries[:5]]
        report.append("\n## SECTEUR AUTO\n" + ("\n".join(news) if news else "Aucune actualité auto ce jour."))
    except Exception as e:
        report.append(f"\n## SECTEUR AUTO\nErreur RSS: {e}")

    return "\n".join(report)

if __name__ == "__main__":
    try:
        content = get_cyber_data()
        os.makedirs("reports", exist_ok=True)
        filename = f"reports/bulletin_{datetime.now().strftime('%Y-%m-%d')}.md"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Succès : {filename} généré.")
    except Exception as e:
        print(f"Erreur fatale : {e}")
        sys.exit(1)
