import requests
import feedparser
from datetime import datetime, timedelta

# Configuration des sources
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RSS_AUTO = "https://www.securityweek.com/category/verticals/automotive/feed/"

def get_vulns():
    # Récupère les CVE > 9.0 des dernières 24h
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    params = {'cvssV3Severity': 'CRITICAL', 'pubStartDate': yesterday}
    res = requests.get(NVD_API, params=params).json()
    return [(v['cve']['id'], f"https://nvd.nist.gov/vuln/detail/{v['cve']['id']}") for v in res.get('vulnerabilities', [])]

def get_auto_news():
    # Récupère les actualités cyber-automobile via RSS
    feed = feedparser.parse(RSS_AUTO)
    return [(entry.title, entry.link) for entry in feed.entries[:5]]

# Génération du rapport (Logique simplifiée pour GitHub Actions)
print(f"Bulletin du {datetime.now().strftime('%d/%m/%Y')}")
print("\n--- Failles Critiques (CVSS > 9) ---\n", get_vulns())
print("\n--- Sécurité Automobile ---\n", get_auto_news())
