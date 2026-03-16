#!/usr/bin/env python3
    """Build a CPE->metrics JSON using local NVD JSON 2.0 feed dumps.

    Input
    -----
    - A CSV file containing a column with CPE 2.3 strings (any header containing 'cpe')
    - A directory containing NVD feed dumps (.json.gz) downloaded by scripts/nvd_mirror.py

    Output
    ------
    - data/cpe_metrics.json : mapping of each CPE to {totalCves, kevCves, maxCvss, lastDate}

    Notes
    -----
    - This script targets the NVD JSON 2.0 schema where CVE records are under top-level key 'vulnerabilities'
      (same structure as the 2.0 API responses).
    - It scans all available yearly dumps + modified + recent in the feeds directory.
      For faster runs, you can restrict to only modified/recent once the base index was built.

    """

    import argparse
    import csv
    import datetime
    import gzip
    import io
    import json
    import os
    import re
    import sys
    import urllib.request

    KEV_DEFAULT = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"


    def read_cpe_list(csv_path):
        # autodetect delimiter
        raw = open(csv_path, 'rb').read()
        text = raw.decode('utf-8-sig', errors='replace')
        sample = text.splitlines()[:5]
        delim = ';' if sample and sample[0].count(';') >= sample[0].count(',') else ','

        f = io.StringIO(text)
        reader = csv.reader(f, delimiter=delim)
        rows = list(reader)
        if not rows:
            return []
        headers = [h.strip() for h in rows[0]]
        idx = -1
        for i, h in enumerate(headers):
            if 'cpe' in h.lower():
                idx = i
                break
        if idx < 0:
            # also accept one-column files
            idx = 0

        out = []
        for r in rows[1:]:
            if idx >= len(r):
                continue
            cpe = (r[idx] or '').strip()
            if cpe.startswith('cpe:2.3:'):
                out.append(cpe)
        return sorted(set(out))


    def http_get_json(url, timeout=120):
        req = urllib.request.Request(url, headers={
            "User-Agent": "cpe-metrics/1.0 (offline-processing)"
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode('utf-8', errors='replace'))


    def load_kev_set(kev_url):
        kev = http_get_json(kev_url)
        items = kev.get('vulnerabilities') or kev.get('Vulnerabilities') or []
        s = set()
        for it in items:
            cid = it.get('cveID') or it.get('cveId') or it.get('cve') or it.get('CVE')
            if cid:
                s.add(str(cid).strip().upper())
        return s


    def extract_max_cvss(cve_obj):
        metrics = cve_obj.get('metrics') or {}
        candidates = []
        for k in ['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV3','cvssMetricV2']:
            arr = metrics.get(k)
            if isinstance(arr, list):
                for m in arr:
                    s = (((m or {}).get('cvssData') or {}).get('baseScore'))
                    if isinstance(s, (int, float)):
                        candidates.append(float(s))
        return max(candidates) if candidates else None


    def extract_date(cve_obj):
        return cve_obj.get('lastModified') or cve_obj.get('published')


    def iter_feed_records(path):
        # NVD feeds are JSON; we store .json.gz
        with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        vulns = data.get('vulnerabilities') or []
        for v in vulns:
            cve = (v or {}).get('cve') or {}
            if cve:
                yield cve


    def extract_cpes_from_configurations(configurations):
        out = []

        def walk(node):
            if not node:
                return
            for m in node.get('cpeMatch') or []:
                crit = m.get('criteria') or m.get('cpe23Uri')
                if crit:
                    out.append(crit)
            for child in node.get('nodes') or []:
                walk(child)
            for child in node.get('children') or []:
                walk(child)

        if isinstance(configurations, list):
            for n in configurations:
                walk(n)
        elif isinstance(configurations, dict):
            walk(configurations)

        return out


    def build_metrics(cpes, feeds_dir, kev_set, include_years=True):
        target = set(cpes)
        stats = {
            cpe: {
                'totalCves': 0,
                'kevCves': 0,
                'maxCvss': None,
                'lastDate': None,
            } for cpe in cpes
        }

        # select feeds
        feed_files = []
        for fn in os.listdir(feeds_dir):
            if not fn.endswith('.json.gz'):
                continue
            if fn.startswith('nvdcve-2.0-modified') or fn.startswith('nvdcve-2.0-recent'):
                feed_files.append(fn)
            elif include_years and re.match(r'^nvdcve-2\.0-\d{4}\.json\.gz$', fn):
                feed_files.append(fn)

        feed_files = sorted(feed_files)
        if not feed_files:
            raise RuntimeError(f"No .json.gz feeds found in {feeds_dir}")

        for fn in feed_files:
            path = os.path.join(feeds_dir, fn)
            for cve in iter_feed_records(path):
                cve_id = (cve.get('id') or '').upper()
                conf = cve.get('configurations')
                if not conf:
                    continue
                cpe_list = extract_cpes_from_configurations(conf)
                if not cpe_list:
                    continue
                # intersect with target
                hits = target.intersection(cpe_list)
                if not hits:
                    continue

                max_cvss = extract_max_cvss(cve)
                dt = extract_date(cve)
                is_kev = cve_id in kev_set if cve_id else False

                for cpe in hits:
                    s = stats[cpe]
                    s['totalCves'] += 1
                    if is_kev:
                        s['kevCves'] += 1
                    if isinstance(max_cvss, (int, float)):
                        s['maxCvss'] = max_cvss if s['maxCvss'] is None else max(s['maxCvss'], max_cvss)
                    if dt:
                        if s['lastDate'] is None:
                            s['lastDate'] = dt
                        else:
                            try:
                                if datetime.datetime.fromisoformat(dt.replace('Z','+00:00')) > datetime.datetime.fromisoformat(s['lastDate'].replace('Z','+00:00')):
                                    s['lastDate'] = dt
                            except Exception:
                                # fallback string compare
                                if str(dt) > str(s['lastDate']):
                                    s['lastDate'] = dt

        return stats


    def main():
        ap = argparse.ArgumentParser()
        ap.add_argument('--cpe-csv', required=True, help='CSV contenant une colonne CPE')
        ap.add_argument('--feeds-dir', default='data/nvd', help='Répertoire des feeds .json.gz (nvd_mirror.py)')
        ap.add_argument('--out', default='data/cpe_metrics.json', help='Fichier JSON sortie')
        ap.add_argument('--kev-url', default=KEV_DEFAULT, help='URL du catalogue KEV (JSON)')
        ap.add_argument('--no-years', action='store_true', help='N'utiliser que modified+recent (plus rapide, moins complet)')
        args = ap.parse_args()

        cpes = read_cpe_list(args.cpe_csv)
        if not cpes:
            raise SystemExit('Aucun CPE trouvé dans le CSV (colonne contenant "cpe").')

        kev_set = load_kev_set(args.kev_url)
        stats = build_metrics(cpes, args.feeds_dir, kev_set, include_years=(not args.no_years))

        out_obj = {
            'meta': {
                'generated_at': datetime.datetime.utcnow().isoformat() + 'Z',
                'source': 'NVD JSON 2.0 feeds + CISA KEV',
                'feeds_dir': os.path.abspath(args.feeds_dir),
                'cpe_count': len(cpes),
                'kev_url': args.kev_url,
                'includes_year_feeds': (not args.no_years)
            },
            'risk_method': {
                'formula': 'risk_score = (CVSSmax × 10) + (#KEV × 25) + min(#CVE, 20)',
                'cvssMultiplier': 10,
                'kevWeight': 25,
                'cveCap': 20
            },
            'cpe_metrics': stats
        }

        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(out_obj, f, indent=2, ensure_ascii=False)
            f.write('
')

        print(f"OK. Écrit: {args.out} ({len(cpes)} CPE)")


    if __name__ == '__main__':
        main()
