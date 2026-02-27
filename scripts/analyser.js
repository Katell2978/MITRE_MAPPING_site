
  /// Enlever recherche EUVD pour l'instant //
/* ============================================================
   Utilitaire UI : log + statut
   - Centralise l’affichage d’état et les traces (debug rapide)
   ============================================================ */
function log(msg) {
  const el = document.getElementById("logs");
  if (el.textContent.trim() === "—") el.textContent = "";
  el.textContent += `[${new Date().toLocaleTimeString()}] ${msg}\n`;
  el.scrollTop = el.scrollHeight;
}
function setStatus(msg) {
  document.getElementById("status").textContent = msg;
}

/* ============================================================
   Utilitaire : fetch JSON robuste
   - Ajoute gestion d’erreurs et message clair dans les logs
   ============================================================ */
async function fetchJson(url, timeoutMs = 12000) {
 const ctrl = new AbortController();
 const t = setTimeout(() => ctrl.abort(), timeoutMs);
 let r;
 try {
   r = await fetch(url, { cache: "no-store", signal: ctrl.signal });
 } catch (e) {
   clearTimeout(t);
   throw new Error(`FETCH échoué sur ${url} : ${e.name || e}`);
 }
 clearTimeout(t);
 if (!r.ok) {
   const txt = await r.text().catch(() => "");
   throw new Error(`HTTP ${r.status} sur ${url} ${txt.slice(0,120)}`);
 }
 return r.json();
}

/* ============================================================
   Récupération NVD (Internet)
   - Source : description + CVSS (v3/v4) + CWE + références
   ============================================================ */
async function fetchNvdCve(cveId) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
  return fetchJson(url);
}

/* ============================================================
   Récupération EPSS FIRST (Internet)
   - Score EPSS + percentile (si dispo)
   ============================================================ */
async function fetchEpss(cveId) {
  const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`;
  const data = await fetchJson(url);
  const rec = (data && data.data && data.data.length) ? data.data[0] : null;
  return {
    epss: rec?.epss ? parseFloat(rec.epss) : null,
    percentile: rec?.percentile ? parseFloat(rec.percentile) : null
  };
}

/* ============================================================
   Récupération KEV CISA (Internet)
   - Source officielle CISA via mirror GitHub (CORS OK)
   ============================================================ */
async function fetchKevStatus(cveId) {
  const url = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
  const kev = await fetchJson(url);
  const list = kev?.vulnerabilities || [];
  const hit = list.find(v => v?.cveID === cveId);
  return {
    inKev: !!hit,
    dateAdded: hit?.dateAdded || null
  };
}

/* ============================================================
   Chargement base CWE→CAPEC (Internet)
   - Base publique du projet CVE2CAPEC (Galeax)
   ============================================================ */
async function loadCweDb() {
  const cacheKey = "CWE_DB_V1";
  const cached = sessionStorage.getItem(cacheKey);
  if (cached) return JSON.parse(cached);
  const url = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/resources/cwe_db.json";
  const db = await fetchJson(url);
  sessionStorage.setItem(cacheKey, JSON.stringify(db));
  return db;
}

/* ============================================================
   Chargement base CAPEC (Internet)
   - Base publique du projet CVE2CAPEC (Galeax)
   ============================================================ */
async function loadCapecDb() {
  const cacheKey = "CAPEC_DB_V1";
  const cached = sessionStorage.getItem(cacheKey);
  if (cached) return JSON.parse(cached);
  const url = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/resources/capec_db.json";
  const db = await fetchJson(url);
  sessionStorage.setItem(cacheKey, JSON.stringify(db));
  return db;
}

/* ============================================================
   Mapping CWE → CAPEC
   - Extrait RelatedAttackPatterns et dé-duplique
   ============================================================ */
function mapCweToCapecIds(cweList, cweDb) {
  const out = new Set();
  (cweList || []).forEach(cwe => {
    const entry = cweDb?.[cwe];
    const capecs = entry?.RelatedAttackPatterns || [];
    capecs.forEach(id => out.add(id));
  });
  return Array.from(out);
}

/* ============================================================
   Détails CAPEC
   - Récupère le nom associé à chaque CAPEC ID
   ============================================================ */
function capecDetails(capecIds, capecDb) {
  return (capecIds || []).map(id => {
    const entry = capecDb?.[String(id)] || capecDb?.[id] || {};
    const name = entry?.name || entry?.Name || "CAPEC";
    return { id: String(id), name };
  });
}

/* ============================================================
   Extraction CVSS (v3 & v4) depuis NVD
   - NVD renvoie cvssMetricV31 / V30 / V40
   ============================================================ */
function extractCvss(nvdItem) {
  const metrics = nvdItem?.cve?.metrics || {};
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const cvss3 = v31 || v30 || null;
  const cvss4 = metrics.cvssMetricV40?.[0]?.cvssData || null;
  return { cvss3, cvss4 };
}

/* ============================================================
   Bandeau : conditions d’exploitation + impacts (CIA v3)
   - Conditions exploitabilité: AV/AC/PR/UI/S
   - Impacts v3: C/I/A
   ============================================================ */
function buildExploitConditionsPills(cvss3, cvss4, kev) {
  const pills = [];

  // Conditions (v3 prioritaire)
  if (cvss3) {
    if (cvss3.attackVector) pills.push({ cls:"", k:"AV", v: cvss3.attackVector });
    if (cvss3.attackComplexity) pills.push({ cls:"", k:"AC", v: cvss3.attackComplexity });
    if (cvss3.privilegesRequired) pills.push({ cls:"", k:"PR", v: cvss3.privilegesRequired });
    if (cvss3.userInteraction) pills.push({ cls:"", k:"UI", v: cvss3.userInteraction });
    if (cvss3.scope) pills.push({ cls:"", k:"S", v: cvss3.scope });

    // Impacts CIA (v3 demandé)
    if (cvss3.confidentialityImpact) pills.push({ cls:"warn", k:"C", v: cvss3.confidentialityImpact });
    if (cvss3.integrityImpact) pills.push({ cls:"warn", k:"I", v: cvss3.integrityImpact });
    if (cvss3.availabilityImpact) pills.push({ cls:"warn", k:"A", v: cvss3.availabilityImpact });
  } else if (cvss4) {
    // fallback v4 pour conditions si v3 absent
    if (cvss4.attackVector) pills.push({ cls:"", k:"AV", v: cvss4.attackVector });
    if (cvss4.attackComplexity) pills.push({ cls:"", k:"AC", v: cvss4.attackComplexity });
    if (cvss4.attackRequirements) pills.push({ cls:"", k:"AT", v: cvss4.attackRequirements });
    if (cvss4.privilegesRequired) pills.push({ cls:"", k:"PR", v: cvss4.privilegesRequired });
    if (cvss4.userInteraction) pills.push({ cls:"", k:"UI", v: cvss4.userInteraction });
  }

  // Statut KEV
  if (kev?.inKev) pills.push({ cls:"crit", k:"KEV", v: "Oui" });
  else pills.push({ cls:"", k:"KEV", v: "Non" });
  return pills;
}

/* ============================================================
   Détection Remote exploitable (visuel)
   - Basée sur AV=NETWORK (v3 ou v4)
   ============================================================ */
function isRemote(cvss3, cvss4) {
  const av3 = (cvss3?.attackVector || "").toString().toUpperCase();
  const av4 = (cvss4?.attackVector || "").toString().toUpperCase();
  return av3 === "NETWORK" || av4 === "NETWORK";
}

/* ============================================================
   Rendu UI centralisé
   - Met à jour scores, badges, bandeau, CWE/CAPEC, refs
   ============================================================ */
function renderResults({ cveId, description, cvss3, cvss4, epss, epssPct, cweList, capecList, refs, kev }) {
  // Description
  document.getElementById("desc").textContent = description || "—";

  // CVSS v3
  const cvss3Score = cvss3?.baseScore ?? null;
  const cvss3Vec = cvss3?.vectorString ?? null;
  document.getElementById("cvss3").textContent = (cvss3Score !== null) ? cvss3Score : "—";
  document.getElementById("cvss3vec").textContent = cvss3Vec || "—";

  // CVSS v4
  const cvss4Score = cvss4?.baseScore ?? null;
  const cvss4Vec = cvss4?.vectorString ?? null;
  document.getElementById("cvss4").textContent = (cvss4Score !== null) ? cvss4Score : "—";
  document.getElementById("cvss4vec").textContent = cvss4Vec || "—";

  // EPSS
  if (typeof epss === "number") document.getElementById("epss").textContent = `${(epss * 100).toFixed(2)}%`;
  else document.getElementById("epss").textContent = "—";
  document.getElementById("epssPct").textContent =
    (typeof epssPct === "number") ? `Percentile : ${(epssPct * 100).toFixed(0)}e` : "Percentile : —";

  // KEV
  document.getElementById("kev").textContent = kev?.inKev ? "Oui" : "Non";
  document.getElementById("kevDate").textContent = kev?.inKev
    ? `Date ajout : ${kev.dateAdded || "—"}`
    : "—";


  // Badges
  const badges = [];
  badges.push(`<span class="badge bg-info">${cveId}</span>`);
  if (isRemote(cvss3, cvss4)) badges.push(`<span class="badge bg-warn">REMOTE exploitable</span>`);
  if (kev?.inKev) badges.push(`<span class="badge bg-bad">KEV</span>`);  if (typeof epss === "number" && epss >= 0.20) badges.push(`<span class="badge bg-bad">EPSS élevé</span>`);
  if (typeof cvss3Score === "number" && cvss3Score >= 9.0) badges.push(`<span class="badge bg-bad">CVSS v3 Critique</span>`);
  if (typeof cvss4Score === "number" && cvss4Score >= 9.0) badges.push(`<span class="badge bg-bad">CVSS v4 Critique</span>`);
  document.getElementById("badges").innerHTML = badges.join(" ") || "—";

  // Bandeau conditions d’exploitation + impacts CIA
  const pills = buildExploitConditionsPills(cvss3, cvss4, kev);
  const banner = document.getElementById("exploitBanner");
  const pillBox = document.getElementById("exploitPills");
  banner.style.display = pills.length ? "block" : "none";
  pillBox.innerHTML = pills.map(p => `<span class="pill ${p.cls || ""}">${p.k}: ${p.v}</span>`).join("");

  // CWE
  if (cweList && cweList.length) {
    document.getElementById("cwe").innerHTML =
      `<ul>${cweList.map(c =>
        `<li><span class="mono">${c}</span> — <a target="_blank" href="https://cwe.mitre.org/data/definitions/${c.replace('CWE-','')}.html">MITRE CWE</a></li>`
      ).join("")}</ul>`;
  } else {
    document.getElementById("cwe").textContent = "—";
  }

  // CAPEC
  if (capecList && capecList.length) {
    document.getElementById("capec").innerHTML =
      `<ul>${capecList.map(c =>
        `<li><span class="mono">CAPEC-${c.id}</span> — ${c.name} — <a target="_blank" href="https://capec.mitre.org/data/definitions/${c.id}.html">CAPEC</a></li>`
      ).join("")}</ul>`;
  } else {
    document.getElementById("capec").textContent = "—";
  }

  // Références
  if (refs && refs.length) {
    document.getElementById("refs").innerHTML =
      `<ul>${refs.map(u => `<li><a target="_blank" rel="noopener" href="${u}">${u}</a></li>`).join("")}</ul>`;
  } else {
    document.getElementById("refs").textContent = "—";
  }
}
