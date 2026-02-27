/* ================= CONFIG ================= */
const DEBUG = true;

/* ================= DEBUG ================= */
function log(msg){
  if(!DEBUG) return;
  const el=document.getElementById("logs");
  if(el.textContent==="—") el.textContent="";
  el.textContent+=`[${new Date().toLocaleTimeString()}] ${msg}\n`;
}
function setStatus(s){document.getElementById("status").textContent=s}

/* ================= EMB3D A completer ================= */
const emb3dMapping={
  "CWE-787":{tid:"T1.1",threat:"Memory Corruption",category:"App",iot:"RCE firmware"},
  "CWE-798":{tid:"T3.1",threat:"Hardcoded Credentials",category:"System",iot:"Root creds"},
  "CWE-295":{tid:"T4.3",threat:"MITM",category:"Network",iot:"TLS bypass"}
};

/* ================= ORCHESTRATION ================= */
async function runAnalysis(){
  const cveId=document.getElementById("cveInput").value.trim().toUpperCase();
  if(!/^CVE-\d{4}-\d{4,}$/.test(cveId)){alert("Format CVE invalide");return;}
  document.getElementById("runBtn").disabled=true;
  setStatus("Analyse en cours…");
  log(`Analyse ${cveId}`);

  try{
    const nvd=await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`).then(r=>r.json());
    const cve=nvd.vulnerabilities[0].cve;

    const desc=cve.descriptions.find(d=>d.lang==="fr")?.value||
               cve.descriptions.find(d=>d.lang==="en")?.value||"—";
    document.getElementById("desc").textContent=desc;

    const cvss3=cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const cvss4=cve.metrics?.cvssMetricV40?.[0]?.cvssData;

    document.getElementById("cvss3").textContent=cvss3?.baseScore??"—";
    document.getElementById("cvss3vec").textContent=cvss3?.vectorString??"—";
    document.getElementById("cvss4").textContent=cvss4?.baseScore??"—";
    document.getElementById("cvss4vec").textContent=cvss4?.vectorString??"—";

    const epss=await fetch(`https://api.first.org/data/v1/epss?cve=${cveId}`).then(r=>r.json());
    document.getElementById("epss").textContent=(epss.data[0].epss*100).toFixed(2)+"%";
    document.getElementById("epssPct").textContent="Percentile "+(epss.data[0].percentile*100).toFixed(0);

    const kev=await fetch("https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json").then(r=>r.json());
    const hit=kev.vulnerabilities.find(v=>v.cveID===cveId);
    document.getElementById("kev").textContent=hit?"Oui":"Non";
    document.getElementById("kevDate").textContent=hit?hit.dateAdded:"—";

    const cweList=[];
    (cve.weaknesses||[]).forEach(w=>w.description.forEach(d=>d.value.startsWith("CWE-")&&cweList.push(d.value)));
    document.getElementById("cwe").innerHTML="<ul>"+cweList.map(c=>`<li>${c}</li>`).join("")+"</ul>";

    const emb=cweList.find(c=>emb3dMapping[c]);
    if(emb){
      const m=emb3dMapping[emb];
      document.getElementById("emb3d-info").innerHTML=
        `<div class="emb3d-card"><b>${m.tid}</b> – ${m.threat}<br>${m.iot}</div>`;
    }

    setStatus("✅ Analyse terminée");
  }catch(e){
    log("ERREUR "+e.message);
    setStatus("Erreur");
  }finally{
    document.getElementById("runBtn").disabled=false;
  }
}
