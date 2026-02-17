let mapping = null;

const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const inputEl = document.getElementById("cweInput");
const searchBtn = document.getElementById("searchBtn");
const clearBtn = document.getElementById("clearBtn");

// Lien direct vers la fiche EMB3D (TID page)
function emb3dTidUrl(tid) {
  // Format : https://emb3d.mitre.org/threats/TID-xxx
  return `https://emb3d.mitre.org/threats/${encodeURIComponent(tid)}`;
}

function setStatus(msg) {
  statusEl.textContent = msg || "";
}

function clearResults() {
  resultsEl.innerHTML = "";
}

function normalizeCwe(value) {
  if (!value) return "";
  const v = value.trim().toUpperCase();
  // Accepte "119" → "CWE-119"
  if (/^\d+$/.test(v)) return `CWE-${v}`;
  return v;
}

async function loadMapping() {
  setStatus("Chargement du mapping CWE → TID…");
  try {
    const res = await fetch("./data/cwe_to_tid.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    mapping = await res.json();
    setStatus("Mapping chargé. Saisis une CWE et clique sur Rechercher.");
  } catch (e) {
    setStatus("Erreur : impossible de charger data/cwe_to_tid.json. Vérifie que GitHub Actions l’a généré.");
    console.error(e);
  }
}

function renderResults(cwe, tids) {
  clearResults();

  if (!tids || tids.length === 0) {
    resultsEl.innerHTML = `<div class="result-item">Aucun TID trouvé pour <code>${cwe}</code>.</div>`;
    return;
  }

  const items = tids.map(tid => {
    const url = emb3dTidUrl(tid);
    return `
      <div class="result-item">
        <strong>${tid}</strong>
        <div><a href="${url}" target="_blank" rel="noopener">Ouvrir la fiche EMB3D</a></div>
      </div>
    `;
  }).join("");

  resultsEl.innerHTML = `
    <div class="result-item">
      <div><strong>${tids.length}</strong> résultat(s) pour <code>${cwe}</code> :</div>
    </div>
    ${items}
  `;
}

function doSearch() {
  if (!mapping) {
    setStatus("Le mapping n’est pas encore chargé.");
    return;
  }

  const cwe = normalizeCwe(inputEl.value);
  if (!cwe) {
    setStatus("Entre une CWE (ex: CWE-119).");
    return;
  }

  const tids = mapping[cwe] || [];
  setStatus(`Recherche : ${cwe}`);
  renderResults(cwe, tids);
}

searchBtn.addEventListener("click", doSearch);
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") doSearch();
});
clearBtn.addEventListener("click", () => {
  inputEl.value = "";
  setStatus("Entrez une CWE pour lancer une recherche.");
  clearResults();
});

// Au chargement de la page
loadMapping();
