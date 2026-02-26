// Ton dictionnaire de mapping (Top 25 simplifié)
const emb3dMapping = {
    "CWE-787": { tid: "T1.1", threat: "Memory Corruption", cat: "Application Software" },
    "CWE-121": { tid: "T1.1", threat: "Stack-based Buffer Overflow", cat: "Application Software" },
    "CWE-798": { tid: "T3.1", threat: "Hard-coded Credentials", cat: "System Software" },
    "CWE-20":  { tid: "T1.2", threat: "Inadequate Input Validation", cat: "Application Software" },
    "CWE-319": { tid: "T4.2", threat: "Cleartext Transmission", cat: "Networking" }
    // Ajoute les autres ici...
};

async function analyzeCVE() {
    const cveId = document.getElementById('cveInput').value.toUpperCase().trim();
    const resultDiv = document.getElementById('result');
    
    resultDiv.innerHTML = "Recherche en cours...";

    try {
        // 1. Appel à l'API NVD (NIST) pour obtenir le CWE lié à la CVE
        const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`);
        const data = await response.json();
        
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            const cveData = data.vulnerabilities[0].cve;
            // Extraction du premier CWE trouvé
            const cweId = cveData.weaknesses[0].description[0].value; 
            
            // 2. Pivot vers EMB3D
            const mapping = emb3dMapping[cweId];

            if (mapping) {
                renderResult(cveId, cweId, mapping);
            } else {
                resultDiv.innerHTML = `CVE trouvée (${cweId}), mais pas encore de mapping EMB3D spécifique.`;
            }
        } else {
            resultDiv.innerHTML = "CVE non trouvée.";
        }
    } catch (error) {
        resultDiv.innerHTML = "Erreur lors de la récupération des données.";
        console.error(error);
    }
}

function renderResult(cve, cwe, emb3d) {
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = `
        <div style="border: 1px solid #ccc; padding: 15px; border-radius: 8px;">
            <h3>Analyse pour ${cve}</h3>
            <p><strong>Faiblesse (CWE) :</strong> ${cwe}</p>
            <hr>
            <h4>🛡️ Menace EMB3D Associée</h4>
            <p><strong>ID :</strong> ${emb3d.tid}</p>
            <p><strong>Menace :</strong> ${emb3d.threat}</p>
            <p><strong>Catégorie :</strong> ${emb3d.cat}</p>
            <button onclick="window.open('https://emb3d.mitre.org/')">Voir remédiations sur EMB3D</button>
        </div>
    `;
}
