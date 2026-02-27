// js/decision-pdf.js
export function generateDecisionPdf({ evidence, ssvcDecision, userInputs, debugText }) {
  if (!window.jspdf?.jsPDF) {
    alert("jsPDF non disponible (CDN non chargé).");
    return;
  }
  const { jsPDF } = window.jspdf;
  const pdf = new jsPDF({ unit:"mm", format:"a4" });

  const wrap = (text, max=185) => pdf.splitTextToSize(String(text || ""), max);

  let y = 14;
  pdf.setFontSize(14);
  pdf.text("Kat‑Force — Decision Record (SSVC)", 10, y); y += 8;

  pdf.setFontSize(10);
  pdf.text(wrap(`CVE: ${evidence.cveId}`), 10, y); y += 6;
  pdf.text(wrap(`Generated: ${new Date().toLocaleString("fr-FR")}`), 10, y); y += 8;

  pdf.setFontSize(11);
  pdf.text("1) Evidence (signals)", 10, y); y += 6;
  pdf.setFontSize(10);

  const lines1 = [
    `CVSS v3: ${evidence.cvss3Score ?? "—"} ${evidence.cvss3Vector ? "(" + evidence.cvss3Vector + ")" : ""}`,
    `CVSS v4: ${evidence.cvss4Score ?? "—"} ${evidence.cvss4Vector ? "(" + evidence.cvss4Vector + ")" : ""}`,
    `EPSS: ${evidence.epssPct ?? "—"} (percentile: ${evidence.epssPercentile ?? "—"})`,
    `KEV: ${evidence.kevIn ? "Yes" : "No"} ${evidence.kevDate ? "(dateAdded: " + evidence.kevDate + ")" : ""}`,
    `System exposure (manual): ${userInputs.exposureLabel}`,
    `Technical impact (manual): ${userInputs.techImpactLabel}`
  ];
  lines1.forEach(l => { pdf.text(wrap(l), 12, y); y += 6; });

  y += 2;
  pdf.setFontSize(11);
  pdf.text("2) SSVC decision points", 10, y); y += 6;
  pdf.setFontSize(10);

  const dpLines = [
    `Exploitation: ${ssvcDecision.inputs.exploitation} (N=None, P=Public PoC, A=Active)`,
    `Exposure: ${ssvcDecision.inputs.exposure} (S=Small, C=Controlled, O=Open)`,
    `Technical Impact: ${ssvcDecision.inputs.techImpact} (P=Partial, T=Total)`
  ];
  dpLines.forEach(l => { pdf.text(wrap(l), 12, y); y += 6; });

  y += 2;
  pdf.setFontSize(11);
  pdf.text("3) Outcome", 10, y); y += 6;
  pdf.setFontSize(10);
  pdf.text(wrap(`CISA: ${ssvcDecision.outcome.cisaLabel} | DSOI: ${ssvcDecision.outcome.dsoiLabel}`), 12, y); y += 6;
  pdf.text(wrap(`Rationale: ${ssvcDecision.rationale}`), 12, y); y += 10;

  pdf.setFontSize(11);
  pdf.text("4) Notes / Debug", 10, y); y += 6;
  pdf.setFontSize(9);
  pdf.text(wrap(debugText || "—", 185), 12, y);

  pdf.save(`Decision_${evidence.cveId}.pdf`);
}
