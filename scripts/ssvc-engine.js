// js/ssvc-engine.js --> scripts/ssvc-engine.js
export const SSVC = (() => {

  // Decision point keys (official definitions in SSVC docs)
  // Exploitation: N (None), P (Public PoC), A (Active)  [3](https://certcc.github.io/SSVC/reference/decision_points/exploitation/)
  // System Exposure: S (Small), C (Controlled), O (Open) [4](https://certcc.github.io/SSVC/reference/decision_points/system_exposure/)
  // Technical Impact: P (Partial), T (Total)             [5](https://certcc.github.io/SSVC/reference/decision_points/technical_impact/)

  function normalizeInputs({ exploitation, exposure, techImpact }) {
    const e = (exploitation || "N").toUpperCase();
    const x = (exposure || "O").toUpperCase();     // if unknown -> Open recommended by SSVC doc [4](https://certcc.github.io/SSVC/reference/decision_points/system_exposure/)
    const ti = (techImpact || "P").toUpperCase();
    return { exploitation: e, exposure: x, techImpact: ti };
  }

  /**
   * Outcome sets:
   * - CISA Levels: Track, Track*, Attend, Act [7](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
   * - DSOI: Defer, Scheduled, Out-of-Cycle, Immediate [6](https://certcc.github.io/SSVC/reference/decision_points/outcomes/)
   *
   * NOTE: SSVC is intended to be customized; these default mappings are sensible,
   * but you should adapt them to your environment (assets, safety, prevalence, mitigations, etc.).
   */
  function decide(inputs) {
    const { exploitation, exposure, techImpact } = normalizeInputs(inputs);

    // ---- Simple, defensible baseline mapping (customizable) ----
    // Think of this as a “starter decision table”:
    //
    // 1) If exploitation is Active (A) AND exposure is Open (O) => Immediate / Act
    // 2) If exploitation is Active (A) and (Controlled/Small) => Out-of-Cycle / Act
    // 3) If Public PoC (P) and Open + Total => Out-of-Cycle / Attend
    // 4) If Public PoC (P) and Open + Partial => Scheduled / Attend
    // 5) If None (N) but Open + Total => Scheduled / Track*
    // 6) Otherwise => Defer/Track
    //
    // (These are “reasonable defaults”; for CISA’s full tree you’d add Automatable, Mission Prevalence,
    // Public Well-being Impact, Mitigation Status, etc. [9](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf)[7](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc))

    let dsoi = "D";  // Defer
    let cisa = "TRACK";

    if (exploitation === "A" && exposure === "O") {
      dsoi = "I"; // Immediate
      cisa = "ACT";
    } else if (exploitation === "A" && (exposure === "C" || exposure === "S")) {
      dsoi = "O"; // Out-of-Cycle
      cisa = "ACT";
    } else if (exploitation === "P" && exposure === "O" && techImpact === "T") {
      dsoi = "O";
      cisa = "ATTEND";
    } else if (exploitation === "P" && exposure === "O" && techImpact === "P") {
      dsoi = "S"; // Scheduled
      cisa = "ATTEND";
    } else if (exploitation === "N" && exposure === "O" && techImpact === "T") {
      dsoi = "S";
      cisa = "TRACK*";
    } else {
      dsoi = "D";
      cisa = "TRACK";
    }

    const labels = {
      DSOI: { D:"Defer", S:"Scheduled", O:"Out-of-Cycle", I:"Immediate" }, // [6](https://certcc.github.io/SSVC/reference/decision_points/outcomes/)
      CISA: { "TRACK":"Track", "TRACK*":"Track*", "ATTEND":"Attend", "ACT":"Act" } // [7](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
    };

    // Human-readable rationale for audit-proof decisions
    const rationale = [
      `Exploitation=${exploitation} (N=None, P=Public PoC, A=Active)`,
      `Exposure=${exposure} (S=Small, C=Controlled, O=Open)`,
      `TechnicalImpact=${techImpact} (P=Partial, T=Total)`,
      `→ Outcome: CISA=${labels.CISA[cisa]}, DSOI=${labels.DSOI[dsoi]}`
    ].join(" | ");

    return {
      inputs: { exploitation, exposure, techImpact },
      outcome: { dsoi, cisa, dsoiLabel: labels.DSOI[dsoi], cisaLabel: labels.CISA[cisa] },
      rationale
    };
  }

  return { decide, normalizeInputs };
})();
