VULNÉRABILITÉ IDENTIFIÉE
│
├── [Base_CVSS: <7] ──────────────────────────────────────────► TRACK
│
└── [Base_CVSS: >=7]
    │
    ├── [Exploitation: active]
    │   ├── [vehicle_sa-concerned: no] ────────────────────────► DISMISS
    │   └── [vehicle_sa-concerned: yes]
    │       ├── [Asset_criticity: Standard&unknown]
    │       │   ├── [System_exposure: none] ───────────────────► DISMISS
    │       │   └── [System_exposure: controlled/open] ────────► TRACK
    │       │
    │       └── [Asset_criticity: Strategic&critical]
    │           ├── [System_exposure: none] ───────────────────► DEFER
    │           ├── [System_exposure: controlled]
    │           │   ├── [Supplier: unresponsive/cooperative] ──► CyberAnalysis_required
    │           │   └── [Supplier: fix_ready] ─────────────────► Patch_shedule
    │           └── [System_exposure: open]
    │               ├── [Safety: Catastrophic] ────────────────► Patch_immediate
    │               ├── [Safety: critical]
    │               │   ├── [Technical: total] ────────────────► Patch_immediate
    │               │   └── [Technical: partial]
    │               │       ├── [Supplier: fix_ready] ───────► Patch_out-of-cycle
    │               │       ├── [Supplier: cooperative] ─────► Patch_shedule
    │               │       └── [Supplier: unresponsive] ────► CyberAnalysis_required
    │               └── [Safety: marginal]
    │                   ├── [Supplier: fix_ready] ─────────────► Patch_shedule
    │                   └── [Supplier: unresponsive/cooperative]► CyberAnalysis_required
    │
    ├── [Exploitation: poc]
    │   ├── [vehicle_sa-concerned: no] ────────────────────────► DISMISS
    │   └── [vehicle_sa-concerned: yes]
    │       └── [Asset_criticity: Strategic&critical]
    │           ├── [Safety: Catastrophic]
    │           │   ├── [Supplier: unresponsive/cooperative] ──► CyberAnalysis_required
    │           │   └── [Supplier: fix_ready] ─────────────────► Patch_shedule
    │           └── [Safety: critical/marginal/none] ──────────► TRACK
    │
    └── [Exploitation: none]
        ├── [vehicle_sa-concerned: no] ────────────────────────► DISMISS
        └── [vehicle_sa-concerned: yes]
            └── [Asset_criticity: Strategic&critical]
                ├── [System_exposure: none/controlled] ────────► TRACK
                └── [System_exposure: open]
                    ├── [Safety: Catastrophic/critical]
                    │   ├── [Supplier: fix_ready] ─────────────► Patch_shedule
                    │   ├── [Supplier: cooperative] ───────────► CyberAnalysis_required
                    │   └── [Supplier: unresponsive] ──────────► TRACK
                    └── [Safety: marginal/none] (non défini) ──► (Usage par défaut selon wiki)
