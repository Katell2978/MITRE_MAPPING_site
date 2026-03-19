Règles de décision (SSVC) Proposées
Les règles ci-dessous définissent le moteur de décision selon un modèle SSVC-compatible. La première règle correspondante est appliquée.

Rule ID	Source	CVSS Base score >= 7	Exploit	Vehicle concerned	ECU en surface d'attaque (sensible)	Safety Impact	Supplier Involvement	Decision	Justification
SSVC-ACT-FIX	Interne	yes	Active	yes	yes	yes	Fix-ready	Patch_immediate	Active + Safety yes + Fix-ready
SSVC-ACT-CA	Interne	yes	Active	yes	yes	yes	Cooperative/unresponsive	CyberAnalysisRequired	Active + Safety yes + Cooperative/unresponsive
SSVC-ACT-SAFETY-NO	Interne	yes	Active	yes	yes	No/unknown	*	CyberAnalysisRequired	Safety Impact No/unknown
SSVC-ACT-ECU-NO	Interne	yes	Active	yes	no	*	*	Track	Active + ECU pas en surface d'attaque
SSVC-ACT-VEH-NO	Interne	yes	Active	no	*	*	*	Dismiss	Vehicle not concerned
SSVC-POC-FIX	Interne	yes	Poc	yes	yes	*	Fix-ready	Patch_schedule	Poc + Fix-ready
SSVC-POC-ECU-NO	Interne	yes	Poc	yes	no	*	*	Track	Poc + ECU pas en surface d'attaque => track pour evaluer si exploit
SSVC-NONE-YES	Interne	yes	none	*	*	*	*	Track	Ni Poc no exploit => Track pour etre informé si exploit ou poc disponible
SSVC-POC-VEH-NO	Interne	yes	Poc	no	*	*	*	Dismiss	Poc + Vehicle concerned no
SSVC-CVSS-NO	Interne	No	*	*	*	*	*	Dismiss	CVSS Base score < 7
SSVC-EXT-VEH-YES	externe	*	*	yes	*	*	*	CyberAnalysisRequired	externe + Vehicle concerned yes
SSVC-EXT-VEH-NO	externe	*	*	no	*	*	*	Dismiss	externe + Vehicle concerned no
SSVC-POC-CA	Interne	yes	Poc	yes	yes	*	Cooperative/unresponsive	CyberAnalysisRequired	Poc + Cooperative/unresponsive
SSVC-DEFAULT	*	*	*	*	*	*	*	Track	Surveillance par défaut
