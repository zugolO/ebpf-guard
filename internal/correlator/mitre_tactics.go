package correlator

import "strings"

// MITRE ATT&CK tactic identifiers used for incident killchain-progress scoring.
// These are the canonical tactic names; rule tags are normalised into this
// vocabulary before they can contribute to tactic diversity.
const (
	tacticReconnaissance      = "reconnaissance"
	tacticResourceDevelopment = "resource-development"
	tacticInitialAccess       = "initial-access"
	tacticExecution           = "execution"
	tacticPersistence         = "persistence"
	tacticPrivilegeEscalation = "privilege-escalation"
	tacticDefenseEvasion      = "defense-evasion"
	tacticCredentialAccess    = "credential-access"
	tacticDiscovery           = "discovery"
	tacticLateralMovement     = "lateral-movement"
	tacticCollection          = "collection"
	tacticCommandAndControl   = "command-and-control"
	tacticExfiltration        = "exfiltration"
	tacticImpact              = "impact"
)

// tacticAliases maps free-form tactic spellings that appear in rule tags onto
// the canonical tactic names above. Only tags present in this table (or a
// resolvable mitre: technique tag) count towards tactic diversity — everything
// else in the tag vocabulary (sigma, owasp, aws, cloud, gtfobins, cve-*, …) is
// descriptive metadata, not a killchain stage, and must not inflate the score.
var tacticAliases = map[string]string{
	"reconnaissance": tacticReconnaissance,
	"recon":          tacticReconnaissance,

	"resource-development": tacticResourceDevelopment,
	"resource_development": tacticResourceDevelopment,

	"initial-access": tacticInitialAccess,
	"initial_access": tacticInitialAccess,
	"initialaccess":  tacticInitialAccess,

	"execution": tacticExecution,

	"persistence": tacticPersistence,

	"privilege-escalation": tacticPrivilegeEscalation,
	"privilege_escalation": tacticPrivilegeEscalation,
	"privesc":              tacticPrivilegeEscalation,

	"defense-evasion": tacticDefenseEvasion,
	"defense_evasion": tacticDefenseEvasion,
	"defence-evasion": tacticDefenseEvasion,
	"evasion":         tacticDefenseEvasion,

	"credential-access": tacticCredentialAccess,
	"credential_access": tacticCredentialAccess,
	"credential-theft":  tacticCredentialAccess,

	"discovery": tacticDiscovery,

	"lateral-movement": tacticLateralMovement,
	"lateral_movement": tacticLateralMovement,
	"lateral":          tacticLateralMovement,

	"collection": tacticCollection,

	"command-and-control": tacticCommandAndControl,
	"command_and_control": tacticCommandAndControl,
	"c2":                  tacticCommandAndControl,

	"exfiltration": tacticExfiltration,
	"exfil":        tacticExfiltration,

	"impact": tacticImpact,
}

// techniqueTactics maps a base MITRE technique ID (sub-technique suffix
// stripped) to its primary tactic. Covers every mitre: tag present in the
// bundled rule set; unknown techniques resolve to "" and are ignored rather
// than counted as a distinct tactic.
var techniqueTactics = map[string]string{
	// Reconnaissance
	"T1595": tacticReconnaissance,
	"T1592": tacticReconnaissance,

	// Resource development
	"T1583": tacticResourceDevelopment,
	"T1584": tacticResourceDevelopment,
	"T1588": tacticResourceDevelopment,
	"T1608": tacticResourceDevelopment,

	// Initial access
	"T1078": tacticInitialAccess,
	"T1133": tacticInitialAccess,
	"T1189": tacticInitialAccess,
	"T1190": tacticInitialAccess,
	"T1195": tacticInitialAccess,
	"T1199": tacticInitialAccess,
	"T1200": tacticInitialAccess,
	"T1566": tacticInitialAccess,

	// Execution
	"T1059": tacticExecution,
	"T1129": tacticExecution,
	"T1203": tacticExecution,
	"T1204": tacticExecution,
	"T1559": tacticExecution,
	"T1609": tacticExecution,
	"T1610": tacticExecution,
	"T1053": tacticExecution,
	"T1569": tacticExecution,

	// Persistence
	"T1098": tacticPersistence,
	"T1136": tacticPersistence,
	"T1176": tacticPersistence,
	"T1505": tacticPersistence,
	"T1525": tacticPersistence,
	"T1543": tacticPersistence,
	"T1546": tacticPersistence,
	"T1547": tacticPersistence,
	"T1554": tacticPersistence,
	"T1574": tacticPersistence,
	"T1037": tacticPersistence,
	"T1556": tacticPersistence,
	"T1542": tacticPersistence,

	// Privilege escalation
	"T1055": tacticPrivilegeEscalation,
	"T1068": tacticPrivilegeEscalation,
	"T1134": tacticPrivilegeEscalation,
	"T1484": tacticPrivilegeEscalation,
	"T1548": tacticPrivilegeEscalation,
	"T1611": tacticPrivilegeEscalation,

	// Defense evasion
	"T1006": tacticDefenseEvasion,
	"T1014": tacticDefenseEvasion,
	"T1027": tacticDefenseEvasion,
	"T1036": tacticDefenseEvasion,
	"T1070": tacticDefenseEvasion,
	"T1112": tacticDefenseEvasion,
	"T1140": tacticDefenseEvasion,
	"T1202": tacticDefenseEvasion,
	"T1216": tacticDefenseEvasion,
	"T1218": tacticDefenseEvasion,
	"T1222": tacticDefenseEvasion,
	"T1497": tacticDefenseEvasion,
	"T1535": tacticDefenseEvasion,
	"T1553": tacticDefenseEvasion,
	"T1562": tacticDefenseEvasion,
	"T1563": tacticDefenseEvasion,
	"T1564": tacticDefenseEvasion,
	"T1578": tacticDefenseEvasion,
	"T1599": tacticDefenseEvasion,
	"T1601": tacticDefenseEvasion,
	"T1620": tacticDefenseEvasion,
	"T1009": tacticDefenseEvasion,

	// Credential access
	"T1003": tacticCredentialAccess,
	"T1040": tacticCredentialAccess,
	"T1110": tacticCredentialAccess,
	"T1111": tacticCredentialAccess,
	"T1187": tacticCredentialAccess,
	"T1212": tacticCredentialAccess,
	"T1528": tacticCredentialAccess,
	"T1539": tacticCredentialAccess,
	"T1552": tacticCredentialAccess,
	"T1555": tacticCredentialAccess,
	"T1557": tacticCredentialAccess,
	"T1558": tacticCredentialAccess,
	"T1550": tacticCredentialAccess,
	"T1649": tacticCredentialAccess,

	// Discovery
	"T1007": tacticDiscovery,
	"T1010": tacticDiscovery,
	"T1016": tacticDiscovery,
	"T1018": tacticDiscovery,
	"T1033": tacticDiscovery,
	"T1046": tacticDiscovery,
	"T1049": tacticDiscovery,
	"T1057": tacticDiscovery,
	"T1069": tacticDiscovery,
	"T1082": tacticDiscovery,
	"T1083": tacticDiscovery,
	"T1087": tacticDiscovery,
	"T1518": tacticDiscovery,
	"T1613": tacticDiscovery,
	"T1580": tacticDiscovery,

	// Lateral movement
	"T1021": tacticLateralMovement,
	"T1072": tacticLateralMovement,
	"T1080": tacticLateralMovement,
	"T1210": tacticLateralMovement,
	"T1534": tacticLateralMovement,
	"T1570": tacticLateralMovement,
	"T1011": tacticLateralMovement,

	// Collection
	"T1005": tacticCollection,
	"T1039": tacticCollection,
	"T1056": tacticCollection,
	"T1074": tacticCollection,
	"T1113": tacticCollection,
	"T1114": tacticCollection,
	"T1115": tacticCollection,
	"T1119": tacticCollection,
	"T1213": tacticCollection,
	"T1530": tacticCollection,
	"T1560": tacticCollection,

	// Command and control
	"T1008": tacticCommandAndControl,
	"T1071": tacticCommandAndControl,
	"T1090": tacticCommandAndControl,
	"T1095": tacticCommandAndControl,
	"T1102": tacticCommandAndControl,
	"T1104": tacticCommandAndControl,
	"T1105": tacticCommandAndControl,
	"T1132": tacticCommandAndControl,
	"T1219": tacticCommandAndControl,
	"T1568": tacticCommandAndControl,
	"T1571": tacticCommandAndControl,
	"T1572": tacticCommandAndControl,
	"T1573": tacticCommandAndControl,
	"T1665": tacticCommandAndControl,

	// Exfiltration
	"T1020": tacticExfiltration,
	"T1029": tacticExfiltration,
	"T1030": tacticExfiltration,
	"T1041": tacticExfiltration,
	"T1048": tacticExfiltration,
	"T1052": tacticExfiltration,
	"T1567": tacticExfiltration,
	"T1537": tacticExfiltration,

	// Impact
	"T1485": tacticImpact,
	"T1486": tacticImpact,
	"T1489": tacticImpact,
	"T1490": tacticImpact,
	"T1491": tacticImpact,
	"T1495": tacticImpact,
	"T1496": tacticImpact,
	"T1498": tacticImpact,
	"T1499": tacticImpact,
	"T1531": tacticImpact,
	"T1561": tacticImpact,
	"T1565": tacticImpact,
}

// tacticForTag resolves a single rule tag to a canonical MITRE tactic name.
// Returns "" when the tag is not a tactic (the common case: descriptive tags
// such as sigma, owasp, cve-2021-44228, gtfobins, cloud, container-escape).
//
// Two tag forms resolve:
//   - "mitre:T1190" / "mitre:T1552.005" → tactic of the base technique
//   - a tactic name or a known alias ("privilege_escalation", "privesc", "c2")
func tacticForTag(tag string) string {
	t := strings.ToLower(strings.TrimSpace(tag))
	if t == "" {
		return ""
	}

	if rest, ok := strings.CutPrefix(t, "mitre:"); ok {
		return tacticForTechnique(rest)
	}
	if rest, ok := strings.CutPrefix(t, "attack."); ok {
		// Sigma-style "attack.privilege_escalation" / "attack.t1055".
		if tactic := tacticForTechnique(rest); tactic != "" {
			return tactic
		}
		t = rest
	}

	return tacticAliases[t]
}

// TacticsForTags resolves a rule's tags to the distinct canonical MITRE tactics
// they represent, preserving first-seen order. Tags that are descriptive rather
// than killchain stages (sigma, owasp, cve-*, …) resolve to nothing and are
// dropped, exactly as they are for incident scoring.
//
// Exported so the API can report per-rule tactics without callers having to
// reimplement the alias and technique tables — the dashboard's coverage view
// must agree with what the scorer actually counts.
func TacticsForTags(tags []string) []string {
	var out []string
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tactic := tacticForTag(tag)
		if tactic == "" {
			continue
		}
		if _, dup := seen[tactic]; dup {
			continue
		}
		seen[tactic] = struct{}{}
		out = append(out, tactic)
	}
	return out
}

// tacticForTechnique maps a (possibly sub-)technique ID such as "t1552.005"
// to its tactic. Returns "" for unknown or malformed IDs.
func tacticForTechnique(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if base, _, found := strings.Cut(id, "."); found {
		id = base
	}
	if len(id) < 2 || id[0] != 'T' {
		return ""
	}
	return techniqueTactics[id]
}
