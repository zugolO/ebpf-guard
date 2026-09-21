package correlator

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.L, №419: инцидентный слой стоит НИЖЕ обогащения Rego (№418
// подаёт ему именно обогащённые алерты), значит alert.RuleID здесь — уже
// переименованное имя, которого нет ни в одном rules/*.yaml. Все три
// опознавательных чтения слоя ключуются на YAML-id и потому обязаны брать
// BaseRuleID(), как это уже сделано у сайленсера (№414) и агрегатора (№415);
// отчётный inc.RuleIDs при этом намеренно остаётся переименованным —
// решение (б) волны 6.3-rid.

func renameAlert(a types.Alert, baseRuleID, renamedRuleID string) types.Alert {
	a.RuleID = renamedRuleID
	if a.Details == nil {
		a.Details = map[string]interface{}{}
	}
	a.Details[types.BaseRuleIDDetailsKey] = baseRuleID
	return a
}

// Твёрдая улика: тег правила читается по базовому id. Иначе список доверенных
// юнитов начинает прощать container-escape/persistence ровно с того момента,
// как Rego включили.
func TestWave6_3L_HardEvidenceSurvivesRegoRename(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, []Rule{
		{ID: "container_escape_init_proc", Tags: []string{"container-escape"}},
	})

	base := makeAlert("container_escape_init_proc", 4242, "prod", types.SeverityCritical, time.Now())
	renamed := renameAlert(base, "container_escape_init_proc", "memfd_fileless_staging")

	assert.True(t, tr.isHardEvidence(renamed),
		"твёрдая улика обязана опознаваться по базовому имени, а не по имени решения Rego")
}

// Уникальность правил в счёте: девять базовых правил под одним именем Rego не
// вправе схлопываться в одно «уникальное правило» — это зеркало №415, только
// на стороне промоушена (недоподнятие вместо ложного повтора).
func TestWave6_3L_ScoringKeysOnBaseRuleID(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	now := time.Now()

	for i, id := range []string{"r1", "r2", "r3"} {
		a := makeAlert(id, 7777, "prod", types.SeverityCritical, now.Add(time.Duration(i)*time.Second))
		tr.Add(renameAlert(a, id, "dga_domain"))
	}

	incidents := tr.GetAll("prod", "", 0)
	require.Len(t, incidents, 1)

	scoring := 0
	tr.mu.RLock()
	for _, inc := range tr.open {
		scoring = len(inc.ScoringRuleIDs)
	}
	tr.mu.RUnlock()

	assert.Equal(t, 3, scoring,
		"три разных базовых правила под одним именем Rego — три уникальных правила в счёте, а не одно")
	assert.Equal(t, []string{"dga_domain"}, incidents[0].RuleIDs,
		"отчётный список правил остаётся на переименованном имени — решение (б) волны 6.3-rid")
}

// Прощение control-plane k3s (№262) не вправе выключаться от переименования:
// гейт называет YAML-id, а до него доезжает имя решения Rego.
func TestWave6_3L_K3sControlPlaneGateSurvivesRegoRename(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{9200: "/var/lib/rancher/k3s/data/abc123/bin/k3s"})

	before := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("granted"))
	alert := makeAlertWithComm(k8sKubectlAPIServerExecRuleID, 9200, "prod", types.SeverityWarning, time.Now(), "k3s-server")
	renamed := renameAlert(alert, k8sKubectlAPIServerExecRuleID, "k8s_token_access")

	assert.True(t, isK3sControlPlaneNetworkSignal(renamed),
		"переименование Rego не вправе отменять прощение control-plane трафика k3s")
	assert.Equal(t, before+1, testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("granted")),
		"попытка обязана быть записана в счётчик, а не потеряна на гейте имени")
}
