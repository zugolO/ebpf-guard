// Package profstage ставит метку pprof "stage" на горутину по стадии пути
// события и алерта (волна 8.7, заход Е1): CPU под пакетом атак раскладывается
// по стадиям средствами `go tool pprof -tagfocus=stage=…`, а не по именам
// функций. Метка — свойство горутины: Set заменяет метки, Clear их снимает.
//
// Цена: выключено — одна атомарная загрузка на вызов Set; включено — одна
// установка меток (контексты построены заранее, без аллокаций). Включается
// server.pprof_stage_labels вместе с enable_pprof, на боевом агенте не
// включается.
package profstage

import (
	"context"
	"runtime/pprof"
	"sync/atomic"
)

// Stage — стадия пути. Значения зафиксированы строками ниже: они попадают в
// профили и в таблицу plan.md.
type Stage uint8

const (
	StageNone Stage = iota
	// Сторона ядра → роутер.
	Collector      // чтение кольца, разбор, proc.args, передача роутеру
	CollectorRoute // раскладка событий коллектора по очередям protected/bulk (PriorityEventCollector)
	RouterLog      // запись event_dump/event log
	RouterEnrich   // k8s + runtime энричеры
	RouterMetrics  // счётчики событий по типам/подам/syscall
	RouterIngest   // раздача по воркерам (IngestAsyncPriority)
	RouterDrift    // детектор дрейфа
	RouterLoop     // цикл роутера между событиями: приём из очереди, возврат слота в пул
	// Воркер корреляции.
	IngestLoop   // цикл воркера между событиями: select по каналам, возраст события в очереди
	IngestPre    // самоисключение, lineage, буфер, частоты соединений
	Rules        // движок правил (метки event_type/rule_* ставит correlator)
	IngestPost   // WASM, IOC, постановка на Rego
	Anomaly      // EWMA профайлер и отчёт оценки
	Rego         // политики Rego
	RegoLoop     // цикл воркера Rego между задачами
	Incident     // слой инцидентов
	PendingFlush // слив локальной очереди алертов
	// Путь алерта после движка.
	DispatchMetrics // счётчики алертов, оси объёма
	DispatchAgg     // сайленс и агрегация
	DispatchEnforce // simple-mode энфорсер и симулятор
	DispatchStore   // стор алертов
	DispatchAM      // Alertmanager
	DispatchNotify  // Slack/Teams/webhook
	DispatchGossip  // gossip
	// Прочее.
	Enforcer    // очередь энфорсера
	HTTPMetrics // сбор /metrics
	HTTPAPI     // остальной HTTP API
	stageCount
)

var names = [stageCount]string{
	StageNone:       "none",
	Collector:       "collector",
	CollectorRoute:  "collector_route",
	RouterLog:       "router_log",
	RouterEnrich:    "router_enrich",
	RouterMetrics:   "router_metrics",
	RouterIngest:    "router_ingest",
	RouterDrift:     "router_drift",
	RouterLoop:      "router_loop",
	IngestLoop:      "ingest_loop",
	RegoLoop:        "rego_loop",
	IngestPre:       "ingest_pre",
	Rules:           "rules",
	IngestPost:      "ingest_post",
	Anomaly:         "anomaly",
	Rego:            "rego",
	Incident:        "incident",
	PendingFlush:    "pending_flush",
	DispatchMetrics: "dispatch_metrics",
	DispatchAgg:     "dispatch_agg",
	DispatchEnforce: "dispatch_enforce",
	DispatchStore:   "dispatch_store",
	DispatchAM:      "dispatch_alertmanager",
	DispatchNotify:  "dispatch_notify",
	DispatchGossip:  "dispatch_gossip",
	Enforcer:        "enforcer",
	HTTPMetrics:     "http_metrics",
	HTTPAPI:         "http_api",
}

// String — значение метки stage.
func (s Stage) String() string {
	if s < stageCount {
		return names[s]
	}
	return "unknown"
}

var (
	enabled atomic.Bool
	// ctxs[s] — контекст с меткой stage=<s>; заполняется при включении, до
	// публикации флага.
	ctxs [stageCount]atomic.Pointer[context.Context]
)

// Enable включает метки. Вызывать один раз при старте, до запуска горутин.
func Enable(on bool) {
	if on {
		for s := Stage(1); s < stageCount; s++ {
			ctx := pprof.WithLabels(context.Background(), pprof.Labels("stage", s.String()))
			ctxs[s].Store(&ctx)
		}
	}
	enabled.Store(on)
}

// Enabled — рантайм-состояние (читается экспортёром флагов).
func Enabled() bool { return enabled.Load() }

// Context возвращает контекст с меткой стадии (для pprof.WithLabels, чтобы
// добавить к ней другие метки) или фоновый, если метки выключены.
func Context(s Stage) context.Context {
	if p := ctxs[s%stageCount].Load(); p != nil {
		return *p
	}
	return context.Background()
}

// Set ставит метку стадии на текущую горутину. Заменяет прежние метки.
func Set(s Stage) {
	if !enabled.Load() || s >= stageCount {
		return
	}
	if p := ctxs[s].Load(); p != nil {
		pprof.SetGoroutineLabels(*p)
	}
}

// Clear снимает метки с текущей горутины.
func Clear() {
	if enabled.Load() {
		pprof.SetGoroutineLabels(context.Background())
	}
}
