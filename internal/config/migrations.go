package config

// FieldTransform describes the kind of change applied to a configuration field.
type FieldTransform string

const (
	// TransformRename means the field was moved to a new dot-separated path.
	TransformRename FieldTransform = "rename"
	// TransformRemove means the field was removed with no direct equivalent.
	TransformRemove FieldTransform = "remove"
)

// FieldChange records a single breaking change to one configuration field.
type FieldChange struct {
	Field     string         // Dot-separated old field path (e.g. "profiler.ewma_weight")
	Transform FieldTransform
	NewField  string // New path for TransformRename (e.g. "profiler.ewma.weight")
	Since     string // Version that introduced this change
	Reason    string // Human-readable guidance shown in validate/migrate output
}

// Migration groups all field changes between two schema versions.
type Migration struct {
	From    string        // Source version prefix (e.g. "v0.1")
	To      string        // Target version (e.g. "v0.2.0")
	Changes []FieldChange
}

// Migrations is the ordered list of all known config schema migrations.
// Entries must be ordered oldest-to-newest; MigrateConfigFile applies them
// in sequence up to the requested target version.
var Migrations = []Migration{
	{
		From: "v0.1",
		To:   "v0.2.0",
		Changes: []FieldChange{
			{
				Field:     "profiler.ewma_weight",
				Transform: TransformRename,
				NewField:  "profiler.ewma.weight",
				Since:     "v0.2.0",
				Reason:    "EWMA settings were grouped under profiler.ewma.*",
			},
			{
				Field:     "alerting.webhook_url",
				Transform: TransformRemove,
				Since:     "v0.2.0",
				Reason:    "use alerting.alertmanager.url instead",
			},
		},
	},
}
