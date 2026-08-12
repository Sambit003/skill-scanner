//go:build parity

package agentskill

import (
	"encoding/json"
	"os"
	"time"
)

type parityTimings struct {
	path   string
	last   time.Time
	stages map[string]int64
}

func newParityTimings() *parityTimings {
	return &parityTimings{path: os.Getenv("SCAN_KERNEL_PARITY_STAGE_TIMING"), last: time.Now(), stages: map[string]int64{}}
}

func (value *parityTimings) mark(stage string) {
	now := time.Now()
	value.stages[stage] += now.Sub(value.last).Milliseconds()
	value.last = now
}

func (value *parityTimings) finish() {
	if value.path == "" {
		return
	}
	raw, err := json.MarshalIndent(map[string]any{"schema_version": 1, "stages_ms": value.stages}, "", "  ")
	if err == nil {
		_ = os.WriteFile(value.path, append(raw, '\n'), 0o644)
	}
}
