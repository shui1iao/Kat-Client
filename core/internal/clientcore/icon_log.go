package clientcore

import (
	"context"
	"github.com/shui1iao/Kat/internal/kernel"
	"time"
)

type iconExpectedKey struct{}
type iconGroupKey struct{}

func (h *Host) iconFailureFor(ctx context.Context, stage, category string) {
	if !iconLogStages[stage] || !iconLogCategories[category] {
		return
	}
	name, _ := ctx.Value(iconGroupKey{}).(string)
	h.logs.recordIcon(kernel.ClientLogEvent{Time: time.Now(), Level: "warn", Event: "icon_" + stage + "_failed", Code: category}, name)
}
