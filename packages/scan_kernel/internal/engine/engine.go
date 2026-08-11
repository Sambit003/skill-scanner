package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type Registry struct {
	plugins map[string]model.AssetPlugin
	aliases map[string]string
}

func New(plugins ...model.AssetPlugin) *Registry {
	r := &Registry{plugins: map[string]model.AssetPlugin{}, aliases: map[string]string{}}
	for _, plugin := range plugins {
		descriptor := plugin.Descriptor()
		r.plugins[descriptor.ID] = plugin
		r.aliases[descriptor.ID] = descriptor.ID
		for _, alias := range descriptor.Aliases {
			r.aliases[alias] = descriptor.ID
		}
	}
	return r
}

func (r *Registry) PluginIDs() []string {
	ids := make([]string, 0, len(r.plugins))
	for id := range r.plugins {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (r *Registry) plugin(assetType string) (model.AssetPlugin, error) {
	id, ok := r.aliases[strings.ToLower(strings.TrimSpace(assetType))]
	if !ok {
		return nil, fmt.Errorf("no plugin compiled for asset type %q; enabled plugins: %v", assetType, r.PluginIDs())
	}
	return r.plugins[id], nil
}

func (r *Registry) Scan(ctx context.Context, request model.ScanRequest) (model.ScanResult, error) {
	plugin, err := r.plugin(request.AssetType)
	if err != nil {
		return model.ScanResult{}, err
	}
	return plugin.Scan(ctx, request)
}

func (r *Registry) Rules() []model.RuleDocument {
	byID := map[string]model.RuleDocument{}
	for _, plugin := range r.plugins {
		for _, rule := range plugin.Rules() {
			byID[rule.RuleID] = rule
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]model.RuleDocument, 0, len(ids))
	for _, id := range ids {
		out = append(out, byID[id])
	}
	return out
}

func (r *Registry) Rule(id string) (model.RuleDocument, bool) {
	for _, rule := range r.Rules() {
		if rule.RuleID == id {
			return rule, true
		}
	}
	return model.RuleDocument{}, false
}
