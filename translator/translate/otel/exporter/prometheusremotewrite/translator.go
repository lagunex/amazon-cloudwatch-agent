// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

package prometheusremotewrite

import (
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusremotewriteexporter"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configauth"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/exporter"

	"github.com/aws/amazon-cloudwatch-agent/translator/translate/agent"
	"github.com/aws/amazon-cloudwatch-agent/translator/translate/otel/common"
)

var (
	AMPSectionKey = common.ConfigKey(common.MetricsKey, common.MetricsDestinationsKey, common.AMPKey)
)

type translator struct {
	name    string
	factory exporter.Factory
}

var _ common.ComponentTranslator = (*translator)(nil)

func NewTranslator() common.ComponentTranslator {
	return NewTranslatorWithName("")
}

func NewTranslatorWithName(name string) common.ComponentTranslator {
	return &translator{name, prometheusremotewriteexporter.NewFactory()}
}

func (t *translator) ID() component.ID {
	return component.NewIDWithName(t.factory.Type(), t.name)
}

// Translate creates an exporter config based on the fields in the
// amp or prometheus section of the JSON config.
func (t *translator) Translate(conf *confmap.Conf) (component.Config, error) {
	if conf == nil || !(conf.IsSet(AMPSectionKey) && conf.IsSet(common.ConfigKey(AMPSectionKey, common.WorkspaceIDKey))) {
		return nil, &common.MissingKeyError{ID: t.ID(), JsonKey: AMPSectionKey + " or " + common.ConfigKey(AMPSectionKey, common.WorkspaceIDKey)}
	}
	cfg := t.factory.CreateDefaultConfig().(*prometheusremotewriteexporter.Config)
	cfg.HTTP.Auth = configoptional.Some(configauth.Config{AuthenticatorID: component.NewID(component.MustNewType(common.SigV4Auth))})
	// Copy every resource attribute onto the series and clear it afterwards. resource_constant_labels replaces the
	// deprecated resource_to_telemetry_conversion block; including "*" behaves exactly like its enabled mode.
	cfg.ResourceConstantLabels = resourcetotelemetry.Settings{Included: []string{"*"}, ClearAfterCopy: true}
	// Disable metric name type/unit suffixes (e.g. _total, _ratio) and otel_scope_* info labels to preserve backward-compatible AMP metrics.
	// The translation strategy replaces the deprecated add_metric_suffixes: false and yields the same names.
	cfg.TranslationStrategy = "UnderscoreEscapingWithoutSuffixes"
	cfg.DisableScopeInfo = true
	// ignoring bool return value since we are checking with isSet beforehand
	value, _ := common.GetString(conf, common.ConfigKey(AMPSectionKey, common.WorkspaceIDKey))
	domain := "amazonaws.com"
	if agent.Global_Config.UseDualStackEndpoint {
		domain = "api.aws"
	}
	ampEndpoint := "https://aps-workspaces." + agent.Global_Config.Region + "." + domain + "/workspaces/" + value + "/api/v1/remote_write"

	cfg.HTTP.Endpoint = ampEndpoint
	// The exporter sends with the nested http block, which takes precedence over the deprecated
	// squashed client settings whenever "http" is present in the YAML. The generated config always
	// contains it, so mirror the same settings into the squashed block to keep both paths identical.
	cfg.ClientConfig = cfg.HTTP
	return cfg, nil
}
