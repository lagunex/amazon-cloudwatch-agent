// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

package prometheus

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver/targetallocator"
	promconfig "github.com/prometheus/prometheus/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/confmap"

	"github.com/aws/amazon-cloudwatch-agent/internal/util/testutil"
)

// loadPromConfig loads a Prometheus YAML config file through promconfig.Load()
// so that all defaults (MetricNameValidationScheme, ScrapeNativeHistograms, etc.)
// are populated the same way the translator's Reload() populates them.
func loadPromConfig(t *testing.T, path string) *promconfig.Config {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	cfg, err := promconfig.Load(string(content), nil)
	require.NoError(t, err)
	return cfg
}

func TestTranslator(t *testing.T) {
	testCases := map[string]struct {
		input   map[string]any
		wantID  string
		wantTA  configoptional.Optional[targetallocator.Config]
		wantErr error
		// promYAML is the path to the raw Prometheus YAML used to build expected
		// GlobalConfig and ScrapeConfigs via promconfig.Load(). This ensures the
		// expected values include all Prometheus defaults (populated by Load/Reload).
		promYAML string
	}{
		"WithOtelConfig": {
			input:    testutil.GetJson(t, filepath.Join("testdata", "config.json")),
			wantID:   "prometheus",
			promYAML: filepath.Join("testdata", "config_prom.yaml"), // same scrape content, just without OTel wrapper
			wantTA: func() configoptional.Optional[targetallocator.Config] {
				// Start from the receiver defaults (the target allocator HTTP client now carries
				// keepalive and HTTP/2 defaults), apply the collector_id from the input YAML the
				// same way the translator does, then the TLS defaults the translator adds.
				ta := defaultTargetAllocator()
				require.NoError(t, confmap.NewFromStringMap(map[string]any{"collector_id": "col-1234"}).Unmarshal(&ta))
				cfg := ta.Get()
				cfg.ClientConfig.TLS.CAFile = defaultTLSCaPath
				cfg.ClientConfig.TLS.CertFile = defaultTLSCertPath
				cfg.ClientConfig.TLS.KeyFile = defaultTLSKeyPath
				cfg.ClientConfig.TLS.ReloadInterval = 10 * time.Second
				return ta
			}(),
		},
		"WithPromConfig": {
			input:    testutil.GetJson(t, filepath.Join("testdata", "config_prom.json")),
			wantID:   "prometheus",
			promYAML: filepath.Join("testdata", "config_prom.yaml"),
			wantTA:   defaultTargetAllocator(),
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			tt := NewTranslator()
			assert.EqualValues(t, testCase.wantID, tt.ID().String())
			conf := confmap.NewFromStringMap(testCase.input)
			got, err := tt.Translate(conf)
			assert.Equal(t, testCase.wantErr, err)
			if err == nil {
				require.NotNil(t, got)
				gotCfg, ok := got.(*prometheusreceiver.Config)
				require.True(t, ok)

				// Build expected Prometheus config by loading the same YAML through
				// promconfig.Load(), which populates all defaults identically to
				// the translator's Reload() path.
				wantPromCfg := loadPromConfig(t, testCase.promYAML)
				assert.Equal(t, wantPromCfg.ScrapeConfigs, gotCfg.PrometheusConfig.ScrapeConfigs)
				assert.Equal(t, wantPromCfg.GlobalConfig, gotCfg.PrometheusConfig.GlobalConfig)
				assert.Equal(t, testCase.wantTA, gotCfg.TargetAllocator)
			}
		})
	}
}

// defaultTargetAllocator returns the receiver's default (unset) target allocator configuration.
func defaultTargetAllocator() configoptional.Optional[targetallocator.Config] {
	return prometheusreceiver.NewFactory().CreateDefaultConfig().(*prometheusreceiver.Config).TargetAllocator
}
