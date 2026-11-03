// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

package prometheusremotewrite

import (
	"path/filepath"
	"testing"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusremotewriteexporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"

	"github.com/aws/amazon-cloudwatch-agent/internal/util/testutil"
	"github.com/aws/amazon-cloudwatch-agent/translator/translate/agent"
	"github.com/aws/amazon-cloudwatch-agent/translator/translate/otel/common"
)

func TestTranslator(t *testing.T) {
	agent.Global_Config.Region = "us-east-1"
	tt := NewTranslatorWithName("test")
	require.EqualValues(t, "prometheus_remote_write/test", tt.ID().String())

	testCases := map[string]struct {
		input   map[string]interface{}
		want    *confmap.Conf
		wantErr error
	}{
		"WithMissingDestination": {
			input: map[string]interface{}{
				"metrics": map[string]interface{}{
					"metrics_destinations": map[string]interface{}{},
				},
			},
			wantErr: &common.MissingKeyError{ID: tt.ID(), JsonKey: AMPSectionKey + " or " + common.ConfigKey(AMPSectionKey, common.WorkspaceIDKey)},
		},
		"WithMissingWorkspaceId": {
			input: map[string]interface{}{
				"metrics": map[string]interface{}{
					"metrics_destinations": map[string]interface{}{
						"amp": map[string]interface{}{},
					},
				},
			},
			wantErr: &common.MissingKeyError{ID: tt.ID(), JsonKey: AMPSectionKey + " or " + common.ConfigKey(AMPSectionKey, common.WorkspaceIDKey)},
		},
		"WithAMPDestination": {
			input: testutil.GetJson(t, filepath.Join("testdata", "config.json")),
			want:  testutil.GetConf(t, filepath.Join("testdata", "config.yaml")),
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			conf := confmap.NewFromStringMap(testCase.input)
			got, err := tt.Translate(conf)
			assert.Equal(t, testCase.wantErr, err)
			if err == nil {
				require.NotNil(t, got)
				gotCfg, ok := got.(*prometheusremotewriteexporter.Config)
				require.True(t, ok)
				// Expected = exporter defaults + the AMP-specific settings in testdata/config.yaml.
				wantCfg := prometheusremotewriteexporter.NewFactory().CreateDefaultConfig().(*prometheusremotewriteexporter.Config)
				require.NoError(t, testCase.want.Unmarshal(wantCfg))
				assert.Equal(t, wantCfg, gotCfg)
			}
		})
	}
}

func TestTranslatorDualStackEndpoint(t *testing.T) {
	tt := NewTranslatorWithName("dualstack-endpoint-test")

	testCases := map[string]struct {
		region           string
		workspaceID      string
		useDualStack     bool
		expectedEndpoint string
	}{
		"StandardEndpoint": {
			region:           "us-east-1",
			workspaceID:      "ws-12345678",
			useDualStack:     false,
			expectedEndpoint: "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678/api/v1/remote_write",
		},
		"DualStackEndpoint": {
			region:           "us-east-1",
			workspaceID:      "ws-12345678",
			useDualStack:     true,
			expectedEndpoint: "https://aps-workspaces.us-east-1.api.aws/workspaces/ws-12345678/api/v1/remote_write",
		},
		"DualStackEndpointEuWest1": {
			region:           "eu-west-1",
			workspaceID:      "ws-abcdefgh",
			useDualStack:     true,
			expectedEndpoint: "https://aps-workspaces.eu-west-1.api.aws/workspaces/ws-abcdefgh/api/v1/remote_write",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			agent.Global_Config.Region = testCase.region
			agent.Global_Config.UseDualStackEndpoint = testCase.useDualStack

			input := map[string]interface{}{
				"metrics": map[string]interface{}{
					"metrics_destinations": map[string]interface{}{
						"amp": map[string]interface{}{
							"workspace_id": testCase.workspaceID,
						},
					},
				},
			}

			conf := confmap.NewFromStringMap(input)
			got, err := tt.Translate(conf)
			require.NoError(t, err)
			require.NotNil(t, got)

			gotCfg, ok := got.(*prometheusremotewriteexporter.Config)
			require.True(t, ok)
			assert.Equal(t, testCase.expectedEndpoint, gotCfg.ClientConfig.Endpoint)
			assert.Equal(t, testCase.expectedEndpoint, gotCfg.HTTP.Endpoint)
		})
	}
}

// TestTranslatorHTTPBlockRoundTrip guards the exporter's nested http block: it takes precedence over the
// squashed client settings whenever "http" is present in the YAML, which the generated config always has.
// The AMP endpoint and SigV4 auth must therefore survive a marshal/unmarshal round trip inside it,
// otherwise remote write would target the factory's placeholder URL without signing.
func TestTranslatorHTTPBlockRoundTrip(t *testing.T) {
	agent.Global_Config.Region = "us-east-1"
	agent.Global_Config.UseDualStackEndpoint = false
	tt := NewTranslatorWithName("roundtrip")
	got, err := tt.Translate(confmap.NewFromStringMap(map[string]interface{}{
		"metrics": map[string]interface{}{
			"metrics_destinations": map[string]interface{}{
				"amp": map[string]interface{}{"workspace_id": "ws-12345678"},
			},
		},
	}))
	require.NoError(t, err)

	marshaled := confmap.New()
	require.NoError(t, marshaled.Marshal(got))
	require.True(t, marshaled.IsSet("http"))
	loaded := prometheusremotewriteexporter.NewFactory().CreateDefaultConfig().(*prometheusremotewriteexporter.Config)
	require.NoError(t, marshaled.Unmarshal(loaded))

	assert.Equal(t, "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678/api/v1/remote_write", loaded.HTTP.Endpoint)
	require.True(t, loaded.HTTP.Auth.HasValue())
	assert.Equal(t, common.SigV4Auth, loaded.HTTP.Auth.Get().AuthenticatorID.Type().String())
}
