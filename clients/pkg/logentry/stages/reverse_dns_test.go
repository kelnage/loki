package stages

import (
	"testing"

	util_log "github.com/grafana/loki/pkg/util/log"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

var logger = util_log.Logger

func Test_Reverse_DNS_process(t *testing.T) {
	type fields struct {
		cfgs *RDNSConfig
	}
	type args struct {
		labels    model.LabelSet
		extracted map[string]interface{}
	}
	field := "ip"
	defConf := RDNSConfig{
		Source: &field,
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		expected model.LabelSet
		wantErr  bool
	}{
		{
			"Google DNS server",
			fields{&defConf},
			args{
				labels: model.LabelSet{},
				extracted: map[string]interface{}{
					"ip": "8.8.8.8",
				},
			},
			model.LabelSet{
				model.LabelName("hostnames"): model.LabelValue("google.dns"),
			},
			false,
		},
		{
			"localhost",
			fields{&defConf},
			args{
				labels: model.LabelSet{},
				extracted: map[string]interface{}{
					"ip": "127.0.0.1",
				},
			},
			model.LabelSet{
				model.LabelName("hostnames"): model.LabelValue("localhost"),
			},
			false,
		},
		{
			"unresolvable",
			fields{&defConf},
			args{
				labels: model.LabelSet{},
				extracted: map[string]interface{}{
					"ip": "1.2.3.4",
				},
			},
			model.LabelSet{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &reverseDNSStage{
				logger: logger,
				cfgs:   tt.fields.cfgs,
			}
			g.process(tt.args.labels, tt.args.extracted)
			require.Equal(t, tt.expected, tt.args.labels)
		})
	}
}

var validDest = "destination"

func Test_validateRDNSConfig(t *testing.T) {
	type args struct {
		c RDNSConfig
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"valid source",
			args{
				RDNSConfig{
					Source: &validDest,
				},
			},
			false,
		},
		{
			"empty (nil) source",
			args{
				RDNSConfig{},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRDNSConfig(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("validateRDNSConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
