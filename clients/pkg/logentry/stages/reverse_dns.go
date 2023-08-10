package stages

import (
	"errors"
	"net"
	"reflect"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/common/model"
)

var (
	ErrEmptyRDNSLookupConfig      = errors.New("reverse_dns stage config cannot be empty")
	ErrEmptySourceRDNSStageConfig = errors.New("source cannot be empty")
)

// RDNSConfig represents Reverse DNS stage config
type RDNSConfig struct {
	Source *string `mapstructure:"source"`
}

func validateRDNSConfig(c RDNSConfig) error {
	if c.Source != nil && *c.Source == "" {
		return ErrEmptySourceRDNSStageConfig
	}
	return nil
}

func newRDNSStage(logger log.Logger, configs interface{}) (Stage, error) {
	cfgs := &RDNSConfig{}
	err := mapstructure.Decode(configs, cfgs)
	if err != nil {
		return nil, err
	}

	err = validateRDNSConfig(*cfgs)
	if err != nil {
		return nil, err
	}

	return &reverseDNSStage{
		logger: logger,
		cfgs:   cfgs,
	}, nil
}

type reverseDNSStage struct {
	logger log.Logger
	cfgs   *RDNSConfig
}

// Run implements Stage
func (g *reverseDNSStage) Run(in chan Entry) chan Entry {
	out := make(chan Entry)
	go func() {
		defer close(out)
		defer g.close()
		for e := range in {
			g.process(e.Labels, e.Extracted)
			out <- e
		}
	}()
	return out
}

// Name implements Stage
func (g *reverseDNSStage) Name() string {
	return StageTypeReverseDNS
}

func (g *reverseDNSStage) process(labels model.LabelSet, extracted map[string]interface{}) {
	var ip net.IP
	if g.cfgs.Source != nil {
		if _, ok := extracted[*g.cfgs.Source]; !ok {
			if Debug {
				level.Debug(g.logger).Log("msg", "source does not exist in the set of extracted values", "source", *g.cfgs.Source)
			}
			return
		}

		value, err := getString(extracted[*g.cfgs.Source])
		if err != nil {
			if Debug {
				level.Debug(g.logger).Log("msg", "failed to convert source value to string", "source", *g.cfgs.Source, "err", err, "type", reflect.TypeOf(extracted[*g.cfgs.Source]))
			}
			return
		}
		if value == "" {
			level.Debug(g.logger).Log("msg", "source was empty")
			return
		}
		ip = net.ParseIP(value)
		if ip == nil {
			level.Error(g.logger).Log("msg", "source is not an ip", "source", value)
			return
		}
	}
	// TODO: allow configuration to use a specific resolver
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		level.Debug(g.logger).Log("msg", "dns reverse lookup failed", "source", ip.String())
		return
	}
	if len(names) > 0 {
		hostnames := ""
		for i, name := range names {
			hostnames += normaliseHost(name)
			if i < len(names)-1 {
				hostnames += ";"
			}
		}
		labels[model.LabelName("hostnames")] = model.LabelValue(hostnames)
		extracted["hostnames"] = hostnames // WTF
	}
}

func (d *reverseDNSStage) close() {
	// NOP?
}

func normaliseHost(ptr string) string {
	return strings.TrimSuffix(ptr, ".")
}
