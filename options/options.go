package options

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// OptionsStruct holds configuration options.
type OptionsStruct struct {
	HostnameWhitelist []*regexp.Regexp `yaml:"hostname_whitelist"`
	HostnameBlacklist []*regexp.Regexp `yaml:"hostname_blacklist"`
	PortWhitelist     []string         `yaml:"port_whitelist"`
	PortBlacklist     []string         `yaml:"port_blacklist"`
	AllowTCPStreams   bool             `yaml:"allow_tcp_streams"`
	AllowUDPStreams   bool             `yaml:"allow_udp_streams"`
	StreamLimitTotal  int              `yaml:"stream_limit_total"`
	StreamLimitPerHost int              `yaml:"stream_limit_per_host"`
}

// Options holds the global configuration options.
var Options OptionsStruct

// LoadOptions loads configuration options from a YAML file.
func LoadOptions() error {
	optionsFile, err := os.ReadFile("options.yaml")
	if err != nil {
		return fmt.Errorf("failed to read options.yaml: %w", err)
	}

	if err := yaml.Unmarshal(optionsFile, &Options); err != nil {
		return fmt.Errorf("failed to unmarshal options: %w", err)
	}

	return nil
}

// compileRegexps compiles a slice of regular expression strings.
func compileRegexps(regexps []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(regexps))
	for _, r := range regexps {
		compiled = append(compiled, regexp.MustCompile(r))
	}
	return compiled
}