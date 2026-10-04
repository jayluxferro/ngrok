package server

import (
	"bytes"
	"os"

	"gopkg.in/yaml.v3"
)

// serverConfig is the YAML config file as it appears on disk.
//
// The four rate limits are pointers so that "key absent" is distinguishable
// from "key set to 0": 0 means "disable this limit" to the server, while absent
// means "leave the flag default alone". With plain ints the two collapse into
// the same value, and the CLI could not tell whether the file had asked for
// anything -- see overrides.num in cli.go for what that cost.
type serverConfig struct {
	HttpAddr     string   `yaml:"http_addr"`
	HTTPSAddr    string   `yaml:"https_addr"`
	TunnelAddr   string   `yaml:"tunnel_addr"`
	QuicAddr     string   `yaml:"quic_addr"`
	AdminAddr    string   `yaml:"admin_addr"`
	AdminAuth    string   `yaml:"admin_auth"`
	AdminToken   string   `yaml:"admin_token"`
	AdminRate    *int     `yaml:"admin_rate"`
	Domain       string   `yaml:"domain"`
	TLSCrt       string   `yaml:"tls_crt"`
	TLSKey       string   `yaml:"tls_key"`
	LogTo        string   `yaml:"log"`
	LogLevel     string   `yaml:"log_level"`
	LogFormat    string   `yaml:"log_format"`
	AuthTokens   []string `yaml:"auth_tokens"`
	MaxMsgBytes  int64    `yaml:"max_msg_bytes"`
	AuthRate     *int     `yaml:"auth_rate"`
	PublicRate   *int     `yaml:"public_rate"`
	MaxConnPerIP *int     `yaml:"max_conn_per_ip"`
	EnablePprof  bool     `yaml:"pprof"`
}

func loadServerConfig(path string) (*serverConfig, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := new(serverConfig)
	// Strict decoding: a typo'd key (auth_tokens misspelled, a rate limit
	// nested one level too deep) silently leaves the server unprotected when
	// it is discarded -- the security-relevant fields here must either load
	// or fail the load.
	dec := yaml.NewDecoder(bytes.NewReader(buf))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
