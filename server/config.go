package server

import (
	"os"

	"gopkg.in/yaml.v1"
)

type serverConfig struct {
	HttpAddr     string   `yaml:"http_addr"`
	HTTPSAddr    string   `yaml:"https_addr"`
	TunnelAddr   string   `yaml:"tunnel_addr"`
	AdminAddr    string   `yaml:"admin_addr"`
	AdminAuth    string   `yaml:"admin_auth"`
	AdminToken   string   `yaml:"admin_token"`
	AdminRate    int      `yaml:"admin_rate"`
	Domain       string   `yaml:"domain"`
	TLSCrt       string   `yaml:"tls_crt"`
	TLSKey       string   `yaml:"tls_key"`
	LogTo        string   `yaml:"log"`
	LogLevel     string   `yaml:"log_level"`
	LogFormat    string   `yaml:"log_format"`
	AuthTokens   []string `yaml:"auth_tokens"`
	MaxMsgBytes  int64    `yaml:"max_msg_bytes"`
	AuthRate     int      `yaml:"auth_rate"`
	PublicRate   int      `yaml:"public_rate"`
	MaxConnPerIP int      `yaml:"max_conn_per_ip"`
	EnablePprof  bool     `yaml:"pprof"`
}

func loadServerConfig(path string) (*serverConfig, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := new(serverConfig)
	if err := yaml.Unmarshal(buf, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
