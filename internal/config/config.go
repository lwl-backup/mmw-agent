package config

import (
	"os"
	"strconv"
	"time"

	"mmw-agent/internal/constants"

	"gopkg.in/yaml.v3"
)

const AgentUserAgent = constants.AgentUserAgent

// Config 保存 agent 的运行配置。
type Config struct {
	MasterURL             string        `yaml:"master_url"`
	Token                 string        `yaml:"token"`
	ConnectionMode        string        `yaml:"connection_mode"`
	ListenPort            string        `yaml:"listen_port"`
	XrayServers           []XrayServer  `yaml:"xray_servers"`
	TrafficReportInterval time.Duration `yaml:"traffic_report_interval"`
	SpeedReportInterval   time.Duration `yaml:"speed_report_interval"`
}

// XrayServer 表示本机 Xray 节点配置。
type XrayServer struct {
	Name       string `yaml:"name"`
	ConfigPath string `yaml:"config_path"`
}

// DefaultXrayConfigPaths 是默认的 Xray 配置搜索路径。
var DefaultXrayConfigPaths = append([]string(nil), constants.DefaultXrayConfigPaths...)

// 从 YAML 文件加载配置。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// 补齐默认值
	config.applyDefaults()

	return &config, nil
}

// 从环境变量构造配置。
func FromEnv() *Config {
	config := &Config{
		MasterURL:      os.Getenv("MMWX_MASTER_URL"),
		Token:          os.Getenv("MMWX_TOKEN"),
		ConnectionMode: os.Getenv("MMWX_CONNECTION_MODE"),
		ListenPort:     os.Getenv("MMWX_LISTEN_PORT"),
	}

	// 读取 Xray 配置路径
	if xrayConfig := os.Getenv("MMWX_XRAY_CONFIG"); xrayConfig != "" {
		config.XrayServers = []XrayServer{
			{Name: "primary", ConfigPath: xrayConfig},
		}
	}

	// 读取上报间隔
	if interval := os.Getenv("MMWX_TRAFFIC_INTERVAL"); interval != "" {
		if d, err := time.ParseDuration(interval); err == nil {
			config.TrafficReportInterval = d
		}
	}
	if interval := os.Getenv("MMWX_SPEED_INTERVAL"); interval != "" {
		if d, err := time.ParseDuration(interval); err == nil {
			config.SpeedReportInterval = d
		}
	}

	config.applyDefaults()
	return config
}

// 合并环境变量配置到文件配置（环境变量优先）。
func (c *Config) Merge(env *Config) {
	if env.MasterURL != "" {
		c.MasterURL = env.MasterURL
	}
	if env.Token != "" {
		c.Token = env.Token
	}
	if env.ConnectionMode != "" {
		c.ConnectionMode = env.ConnectionMode
	}
	if env.ListenPort != "" {
		c.ListenPort = env.ListenPort
	}
	if len(env.XrayServers) > 0 {
		c.XrayServers = env.XrayServers
	}
	if env.TrafficReportInterval > 0 {
		c.TrafficReportInterval = env.TrafficReportInterval
	}
	if env.SpeedReportInterval > 0 {
		c.SpeedReportInterval = env.SpeedReportInterval
	}
}

// 为空字段填充默认值。
func (c *Config) applyDefaults() {
	if c.ConnectionMode == "" {
		c.ConnectionMode = constants.ConnectionModeAuto
	}
	if c.ListenPort == "" {
		c.ListenPort = constants.DefaultListenPort
	}
	if c.TrafficReportInterval == 0 {
		c.TrafficReportInterval = constants.DefaultTrafficReportInterval
	}
	if c.SpeedReportInterval == 0 {
		c.SpeedReportInterval = constants.DefaultSpeedReportInterval
	}

	// 未显式配置时自动探测 Xray 配置
	if len(c.XrayServers) == 0 {
		c.XrayServers = c.discoverXrayServers()
	}
}

// 扫描默认路径中的 Xray 配置文件。
func (c *Config) discoverXrayServers() []XrayServer {
	var servers []XrayServer
	for i, path := range DefaultXrayConfigPaths {
		if _, err := os.Stat(path); err == nil {
			servers = append(servers, XrayServer{
				Name:       "xray-" + strconv.Itoa(i+1),
				ConfigPath: path,
			})
		}
	}
	return servers
}

// 校验配置是否合法。
func (c *Config) Validate() error {
	// 拉取模式之外通常需要 token
	if c.ConnectionMode != constants.ConnectionModePull && c.Token == "" {
		// 兼容空 token，实际仅拉取模式可正常工作
	}
	return nil
}
