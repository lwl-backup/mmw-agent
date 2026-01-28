package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// XrayMetrics represents the metrics response from Xray's /debug/vars endpoint
type XrayMetrics struct {
	Stats *XrayStats `json:"stats,omitempty"`
}

// XrayStats contains inbound, outbound, and user traffic stats
type XrayStats struct {
	Inbound  map[string]TrafficData `json:"inbound,omitempty"`
	Outbound map[string]TrafficData `json:"outbound,omitempty"`
	User     map[string]TrafficData `json:"user,omitempty"`
}

// TrafficData contains uplink and downlink traffic in bytes
type TrafficData struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

// XrayConfig represents the structure of xray config.json for reading metrics port
type XrayConfig struct {
	Log       json.RawMessage `json:"log,omitempty"`
	DNS       json.RawMessage `json:"dns,omitempty"`
	API       json.RawMessage `json:"api,omitempty"`
	Stats     json.RawMessage `json:"stats,omitempty"`
	Policy    json.RawMessage `json:"policy,omitempty"`
	Routing   json.RawMessage `json:"routing,omitempty"`
	Inbounds  json.RawMessage `json:"inbounds,omitempty"`
	Outbounds json.RawMessage `json:"outbounds,omitempty"`
	Metrics   *MetricsConfig  `json:"metrics,omitempty"`
}

// MetricsConfig represents the metrics section in xray config
type MetricsConfig struct {
	Tag    string `json:"tag,omitempty"`
	Listen string `json:"listen,omitempty"` // Format: "127.0.0.1:38889"
}

// Collector collects traffic metrics from Xray servers
type Collector struct {
	httpClient         *http.Client
	defaultMetricsPort int
	defaultMetricsHost string
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		defaultMetricsPort: 38889,
		defaultMetricsHost: "127.0.0.1",
	}
}

// GetMetricsPortFromConfig reads the metrics port from xray config file
func (c *Collector) GetMetricsPortFromConfig(configPath string) (string, int, error) {
	if configPath == "" {
		return "127.0.0.1", c.defaultMetricsPort, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "127.0.0.1", c.defaultMetricsPort, fmt.Errorf("read config file: %w", err)
	}

	var config XrayConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return "127.0.0.1", c.defaultMetricsPort, fmt.Errorf("parse config file: %w", err)
	}

	if config.Metrics == nil || config.Metrics.Listen == "" {
		return "", 0, fmt.Errorf("metrics not configured in xray config")
	}

	// Parse listen address (format: "127.0.0.1:38889" or ":38889")
	listen := config.Metrics.Listen
	host := "127.0.0.1"
	var port int

	if strings.Contains(listen, ":") {
		parts := strings.Split(listen, ":")
		if len(parts) == 2 {
			if parts[0] != "" {
				host = parts[0]
			}
			p, err := strconv.Atoi(parts[1])
			if err != nil {
				return "", 0, fmt.Errorf("invalid metrics port: %s", parts[1])
			}
			port = p
		}
	} else {
		// Try to parse as port only
		p, err := strconv.Atoi(listen)
		if err != nil {
			return "", 0, fmt.Errorf("invalid metrics listen format: %s", listen)
		}
		port = p
	}

	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid metrics port: %d", port)
	}

	return host, port, nil
}

// FetchMetrics fetches metrics from Xray's /debug/vars endpoint
func (c *Collector) FetchMetrics(host string, port int) (*XrayMetrics, error) {
	url := fmt.Sprintf("http://%s:%d/debug/vars", host, port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var metrics XrayMetrics
	if err := json.Unmarshal(body, &metrics); err != nil {
		return nil, fmt.Errorf("unmarshal metrics: %w", err)
	}

	return &metrics, nil
}

// MergeStats merges source stats into dest stats
func MergeStats(dest, source *XrayStats) {
	if source == nil {
		return
	}
	if dest.Inbound == nil {
		dest.Inbound = make(map[string]TrafficData)
	}
	if dest.Outbound == nil {
		dest.Outbound = make(map[string]TrafficData)
	}
	if dest.User == nil {
		dest.User = make(map[string]TrafficData)
	}

	for k, v := range source.Inbound {
		dest.Inbound[k] = v
	}
	for k, v := range source.Outbound {
		dest.Outbound[k] = v
	}
	for k, v := range source.User {
		dest.User[k] = v
	}
}
