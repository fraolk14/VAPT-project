package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"vap-agent/internal/collector"
)

type Config struct {
	BackendURL      string `json:"backend_url"`
	DeviceID        string `json:"device_id"`
	AgentKey        string `json:"agent_key"`
	EnrollmentToken string `json:"enrollment_token"`
	CheckinInterval int    `json:"checkin_interval_sec"`
}

type AgentClient struct {
	cfg        Config
	httpClient *http.Client
}

func NewAgentClient(cfg Config) *AgentClient {
	if cfg.BackendURL == "" {
		cfg.BackendURL = "http://localhost:18080"
	}
	return &AgentClient{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// LoadConfigFromRegistry retrieves BackendURL, DeviceID, and AgentKey from Registry HKLM\SOFTWARE\VAP\Agent or config.json
func LoadConfigFromRegistry() (Config, error) {
	var cfg Config
	cfg.BackendURL = "http://localhost:18080"
	cfg.CheckinInterval = 14400

	// 1. Try Registry
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\VAP\Agent`, registry.QUERY_VALUE)
	if err == nil {
		url, _, _ := k.GetStringValue("BackendURL")
		deviceID, _, _ := k.GetStringValue("DeviceID")
		agentKey, _, _ := k.GetStringValue("AgentKey")
		token, _, _ := k.GetStringValue("EnrollmentToken")
		k.Close()

		if url != "" {
			cfg.BackendURL = url
		}
		if deviceID != "" {
			cfg.DeviceID = deviceID
		}
		if agentKey != "" {
			cfg.AgentKey = agentKey
		}
		if token != "" {
			cfg.EnrollmentToken = token
		}
		if cfg.AgentKey != "" {
			return cfg, nil
		}
	}

	// 2. Fallback to config.json
	exePath, err := os.Executable()
	if err == nil {
		jsonPath := filepath.Join(filepath.Dir(exePath), "config.json")
		data, err := os.ReadFile(jsonPath)
		if err == nil {
			var jsonCfg Config
			if err := json.Unmarshal(data, &jsonCfg); err == nil {
				if jsonCfg.BackendURL != "" {
					cfg.BackendURL = jsonCfg.BackendURL
				}
				if jsonCfg.DeviceID != "" {
					cfg.DeviceID = jsonCfg.DeviceID
				}
				if jsonCfg.AgentKey != "" {
					cfg.AgentKey = jsonCfg.AgentKey
				}
				if jsonCfg.EnrollmentToken != "" {
					cfg.EnrollmentToken = jsonCfg.EnrollmentToken
				}
			}
		}
	}

	return cfg, nil
}

// SaveConfigToRegistry persists DeviceID, AgentKey, and BackendURL to Registry or config.json
func SaveConfigToRegistry(cfg Config) error {
	var regErr error
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\VAP\Agent`, registry.ALL_ACCESS)
	if err == nil {
		_ = k.SetStringValue("BackendURL", cfg.BackendURL)
		_ = k.SetStringValue("DeviceID", cfg.DeviceID)
		_ = k.SetStringValue("AgentKey", cfg.AgentKey)
		_ = k.SetStringValue("EnrollmentToken", cfg.EnrollmentToken)
		k.Close()
	} else {
		regErr = err
	}

	// Save to config.json as fallback
	exePath, err := os.Executable()
	if err == nil {
		jsonPath := filepath.Join(filepath.Dir(exePath), "config.json")
		data, _ := json.MarshalIndent(cfg, "", "  ")
		_ = os.WriteFile(jsonPath, data, 0600)
	}

	return regErr
}

// Enroll performs single-use token bootstrap trust enrollment with backend
func (c *AgentClient) Enroll(token string, backendURL string) error {
	if backendURL != "" {
		c.cfg.BackendURL = backendURL
	}
	hostname, _ := os.Hostname()

	reqBody := map[string]string{
		"token":       token,
		"hostname":    hostname,
		"hardware_id": hostname,
		"os_info":     "Windows Endpoint",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	enrollURL := strings.TrimRight(c.cfg.BackendURL, "/") + "/api/agent/enroll"
	resp, err := c.httpClient.Post(enrollURL, "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("enrollment HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respData, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment rejected (Status %d): %s", resp.StatusCode, string(respData))
	}

	var enrollResult struct {
		DeviceID   string `json:"device_id"`
		AgentKey   string `json:"agent_key"`
		IntervalSec int   `json:"checkin_interval_sec"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&enrollResult); err != nil {
		return fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	c.cfg.DeviceID = enrollResult.DeviceID
	c.cfg.AgentKey = enrollResult.AgentKey
	c.cfg.EnrollmentToken = token
	if enrollResult.IntervalSec > 0 {
		c.cfg.CheckinInterval = enrollResult.IntervalSec
	}

	if err := SaveConfigToRegistry(c.cfg); err != nil {
		fmt.Printf("Warning: Failed to write registry credentials: %v\n", err)
	}

	fmt.Printf("Enrollment Successful! DeviceID: %s\n", c.cfg.DeviceID)
	return nil
}

// PerformCheckin collects asset properties, misconfigurations, and shadow IT signals and posts to checkin endpoint
func (c *AgentClient) PerformCheckin() error {
	if c.cfg.AgentKey == "" || c.cfg.DeviceID == "" {
		return fmt.Errorf("agent is not enrolled yet. Run enrollment first")
	}

	assetPayload, softwareList, err := collector.CollectAssetProperties()
	if err != nil {
		return fmt.Errorf("asset collection error: %w", err)
	}

	misconfigs, err := collector.CollectMisconfigurations()
	if err != nil {
		return fmt.Errorf("misconfiguration collection error: %w", err)
	}

	shadowITFlags, err := collector.CollectShadowITSignals(softwareList)
	if err != nil {
		return fmt.Errorf("shadow IT collection error: %w", err)
	}

	checkinData := map[string]interface{}{
		"agent_id":          c.cfg.DeviceID,
		"collected_at":      time.Now().UTC().Format(time.RFC3339),
		"asset":             assetPayload,
		"software_inventory": softwareList,
		"misconfigurations": misconfigs,
		"shadow_it_flags":   shadowITFlags,
	}

	bodyBytes, err := json.Marshal(checkinData)
	if err != nil {
		return fmt.Errorf("failed to marshal checkin payload: %w", err)
	}

	checkinURL := strings.TrimRight(c.cfg.BackendURL, "/") + "/api/agent/checkin"
	req, err := http.NewRequest("POST", checkinURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create checkin request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", c.cfg.AgentKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("checkin HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("checkin rejected: Agent key has been revoked by admin")
	}

	if resp.StatusCode != http.StatusOK {
		respData, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("checkin returned status %d: %s", resp.StatusCode, string(respData))
	}

	return nil
}
