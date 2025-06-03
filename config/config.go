package config

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
)

var (
	TelegramBotToken string
	TelegramChatID   string
	AllowedModules   = []string{"kvm", "vboxdrv", "nvidia"}
	AllowedSet       = make(map[string]struct{})

	AlertConfig AlertConfiguration
)

type AlertRule struct {
	Enabled     bool     `json:"enabled"`
	Severity    string   `json:"severity"`
	Conditions  []string `json:"conditions"`
	Exceptions  []string `json:"exceptions"`
	Description string   `json:"description"`
}

type AlertConfiguration struct {
	DefaultEnabled bool                  `json:"default_enabled"`
	HostExceptions map[string][]string   `json:"host_exceptions"`
	Rules          map[string]*AlertRule `json:"rules"`
}

func LoadAlertConfig(configPath string) error {
	AlertConfig = AlertConfiguration{
		DefaultEnabled: true,
		HostExceptions: make(map[string][]string),
		Rules: map[string]*AlertRule{
			"selinux": {
				Enabled:     true,
				Severity:    "high",
				Description: "SELinux status alerts",
			},
			"apparmor": {
				Enabled:     true,
				Severity:    "high",
				Description: "AppArmor status alerts",
			},
			"modules": {
				Enabled:     true,
				Severity:    "high",
				Description: "Kernel module alerts",
			},
			"ebpf": {
				Enabled:     true,
				Severity:    "high",
				Description: "eBPF program and event alerts",
			},
			"files": {
				Enabled:     true,
				Severity:    "medium",
				Description: "File integrity alerts",
			},
			"params": {
				Enabled:     true,
				Severity:    "medium",
				Description: "Kernel parameter alerts",
			},
		},
	}

	log.Printf("[DEBUG] Loading alert config from: %s", configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		data, err = json.MarshalIndent(AlertConfig, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(configPath, data, 0644); err != nil {
			return err
		}
		log.Printf("[DEBUG] Created default alert configuration at %s", configPath)
		return nil
	}

	if err := json.Unmarshal(data, &AlertConfig); err != nil {
		return err
	}

	log.Printf("[DEBUG] Alert configuration loaded successfully")
	log.Printf("[DEBUG] Rules enabled status:")
	for category, rule := range AlertConfig.Rules {
		log.Printf("[DEBUG] - %s: enabled=%v, severity=%s", category, rule.Enabled, rule.Severity)
	}

	return nil
}

func ShouldProcessAlert(alert, hostname, category string) bool {
	log.Printf("[DEBUG] Checking alert: category=%s, hostname=%s, alert=%s", category, hostname, alert)

	if exceptions, ok := AlertConfig.HostExceptions[hostname]; ok {
		for _, exception := range exceptions {
			if matched, _ := regexp.MatchString(exception, alert); matched {
				log.Printf("[DEBUG] Alert matched host exception: %s", exception)
				return false
			}
		}
	}

	if rule, ok := AlertConfig.Rules[category]; ok {
		log.Printf("[DEBUG] Found rule for category %s: enabled=%v", category, rule.Enabled)
		if !rule.Enabled {
			log.Printf("[DEBUG] Category %s is disabled", category)
			return false
		}

		for _, exception := range rule.Exceptions {
			if matched, _ := regexp.MatchString(exception, alert); matched {
				log.Printf("[DEBUG] Alert matched category exception: %s", exception)
				return false
			}
		}

		if len(rule.Conditions) > 0 {
			for _, condition := range rule.Conditions {
				if matched, _ := regexp.MatchString(condition, alert); matched {
					log.Printf("[DEBUG] Alert matched condition: %s", condition)
					return true
				}
			}
			log.Printf("[DEBUG] Alert didn't match any conditions")
			return false
		}

		log.Printf("[DEBUG] Alert passed all checks for category %s", category)
		return true
	}

	log.Printf("[DEBUG] No specific rule found for category %s, using default_enabled=%v", category, AlertConfig.DefaultEnabled)
	return AlertConfig.DefaultEnabled
}

func GetAlertSeverity(category string) string {
	if rule, ok := AlertConfig.Rules[category]; ok {
		return rule.Severity
	}
	return "medium"
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
