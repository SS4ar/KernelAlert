package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"kernalert/config"
	"kernalert/models"
	"log"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

var (
	sysctlChangeRegex     = regexp.MustCompile(`sysctl: ([\w\.]+) = (.+)`)
	securityAlertRegex    = regexp.MustCompile(`(?i)(audit|selinux|apparmor|security).*(denied|blocked|violation|warning)`)
	kernelErrorRegex      = regexp.MustCompile(`(?i)kernel:.*(error|warning|fail)`)
	syscallBlockRegex     = regexp.MustCompile(`(?i)syscall (\w+) (blocked|denied)`)
	capabilityChangeRegex = regexp.MustCompile(`(?i)capability.*(granted|removed)`)
	ebpfEventRegex        = regexp.MustCompile(`(?i)bpf.*prog.*loaded|bpf.*prog.*verified|bpf.*map.*created`)
)

func analyzeDmesgLogs(logs []string) []string {
	var alerts []string

	for _, log := range logs {
		if matches := sysctlChangeRegex.FindStringSubmatch(log); matches != nil {
			parameter, value := matches[1], matches[2]
			alerts = append(alerts, fmt.Sprintf("Kernel parameter change detected: %s = %s", parameter, value))
		}

		if securityAlertRegex.MatchString(log) {
			alerts = append(alerts, fmt.Sprintf("Security alert: %s", log))
		}

		if kernelErrorRegex.MatchString(log) {
			alerts = append(alerts, fmt.Sprintf("Kernel error detected: %s", log))
		}

		if matches := syscallBlockRegex.FindStringSubmatch(log); matches != nil {
			alerts = append(alerts, fmt.Sprintf("Syscall %s was %s", matches[1], matches[2]))
		}

		if capabilityChangeRegex.MatchString(log) {
			alerts = append(alerts, fmt.Sprintf("Capability change detected: %s", log))
		}

		if ebpfEventRegex.MatchString(log) {
			alerts = append(alerts, fmt.Sprintf("eBPF event detected: %s", log))
		}
	}

	return alerts
}

func analyzeFileIntegrity(report models.KernelReport, hostname string) []string {
	var alerts []string
	ctx := context.Background()

	ignoredFiles := map[string]bool{
		"/proc/sys/kernel/pty/nr":               true,
		"/proc/sys/kernel/random/entropy_avail": true,
		"/proc/sys/kernel/random/uuid":          true,
		"/proc/sys/kernel/random/boot_id":       true,
		"/proc/sys/kernel/ns_last_pid":          true,
	}

	checkFiles := func(files []models.FileState, category string) {
		for _, file := range files {
			if ignoredFiles[file.Path] {
				continue
			}

			key := fmt.Sprintf("file:%s:%s", hostname, file.Path)
			prevHash, err := RDB.Get(ctx, key).Result()
			if err == nil && prevHash != file.Hash {
				alerts = append(alerts, fmt.Sprintf("%s file changed: %s (old hash: %s, new hash: %s)",
					category, file.Path, prevHash[:8], file.Hash[:8]))
			}
			_ = RDB.Set(ctx, key, file.Hash, 30*24*time.Hour).Err()
		}
	}

	if report.FileIntegrity.BootFiles != nil {
		checkFiles(report.FileIntegrity.BootFiles, "Boot")
	}
	if report.FileIntegrity.SysKernelFiles != nil {
		checkFiles(report.FileIntegrity.SysKernelFiles, "Kernel sysctl")
	}
	if report.FileIntegrity.SecurityFiles != nil {
		checkFiles(report.FileIntegrity.SecurityFiles, "Security")
	}

	return alerts
}

func analyzeEbpfState(report models.KernelReport) []string {
	var alerts []string

	if report.EbpfState.Events != nil {
		for _, event := range report.EbpfState.Events {
			if event.Type == "unsafe_program" {
				alerts = append(alerts, fmt.Sprintf("New eBPF program loaded: %s (type: %s)",
					event.Program, event.Details))
			}
		}
	}

	return alerts
}

func analyzeKernelParams(report models.KernelReport, hostname string) []string {
	var alerts []string
	ctx := context.Background()

	if report.KernelParams.SysKernel != nil {
		prevParams, err := RDB.HGetAll(ctx, fmt.Sprintf("kernel:params:%s", hostname)).Result()
		if err == nil {
			for param, value := range report.KernelParams.SysKernel {
				if prevValue, exists := prevParams[param]; exists && prevValue != value {
					alerts = append(alerts, fmt.Sprintf("Kernel parameter changed: %s: %s -> %s",
						param, prevValue, value))
				}
			}
			_ = RDB.HMSet(ctx, fmt.Sprintf("kernel:params:%s", hostname),
				report.KernelParams.SysKernel).Err()
		}
	}

	if report.KernelParams.SysSecurity != nil {
		for param, value := range report.KernelParams.SysSecurity {
			if strings.Contains(strings.ToLower(param), "restrict") ||
				strings.Contains(strings.ToLower(param), "protect") ||
				strings.Contains(strings.ToLower(param), "secure") {
				if value == "0" || strings.ToLower(value) == "off" || strings.ToLower(value) == "false" {
					alerts = append(alerts, fmt.Sprintf("Security parameter disabled: %s = %s", param, value))
				}
			}
		}
	}

	return alerts
}

func categorizeAlert(alert string) string {
	switch {
	case strings.Contains(strings.ToLower(alert), "ebpf"):
		return "ebpf"
	case strings.Contains(strings.ToLower(alert), "selinux"):
		return "selinux"
	case strings.Contains(strings.ToLower(alert), "apparmor"):
		return "apparmor"
	case strings.Contains(strings.ToLower(alert), "module"):
		return "modules"
	case strings.Contains(strings.ToLower(alert), "file") ||
		strings.Contains(strings.ToLower(alert), "hash"):
		return "files"
	case strings.Contains(strings.ToLower(alert), "parameter") ||
		strings.Contains(strings.ToLower(alert), "sysctl"):
		return "params"
	default:
		return "other"
	}
}

func formatAlertMessage(alerts []string, hostname string) string {
	var sections = make(map[string][]string)
	var severityEmoji = map[string]string{
		"high":   "🔴",
		"medium": "🟡",
		"low":    "🟢",
	}

	for _, alert := range alerts {
		category := categorizeAlert(alert)
		if config.ShouldProcessAlert(alert, hostname, category) {
			sections[category] = append(sections[category], alert)
		}
	}

	if len(sections) == 0 {
		return ""
	}

	var message strings.Builder
	message.WriteString("🚨 *KERNEL ALERT* 🚨\n\n")
	message.WriteString(fmt.Sprintf("🖥 *Host:* `%s`\n", hostname))
	message.WriteString(fmt.Sprintf("🕒 *Time:* `%s`\n\n", time.Now().Format("2006-01-02 15:04:05")))

	processSection := func(category string, emoji string) {
		if alerts, ok := sections[category]; ok && len(alerts) > 0 {
			severity := config.GetAlertSeverity(category)
			message.WriteString(fmt.Sprintf("%s %s *%s:* %s\n",
				emoji,
				severityEmoji[severity],
				strings.Title(category),
				severity))
			for _, alert := range alerts {
				message.WriteString(fmt.Sprintf("• `%s`\n", alert))
			}
			message.WriteString("\n")
		}
	}

	sectionOrder := []struct {
		category string
		emoji    string
	}{
		{"selinux", "🛡"},
		{"apparmor", "🛡"},
		{"modules", "📦"},
		{"ebpf", "🔍"},
		{"files", "📄"},
		{"params", "⚙️"},
		{"other", "❗️"},
	}

	for _, section := range sectionOrder {
		processSection(section.category, section.emoji)
	}

	message.WriteString("🔗 *Details:* Check system logs for more information")

	return message.String()
}

func SendTelegramAlert(message string, telegramChatID string, telegramBotToken string) {
	if telegramBotToken == "" || telegramChatID == "" {
		log.Printf("Skipping Telegram alert: bot token or chat ID not configured")
		return
	}

	log.Printf("Sending Telegram alert: %s", message)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)

	values := url.Values{}
	values.Set("chat_id", telegramChatID)
	values.Set("text", message)
	values.Set("parse_mode", "Markdown")
	values.Set("disable_web_page_preview", "true")

	resp, err := http.PostForm(apiURL, values)
	if err != nil {
		log.Printf("Error sending alert to Telegram: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Telegram API error: status=%s, response=%s", resp.Status, string(body))
	} else {
		log.Printf("Telegram alert sent successfully: %s", string(body))
	}
}

func checkModuleChanges(report models.KernelReport) ([]string, error) {
	var alerts []string
	ctx := context.Background()

	baselineKey := fmt.Sprintf("baseline:modules:%s", report.Hostname)

	baselineModules, err := RDB.SMembers(ctx, baselineKey).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("error getting baseline modules: %v", err)
	}

	baselineSet := make(map[string]bool)
	for _, module := range baselineModules {
		baselineSet[module] = true
	}

	var newModules []string
	for _, module := range report.Modules {
		if !baselineSet[module] {
			newModules = append(newModules, module)
		}
	}

	if len(newModules) > 0 {
		exists, err := RDB.Exists(ctx, baselineKey).Result()
		if err != nil {
			log.Printf("Error checking key existence: %v", err)
		}

		if exists == 0 {
			for _, module := range report.Modules {
				err := RDB.SAdd(ctx, baselineKey, module).Err()
				if err != nil {
					log.Printf("Error adding module to baseline: %v", err)
				}
			}
			err := RDB.Expire(ctx, baselineKey, 24*time.Hour).Err()
			if err != nil {
				log.Printf("Error setting TTL: %v", err)
			}
			return nil, nil
		} else {
			alerts = append(alerts, fmt.Sprintf("New kernel modules detected: %s",
				strings.Join(newModules, ", ")))
		}
	}

	var removedModules []string
	for _, module := range baselineModules {
		found := false
		for _, currentModule := range report.Modules {
			if currentModule == module {
				found = true
				break
			}
		}
		if !found {
			removedModules = append(removedModules, module)
		}
	}

	if len(removedModules) > 0 {
		alerts = append(alerts, fmt.Sprintf("Kernel modules removed: %s",
			strings.Join(removedModules, ", ")))
	}

	return alerts, nil
}

func checkKernelParamChanges(report models.KernelReport) ([]string, error) {
	var alerts []string
	ctx := context.Background()

	checkParams := func(params map[string]string, category string) error {
		for name, value := range params {
			var prevValue string
			err := DB.QueryRowContext(ctx, `
				SELECT param_value 
				FROM baseline_kernel_params 
				WHERE host = $1 AND param_name = $2 AND category = $3`,
				report.Hostname, name, category).Scan(&prevValue)

			if err == sql.ErrNoRows {
				_, err = DB.ExecContext(ctx, `
					INSERT INTO baseline_kernel_params 
					(host, param_name, param_value, category)
					VALUES ($1, $2, $3, $4)`,
					report.Hostname, name, value, category)
				if err != nil {
					return fmt.Errorf("error inserting baseline param: %v", err)
				}
			} else if err != nil {
				return fmt.Errorf("error querying baseline param: %v", err)
			} else if prevValue != value {
				if shouldAlertOnParamChange(name, prevValue, value) {
					alerts = append(alerts, fmt.Sprintf("Kernel parameter changed: %s: %s -> %s",
						name, prevValue, value))
				}

				_, err = DB.ExecContext(ctx, `
					UPDATE baseline_kernel_params 
					SET param_value = $1, last_seen = NOW()
					WHERE host = $2 AND param_name = $3 AND category = $4`,
					value, report.Hostname, name, category)
				if err != nil {
					return fmt.Errorf("error updating baseline param: %v", err)
				}

				_, err = DB.ExecContext(ctx, `
					INSERT INTO kernel_param_changes 
					(host, param_name, old_value, new_value, category)
					VALUES ($1, $2, $3, $4, $5)`,
					report.Hostname, name, prevValue, value, category)
				if err != nil {
					return fmt.Errorf("error recording param change: %v", err)
				}
			}
		}
		return nil
	}

	if report.KernelParams.SysKernel != nil {
		if err := checkParams(report.KernelParams.SysKernel, "sys_kernel"); err != nil {
			log.Printf("Error checking sys_kernel params: %v", err)
		}
	}
	if report.KernelParams.SysSecurity != nil {
		if err := checkParams(report.KernelParams.SysSecurity, "sys_security"); err != nil {
			log.Printf("Error checking sys_security params: %v", err)
		}
	}
	if report.KernelParams.RuntimeParams != nil {
		if err := checkParams(report.KernelParams.RuntimeParams, "runtime_params"); err != nil {
			log.Printf("Error checking runtime params: %v", err)
		}
	}

	return alerts, nil
}

func shouldAlertOnParamChange(name, oldValue, newValue string) bool {
	ignoredParams := map[string]bool{
		"random/uuid":                      true,
		"random/entropy_avail":             true,
		"random/boot_id":                   true,
		"ns_last_pid":                      true,
		"net/netfilter/nf_conntrack_count": true,
		"fs/file-nr":                       true,
		"fs/inode-nr":                      true,
		"fs/inode-state":                   true,
		"fs/dentry-state":                  true,
		"spl/kmem/slab_alloc":              true,
		"spl/kmem/slab_kvmem_alloc":        true,
		"spl/kmem/slab_kvmem_total":        true,
		"vm/nr_pdflush_threads":            true,
		"vm/nr_mapped":                     true,
		"vm/nr_file_pages":                 true,
		"sched/nr_running":                 true,
	}

	normalizedName := strings.ReplaceAll(name, ".", "/")

	for ignoredParam := range ignoredParams {
		if strings.HasSuffix(normalizedName, ignoredParam) {
			return false
		}
	}

	securityParams := []string{
		"dmesg_restrict",
		"kptr_restrict",
		"modules_disabled",
		"protect_hardlinks",
		"protect_symlinks",
		"unprivileged_bpf_disabled",
		"kexec_load_disabled",
		"yama/ptrace_scope",
		"user/max_user_namespaces",
		"user/max_user_watches",
		"kernel/caps",
		"mmap_min_addr",
	}

	for _, param := range securityParams {
		if strings.Contains(normalizedName, param) {
			return true
		}
	}

	if strings.Contains(normalizedName, "shmmax") ||
		strings.Contains(normalizedName, "shmall") ||
		strings.Contains(normalizedName, "threads-max") {
		oldVal, err1 := strconv.ParseInt(oldValue, 10, 64)
		newVal, err2 := strconv.ParseInt(newValue, 10, 64)
		if err1 == nil && err2 == nil {
			if math.Abs(float64(newVal-oldVal))/float64(oldVal) > 0.5 {
				return true
			}
		}
		return false
	}

	return false
}

func analyzeKernelChanges(report models.KernelReport) []string {
	var alerts []string

	alerts = append(alerts, analyzeDmesgLogs(report.DmesgLogs)...)

	if report.SecurityState.SelinuxEnabled {
		if report.SecurityState.SelinuxMode != "enforcing" {
			alert := fmt.Sprintf("SELinux is not in enforcing mode: %s",
				report.SecurityState.SelinuxMode)
			if config.ShouldProcessAlert(alert, report.Hostname, "selinux") {
				alerts = append(alerts, alert)
			}
		}
	} else {
		alert := "SELinux is disabled"
		if config.ShouldProcessAlert(alert, report.Hostname, "selinux") {
			alerts = append(alerts, alert)
		}
	}

	if report.SecurityState.AppArmorStatus != "" &&
		!strings.Contains(strings.ToLower(report.SecurityState.AppArmorStatus), "enabled") {
		alert := fmt.Sprintf("AppArmor status is concerning: %s",
			report.SecurityState.AppArmorStatus)
		if config.ShouldProcessAlert(alert, report.Hostname, "apparmor") {
			alerts = append(alerts, alert)
		}
	}

	moduleAlerts, err := checkModuleChanges(report)
	if err != nil {
		log.Printf("Error checking module changes: %v", err)
	} else {
		alerts = append(alerts, moduleAlerts...)
	}

	paramAlerts, err := checkKernelParamChanges(report)
	if err != nil {
		log.Printf("Error checking kernel parameter changes: %v", err)
	} else {
		alerts = append(alerts, paramAlerts...)
	}

	alerts = append(alerts, analyzeEbpfState(report)...)
	alerts = append(alerts, analyzeFileIntegrity(report, report.Hostname)...)

	return alerts
}

func HandleReport(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received report request from %s", r.RemoteAddr)

	if r.Method != http.MethodPost {
		log.Printf("Invalid method %s from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var report models.KernelReport
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	log.Printf("Received report data: %s", string(body))

	if err := json.Unmarshal(body, &report); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	timestamp := time.Now()
	log.Printf("Processing report from host %s with %d modules and %d dmesg entries",
		report.Hostname, len(report.Modules), len(report.DmesgLogs))

	reportJSON, _ := json.Marshal(report)
	_, err = DB.Exec(
		"INSERT INTO reports(host, time, modules, dmesg, full_report) VALUES($1, $2, $3, $4, $5)",
		report.Hostname, timestamp,
		strings.Join(report.Modules, ","),
		strings.Join(report.DmesgLogs, "\n"),
		reportJSON,
	)
	if err != nil {
		log.Printf("Error writing report to DB: %v", err)
	} else {
		log.Printf("Successfully saved report to database")
	}

	allAlerts := analyzeKernelChanges(report)

	if len(allAlerts) > 0 {
		alertText := formatAlertMessage(allAlerts, report.Hostname)
		if alertText != "" {
			log.Printf("Preparing to send alert: %s", alertText)
			go SendTelegramAlert(alertText, config.TelegramChatID, config.TelegramBotToken)
		}
	} else {
		log.Printf("No concerning changes found for host %s", report.Hostname)
	}

	w.WriteHeader(http.StatusOK)
	log.Printf("Request processed successfully")
}
