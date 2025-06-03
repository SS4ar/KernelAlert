package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"kernalert/models"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	serverURL = getEnvOrDefault("SERVER_URL", "https://localhost:8443/report")
	interval  = getEnvOrDefault("CHECK_INTERVAL", "300")
)

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	logFile, err := os.OpenFile("/var/log/kernalert-agent.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open log file:", err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	log.Printf("[DEBUG] Starting agent with configuration:")
	log.Printf("[DEBUG] Server URL: %s", serverURL)
	log.Printf("[DEBUG] Check interval: %s seconds", interval)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for {
		report, err := collectReport()
		if err != nil {
			log.Printf("[ERROR] Error collecting report: %v", err)
			time.Sleep(time.Minute)
			continue
		}

		log.Printf("[DEBUG] Collected report for host: %s", report.Hostname)
		log.Printf("[DEBUG] Number of modules: %d", len(report.Modules))
		log.Printf("[DEBUG] Number of dmesg logs: %d", len(report.DmesgLogs))

		reportJSON, _ := json.Marshal(report)
		log.Printf("[DEBUG] Sending report to %s", serverURL)
		log.Printf("[DEBUG] Report JSON: %s", string(reportJSON))

		req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(reportJSON))
		if err != nil {
			log.Printf("[ERROR] Error creating request: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		log.Printf("[DEBUG] Sending HTTP POST request to %s", req.URL.String())
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Error sending report: %v", err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("[DEBUG] Server response: Status=%s, Body=%s", resp.Status, string(body))
			resp.Body.Close()
			log.Printf("[INFO] Report sent successfully")
		}

		interval, _ := time.ParseDuration(interval + "s")
		log.Printf("[DEBUG] Waiting %v before next report", interval)
		time.Sleep(interval)
	}
}

func collectReport() (*models.KernelReport, error) {
	log.Printf("[DEBUG] Starting report collection")

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %v", err)
	}
	log.Printf("[DEBUG] Got hostname: %s", hostname)

	report := &models.KernelReport{
		Hostname: hostname,
	}

	log.Printf("[DEBUG] Collecting loaded modules...")
	if modules, err := getLoadedModules(); err == nil {
		report.Modules = modules
		log.Printf("[DEBUG] Collected %d modules", len(modules))
	} else {
		log.Printf("[ERROR] Failed to collect modules: %v", err)
	}

	log.Printf("[DEBUG] Collecting dmesg logs...")
	if logs, err := getDmesgLogs(); err == nil {
		report.DmesgLogs = logs
		log.Printf("[DEBUG] Collected %d dmesg log entries", len(logs))
	} else {
		log.Printf("[ERROR] Failed to collect dmesg logs: %v", err)
	}

	log.Printf("[DEBUG] Collecting security state...")
	if secState, err := getSecurityState(); err == nil {
		report.SecurityState = secState
		log.Printf("[DEBUG] Security state collected")
	} else {
		log.Printf("[ERROR] Failed to collect security state: %v", err)
	}

	log.Printf("[DEBUG] Collecting eBPF state...")
	if ebpfState, err := getEbpfState(); err == nil {
		report.EbpfState = ebpfState
		log.Printf("[DEBUG] eBPF state collected")
	} else {
		log.Printf("[ERROR] Failed to collect eBPF state: %v", err)
	}

	log.Printf("[DEBUG] Checking file integrity...")
	if fileIntegrity, err := checkFileIntegrity(); err == nil {
		report.FileIntegrity = fileIntegrity
		log.Printf("[DEBUG] File integrity check completed")
	} else {
		log.Printf("[ERROR] Failed to check file integrity: %v", err)
	}

	log.Printf("[DEBUG] Collecting kernel parameters...")
	if kernelParams, err := getKernelParams(); err == nil {
		report.KernelParams = kernelParams
		log.Printf("[DEBUG] Kernel parameters collected")
	} else {
		log.Printf("[ERROR] Failed to collect kernel parameters: %v", err)
	}

	log.Printf("[DEBUG] Report collection completed")
	return report, nil
}

func getLoadedModules() ([]string, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}

	var modules []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		modules = append(modules, strings.Fields(line)[0])
	}
	return modules, nil
}

func getDmesgLogs() ([]string, error) {
	cmd := exec.Command("dmesg", "--time-format", "iso")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var logs []string
	for _, line := range strings.Split(string(output), "\n") {
		if line != "" {
			logs = append(logs, line)
		}
	}
	return logs, nil
}

func getSecurityState() (models.SecurityState, error) {
	state := models.SecurityState{}

	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		state.SelinuxEnabled = true
		if mode, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
			if strings.TrimSpace(string(mode)) == "1" {
				state.SelinuxMode = "enforcing"
			} else {
				state.SelinuxMode = "permissive"
			}
		}
	}

	if data, err := os.ReadFile("/sys/kernel/security/apparmor/status"); err == nil {
		state.AppArmorStatus = strings.TrimSpace(string(data))
	} else {
		state.AppArmorStatus = "disabled"
	}

	cmd := exec.Command("grep", "Seccomp", "/proc/self/status")
	if output, err := cmd.Output(); err == nil {
		state.SeccompEnabled = strings.Contains(string(output), "2")
	}

	cmd = exec.Command("capsh", "--print")
	if output, err := cmd.Output(); err == nil {
		re := regexp.MustCompile(`cap_\w+`)
		state.Capabilities = re.FindAllString(string(output), -1)
	}

	return state, nil
}

func getEbpfState() (models.EbpfState, error) {
	state := models.EbpfState{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	safeTypes := map[string]bool{
		"cgroup_device": true,
		"cgroup_skb":    true,
		"sock_ops":      true,
		"sk_msg":        true,
	}

	cmd := exec.CommandContext(ctx, "bpftool", "prog", "list", "-j")
	if output, err := cmd.Output(); err == nil {
		log.Printf("[DEBUG] Running bpftool prog list...")

		var rawPrograms []struct {
			ID         int    `json:"id"`
			Type       string `json:"type"`
			Name       string `json:"name"`
			Tag        string `json:"tag"`
			LoadTime   string `json:"load_time"`
			AttachType string `json:"attach_type"`
		}

		if err := json.Unmarshal(output, &rawPrograms); err == nil {
			log.Printf("[DEBUG] Successfully parsed bpftool output, found %d programs", len(rawPrograms))

			existingPrograms := make(map[string]bool)

			for _, prog := range state.Programs {
				key := fmt.Sprintf("%s_%s_%s", prog.Type, prog.AttachType, prog.Tag)
				existingPrograms[key] = true
			}

			var newSafePrograms, newUnsafePrograms int

			for _, raw := range rawPrograms {
				progKey := fmt.Sprintf("%s_%s_%s", raw.Type, raw.AttachType, raw.Tag)

				if existingPrograms[progKey] {
					log.Printf("[DEBUG] Skipping existing program: %s (type: %s)", raw.Name, raw.Type)
					continue
				}

				log.Printf("[DEBUG] Found new program - Name: %s, Type: %s, Tag: %s",
					raw.Name, raw.Type, raw.Tag)

				safe := safeTypes[raw.Type]
				log.Printf("[DEBUG] Safety check for program %s (type: %s) -> safe=%v",
					raw.Name, raw.Type, safe)

				prog := models.EbpfProgram{
					Name:       raw.Name,
					Type:       raw.Type,
					AttachType: raw.AttachType,
					Tag:        raw.Tag,
					LoadTime:   raw.LoadTime,
					Verified:   true,
					Loaded:     true,
					Running:    true,
					Hooks:      []string{raw.AttachType},
				}

				state.Programs = append(state.Programs, prog)

				if safe {
					newSafePrograms++
					log.Printf("[DEBUG] Program %s (type: %s) is safe Docker program",
						prog.Name, prog.Type)
				} else {
					newUnsafePrograms++
					log.Printf("[WARN] Found potentially unsafe eBPF program: %s (type: %s)",
						prog.Name, prog.Type)

					state.Events = append(state.Events, models.EbpfEvent{
						Timestamp: time.Now().Format(time.RFC3339),
						Type:      "unsafe_program",
						Program:   prog.Name,
						Action:    "loaded",
						Details: fmt.Sprintf("Potentially unsafe eBPF program detected (type: %s)",
							prog.Type),
					})
				}
			}

			log.Printf("[INFO] eBPF programs summary - New safe: %d, New unsafe: %d, Total: %d",
				newSafePrograms, newUnsafePrograms, len(state.Programs))

		} else {
			log.Printf("[ERROR] Failed to parse bpftool output: %v", err)
			log.Printf("[DEBUG] Raw output: %s", string(output))
		}
	} else {
		log.Printf("[ERROR] Failed to run bpftool: %v", err)
		if len(output) > 0 {
			log.Printf("[DEBUG] Command output: %s", string(output))
		}
	}

	cmd = exec.CommandContext(ctx, "bpftool", "map", "list", "-j")
	if output, err := cmd.Output(); err == nil {
		var rawMaps []struct {
			ID         int    `json:"id"`
			Type       string `json:"type"`
			Name       string `json:"name"`
			KeySize    int    `json:"key_size"`
			ValueSize  int    `json:"value_size"`
			MaxEntries int    `json:"max_entries"`
		}
		if err := json.Unmarshal(output, &rawMaps); err == nil {
			for _, raw := range rawMaps {
				m := models.EbpfMap{
					Name:       raw.Name,
					Type:       raw.Type,
					KeySize:    raw.KeySize,
					ValueSize:  raw.ValueSize,
					MaxEntries: raw.MaxEntries,
				}
				state.Maps = append(state.Maps, m)

				if m.MaxEntries > 1000000 {
					state.Events = append(state.Events, models.EbpfEvent{
						Timestamp: time.Now().Format(time.RFC3339),
						Type:      "unusual_map_size",
						Program:   m.Name,
						Action:    "created",
						Details:   fmt.Sprintf("eBPF map with large max entries: %d", m.MaxEntries),
					})
				}
			}
		}
	}

	cmd = exec.CommandContext(ctx, "timeout", "1", "cat", "/sys/kernel/debug/tracing/trace_pipe")
	if output, err := cmd.Output(); err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
				continue
			}

			if strings.Contains(line, "bpf_prog_load") ||
				strings.Contains(line, "bpf_map_create") ||
				strings.Contains(line, "bpf_prog_attach") {
				state.Events = append(state.Events, models.EbpfEvent{
					Timestamp: time.Now().Format(time.RFC3339),
					Type:      "runtime_activity",
					Action:    "system_call",
					Details:   fmt.Sprintf("eBPF runtime activity detected: %s", line),
				})
			}
		}
	}

	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		if strings.TrimSpace(string(data)) == "0" {
			state.Events = append(state.Events, models.EbpfEvent{
				Timestamp: time.Now().Format(time.RFC3339),
				Type:      "security_config",
				Action:    "check",
				Details:   "Warning: Unprivileged eBPF is enabled",
			})
		}
	}

	return state, nil
}

func checkFileIntegrity() (models.FileIntegrity, error) {
	integrity := models.FileIntegrity{}

	checkDir := func(dir string) ([]models.FileState, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resultChan := make(chan []models.FileState, 1)
		errChan := make(chan error, 1)

		ignoreDirs := map[string]bool{
			"/sys/kernel/security/apparmor": true,
			"/sys/kernel/security/selinux":  true,
			"/proc/sys/kernel/random":       true,
		}

		ignoreFiles := map[string]bool{
			"/proc/sys/kernel/ns_last_pid": true,
		}

		go func() {
			var result []models.FileState
			err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					log.Printf("[WARN] Error accessing %s: %v", path, err)
					return nil
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				for ignoreDir := range ignoreDirs {
					if strings.HasPrefix(path, ignoreDir) {
						return filepath.SkipDir
					}
				}

				if ignoreFiles[path] {
					return nil
				}

				if info.IsDir() || !info.Mode().IsRegular() {
					return nil
				}

				if info.Size() > 10*1024*1024 {
					log.Printf("[DEBUG] Skipping large file %s (%d bytes)", path, info.Size())
					return nil
				}

				hashCmd := exec.CommandContext(ctx, "sha256sum", path)
				output, err := hashCmd.Output()
				if err != nil {
					log.Printf("[WARN] Failed to get hash for %s: %v", path, err)
					return nil
				}
				hash := strings.Fields(string(output))[0]

				state := models.FileState{
					Path:         path,
					Hash:         hash,
					Permissions:  info.Mode().String(),
					LastModified: info.ModTime().Format(time.RFC3339),
					Size:         info.Size(),
				}
				result = append(result, state)
				return nil
			})

			if err != nil && err != context.DeadlineExceeded {
				errChan <- err
				return
			}
			resultChan <- result
		}()

		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				log.Printf("[WARN] Timeout while checking directory %s", dir)
				return nil, nil
			}
			return nil, ctx.Err()
		case err := <-errChan:
			return nil, err
		case result := <-resultChan:
			return result, nil
		}
	}

	log.Printf("[DEBUG] Checking /boot directory...")
	if bootFiles, err := checkDir("/boot"); err == nil {
		integrity.BootFiles = bootFiles
		log.Printf("[DEBUG] Checked %d files in /boot", len(bootFiles))
	} else {
		log.Printf("[WARN] Failed to check /boot: %v", err)
	}

	log.Printf("[DEBUG] Checking /proc/sys/kernel directory...")
	if sysKernelFiles, err := checkDir("/proc/sys/kernel"); err == nil {
		integrity.SysKernelFiles = sysKernelFiles
		log.Printf("[DEBUG] Checked %d files in /proc/sys/kernel", len(sysKernelFiles))
	} else {
		log.Printf("[WARN] Failed to check /proc/sys/kernel: %v", err)
	}

	log.Printf("[DEBUG] Checking /sys/kernel/security directory...")
	if securityFiles, err := checkDir("/sys/kernel/security"); err == nil {
		integrity.SecurityFiles = securityFiles
		log.Printf("[DEBUG] Checked %d files in /sys/kernel/security", len(securityFiles))
	} else {
		log.Printf("[WARN] Failed to check /sys/kernel/security: %v", err)
	}

	return integrity, nil
}

func getKernelParams() (models.KernelParams, error) {
	params := models.KernelParams{
		SysKernel:     make(map[string]string),
		SysSecurity:   make(map[string]string),
		RuntimeParams: make(map[string]string),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ignorePatterns := []string{
		"/proc/sys/kernel/random",
		"/sys/kernel/security/apparmor",
		"/sys/kernel/security/selinux",
		"core_pattern",
		"modprobe",
	}

	shouldIgnore := func(path string) bool {
		for _, pattern := range ignorePatterns {
			if strings.Contains(path, pattern) {
				return true
			}
		}
		return false
	}

	done := make(chan bool)
	go func() {
		err := filepath.Walk("/proc/sys/kernel", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("[WARN] Error accessing %s: %v", path, err)
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if !info.IsDir() && !shouldIgnore(path) {
				if data, err := os.ReadFile(path); err == nil {
					key := strings.TrimPrefix(path, "/proc/sys/kernel/")
					params.SysKernel[key] = strings.TrimSpace(string(data))
				}
			}
			return nil
		})
		if err != nil && err != context.DeadlineExceeded {
			log.Printf("[WARN] Error reading /proc/sys/kernel: %v", err)
		}
		done <- true
	}()

	done2 := make(chan bool)
	go func() {
		err := filepath.Walk("/sys/kernel/security", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("[WARN] Error accessing %s: %v", path, err)
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if !info.IsDir() && !shouldIgnore(path) {
				if data, err := os.ReadFile(path); err == nil {
					key := strings.TrimPrefix(path, "/sys/kernel/security/")
					params.SysSecurity[key] = strings.TrimSpace(string(data))
				}
			}
			return nil
		})
		if err != nil && err != context.DeadlineExceeded {
			log.Printf("[WARN] Error reading /sys/kernel/security: %v", err)
		}
		done2 <- true
	}()

	done3 := make(chan bool)
	go func() {
		cmd := exec.CommandContext(ctx, "sysctl", "-a")
		if output, err := cmd.Output(); err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 && !shouldIgnore(parts[0]) {
					params.RuntimeParams[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
		done3 <- true
	}()

	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			log.Printf("[WARN] Timeout while collecting kernel parameters")
			return params, nil
		case <-done:
			log.Printf("[DEBUG] Collected %d sys kernel parameters", len(params.SysKernel))
		case <-done2:
			log.Printf("[DEBUG] Collected %d security parameters", len(params.SysSecurity))
		case <-done3:
			log.Printf("[DEBUG] Collected %d runtime parameters", len(params.RuntimeParams))
		}
	}

	return params, nil
}
