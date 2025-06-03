package agent

import (
	"log"
	"os"
	"os/exec"
	"strings"
)

func GetDmesgLogs() []string {
	output, err := exec.Command("dmesg").Output()
	if err != nil {
		log.Printf("Error getting log dmesg: %v", err)
		return []string{}
	}
	logs := strings.Split(string(output), "\n")
	if len(logs) > 0 && logs[len(logs)-1] == "" {
		logs = logs[:len(logs)-1]
	}
	return logs
}

func GetLoadedModules() []string {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		log.Printf("Error reading /proc/modules: %v", err)
		return []string{}
	}
	lines := strings.Split(string(data), "\n")
	var modules []string
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			modules = append(modules, fields[0])
		}
	}
	return modules
}
