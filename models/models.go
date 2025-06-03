package models

type KernelReport struct {
	Hostname      string            `json:"hostname"`
	Modules       []string          `json:"modules"`
	DmesgLogs     []string          `json:"dmesg_logs"`
	SysctlChanges map[string]string `json:"sysctl_changes,omitempty"`
	SecurityState SecurityState     `json:"security_state,omitempty"`
	KernelInfo    KernelInfo        `json:"kernel_info,omitempty"`
	SystemCalls   []SystemCall      `json:"syscalls,omitempty"`
	EbpfState     EbpfState         `json:"ebpf_state,omitempty"`
	FileIntegrity FileIntegrity     `json:"file_integrity,omitempty"`
	KernelParams  KernelParams      `json:"kernel_params,omitempty"`
}

type SecurityState struct {
	SelinuxEnabled bool     `json:"selinux_enabled"`
	SelinuxMode    string   `json:"selinux_mode,omitempty"`
	AppArmorStatus string   `json:"apparmor_status,omitempty"`
	SeccompEnabled bool     `json:"seccomp_enabled"`
	Capabilities   []string `json:"capabilities,omitempty"`
}

type KernelInfo struct {
	Version    string            `json:"version"`
	Parameters map[string]string `json:"parameters"`
	Symbols    []KernelSymbol    `json:"symbols,omitempty"`
	BootConfig map[string]string `json:"boot_config,omitempty"`
}

type KernelSymbol struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Module  string `json:"module,omitempty"`
}

type SystemCall struct {
	Name      string  `json:"name"`
	Count     int64   `json:"count"`
	ErrorRate float64 `json:"error_rate"`
	Blocked   bool    `json:"blocked"`
}

type EbpfState struct {
	Programs []EbpfProgram `json:"programs"`
	Maps     []EbpfMap     `json:"maps,omitempty"`
	Events   []EbpfEvent   `json:"events,omitempty"`
}

type EbpfProgram struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	AttachType string   `json:"attach_type"`
	Tag        string   `json:"tag"`
	LoadTime   string   `json:"load_time"`
	Verified   bool     `json:"verified"`
	Loaded     bool     `json:"loaded"`
	Running    bool     `json:"running"`
	Hooks      []string `json:"hooks,omitempty"`
}

type EbpfMap struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	KeySize    int    `json:"key_size"`
	ValueSize  int    `json:"value_size"`
	MaxEntries int    `json:"max_entries"`
}

type EbpfEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Program   string `json:"program"`
	Action    string `json:"action"`
	Details   string `json:"details,omitempty"`
}

type FileIntegrity struct {
	BootFiles      []FileState `json:"boot_files"`
	SysKernelFiles []FileState `json:"syskernel_files"`
	SecurityFiles  []FileState `json:"security_files"`
}

type FileState struct {
	Path         string `json:"path"`
	Hash         string `json:"hash"`
	Permissions  string `json:"permissions"`
	Owner        string `json:"owner"`
	LastModified string `json:"last_modified"`
	Size         int64  `json:"size"`
	Changed      bool   `json:"changed"`
}

type KernelParams struct {
	SysKernel     map[string]string `json:"sys_kernel"`
	SysSecurity   map[string]string `json:"sys_security"`
	RuntimeParams map[string]string `json:"runtime_params"`
}
