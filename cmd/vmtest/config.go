package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// VMConfig describes a single managed VM. Every field is optional: defaults
// kick in at driver level (e.g., SSHPort 22, WaitReadySeconds 45).
type VMConfig struct {
	Platform         string `yaml:"platform"` // windows | linux
	VBoxName         string `yaml:"vbox_name"`
	LibvirtName      string `yaml:"libvirt_name"`
	Snapshot         string `yaml:"snapshot"`
	User             string `yaml:"user"`
	Password         string `yaml:"password,omitempty"`
	SSHPort          int    `yaml:"ssh_port"`
	SSHKey           string `yaml:"ssh_key,omitempty"`
	SSHHost          string `yaml:"ssh_host,omitempty"`
	SharedFolder     string `yaml:"shared_folder,omitempty"`
	SharedMount      string `yaml:"shared_mountpoint,omitempty"`
	GuestRunner      string `yaml:"guest_runner,omitempty"`
	ProjectCopyPath  string `yaml:"project_copy_path,omitempty"`
	WaitReadySeconds int    `yaml:"wait_ready_seconds,omitempty"`
}

type VBoxSettings struct {
	ExePath string `yaml:"exe_path"`
}

type LibvirtSettings struct {
	ConnectURI string `yaml:"connect_uri"`
}

// Config is the parsed YAML configuration after deep-merge of base + local
// and environment-variable overrides.
type Config struct {
	Driver  string              `yaml:"driver"`
	VMs     map[string]VMConfig `yaml:"vms"`
	VBox    VBoxSettings        `yaml:"vbox"`
	Libvirt LibvirtSettings     `yaml:"libvirt"`
}

// LoadConfig loads the base config YAML, deep-merges a local override YAML
// when present, then applies environment-variable overrides and auto-detects
// the driver if not explicitly set.
func LoadConfig(base, local string) (*Config, error) {
	baseMap, err := loadYAMLMap(base)
	if err != nil {
		return nil, err
	}
	if local != "" {
		if _, statErr := os.Stat(local); statErr == nil {
			localMap, err := loadYAMLMap(local)
			if err != nil {
				return nil, err
			}
			deepMerge(baseMap, localMap)
		}
	}
	merged, err := yaml.Marshal(baseMap)
	if err != nil {
		return nil, fmt.Errorf("remarshal merged config: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(merged, cfg); err != nil {
		return nil, fmt.Errorf("parse merged config: %w", err)
	}
	applyEnvOverrides(cfg)
	if cfg.Driver == "" {
		cfg.Driver = autoDetectDriver(cfg)
	}
	return cfg, nil
}

func loadYAMLMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	m := map[string]any{}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// deepMerge merges src into dst recursively. Nested maps are merged
// field-by-field; other values in src replace dst. Mirrors intuition for
// config-override files.
func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if dv, ok := dst[k]; ok {
			if dm, ok1 := dv.(map[string]any); ok1 {
				if sm, ok2 := v.(map[string]any); ok2 {
					deepMerge(dm, sm)
					continue
				}
			}
		}
		dst[k] = v
	}
}

// applyEnvOverrides lets users tune host-specific fields without editing
// the YAML files. Envs win over YAML; useful for CI and one-shot overrides.
//
//	MALDEV_VM_DRIVER               -> cfg.Driver
//	MALDEV_VBOX_EXE                -> cfg.VBox.ExePath
//	MALDEV_VM_<NAME>_SSH_KEY       -> vm.SSHKey
//	MALDEV_VM_<NAME>_SSH_HOST      -> vm.SSHHost
//	MALDEV_VM_<NAME>_USER          -> vm.User
//	MALDEV_VM_<NAME>_PASSWORD      -> vm.Password
//	MALDEV_VM_<NAME>_SNAPSHOT      -> vm.Snapshot
//	MALDEV_VM_<NAME>_LIBVIRT_NAME  -> vm.LibvirtName
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("MALDEV_VM_DRIVER"); v != "" {
		cfg.Driver = v
	}
	if v := os.Getenv("MALDEV_VBOX_EXE"); v != "" {
		cfg.VBox.ExePath = v
	}
	for name, vm := range cfg.VMs {
		up := strings.ToUpper(name)
		if v := os.Getenv("MALDEV_VM_" + up + "_SSH_KEY"); v != "" {
			vm.SSHKey = v
		}
		if v := os.Getenv("MALDEV_VM_" + up + "_SSH_HOST"); v != "" {
			vm.SSHHost = v
		}
		if v := os.Getenv("MALDEV_VM_" + up + "_USER"); v != "" {
			vm.User = v
		}
		if v := os.Getenv("MALDEV_VM_" + up + "_PASSWORD"); v != "" {
			vm.Password = v
		}
		if v := os.Getenv("MALDEV_VM_" + up + "_SNAPSHOT"); v != "" {
			vm.Snapshot = v
		}
		if v := os.Getenv("MALDEV_VM_" + up + "_LIBVIRT_NAME"); v != "" {
			vm.LibvirtName = v
		}
		cfg.VMs[name] = vm
	}
}

func autoDetectDriver(cfg *Config) string {
	if cfg.VBox.ExePath != "" {
		if _, err := os.Stat(cfg.VBox.ExePath); err == nil {
			return "vbox"
		}
	}
	if _, err := exec.LookPath("VBoxManage"); err == nil {
		return "vbox"
	}
	if _, err := exec.LookPath("VBoxManage.exe"); err == nil {
		return "vbox"
	}
	if _, err := exec.LookPath("virsh"); err == nil {
		return "libvirt"
	}
	return ""
}
