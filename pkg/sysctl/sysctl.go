package sysctl

import (
	"fmt"
	"io/ioutil"
	"path"
	"strconv"
	"strings"
)

const (
	sysctlBase = "/proc/sys"

	NetCoreRmemMax = "net/core/rmem_max"
	NetCoreWmemMax = "net/core/wmem_max"
	NetIpv4TcpRmem = "net/ipv4/tcp_rmem"
	NetIpv4TcpWmem = "net/ipv4/tcp_wmem"
	NetIpv4TcpMem  = "net/ipv4/tcp_mem"
	NetIpv4UdpMem  = "net/ipv4/udp_mem"

	NetCoreRmemMax64M    = 67108864
	NetCoreWmemMax64M    = 67108864
	NetIpv4TcpMem64M     = "67108864 67108864 67108864"
	NetIpv4UdpMem64M     = "67108864 67108864 67108864"
	NetIpv4TcpRmemMax64M = 67108864
	NetIpv4TcpWmemMax64M = 67108864

	VmOvercommitMemory = "vm/overcommit_memory"
	VmPanicOnOOM       = "vm/panic_on_oom"
	KernelPanic        = "kernel/panic"
	KernelPanicOnOops  = "kernel/panic_on_oops"

	VmOvercommitMemoryAlways    = 1  // kernel performs no memory over-commit handling
	VmPanicOnOOMInvokeOOMKiller = 0  // kernel calls the oom_killer function when OOM occurs
	KernelPanicOnOopsAlways     = 1  // kernel panics on kernel oops
	KernelPanicRebootTimeout    = 10 // seconds after a panic for the kernel to reboot
)

// GetSysctl returns the value for the specified sysctl setting
func GetSysctl(sysctl string) (int, error) {
	data, err := ioutil.ReadFile(path.Join(sysctlBase, sysctl))
	if err != nil {
		return -1, err
	}
	val, err := strconv.Atoi(strings.Trim(string(data), " \n"))
	if err != nil {
		return -1, err
	}
	return val, nil
}

// SetSysctl modifies the specified sysctl flag to the new value
func SetSysctl(sysctl string, newVal int) error {
	return ioutil.WriteFile(path.Join(sysctlBase, sysctl), []byte(strconv.Itoa(newVal)), 0640)
}

// GetSysctlString returns the string value for the specified sysctl setting
func GetSysctlString(sysctl string) (string, error) {
	data, err := ioutil.ReadFile(path.Join(sysctlBase, sysctl))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SetSysctlString modifies the specified sysctl flag to the new string value
func SetSysctlString(sysctl string, newVal string) error {
	return ioutil.WriteFile(path.Join(sysctlBase, sysctl), []byte(newVal), 0640)
}

// SetSysctlMax modifies the max value of 'min default max'
func SetSysctlMax(sysctl string, newVal int) error {
	key := path.Join(sysctlBase, sysctl)
	data, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	words := strings.Fields(string(data))
	if len(words) != 3 {
		return fmt.Errorf("%q does not have 3 fields", key)
	}
	val := fmt.Sprintf("%s %s %d", words[0], words[1], newVal)
	return ioutil.WriteFile(key, []byte(val), 0640)
}
