//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readInterfaceTraffic(iface string) (uint64, uint64) {
	if strings.TrimSpace(iface) == "" {
		iface = "eth0"
	}
	rx := readUintFile(filepath.Join("/sys/class/net", iface, "statistics", "rx_bytes"))
	tx := readUintFile(filepath.Join("/sys/class/net", iface, "statistics", "tx_bytes"))
	return rx, tx
}

func readUintFile(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
