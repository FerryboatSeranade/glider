//go:build !linux

package main

func readInterfaceTraffic(iface string) (uint64, uint64) {
	return 0, 0
}
