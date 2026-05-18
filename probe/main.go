//go:build linux

// probe reports Landlock availability using the same detection logic as
// sandbox.DetectKernelCapabilities() from the 001-linux-landlock-sandbox branch.
package main

import (
	"fmt"
	"os"
	"strings"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func main() {
	enabled := false
	abi := 0

	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		for _, lsm := range strings.Split(strings.TrimSpace(string(data)), ",") {
			if strings.TrimSpace(lsm) == "landlock" {
				enabled = true
				break
			}
		}
	}

	if enabled {
		if v, err := ll.LandlockGetABIVersion(); err == nil {
			abi = v
		}
	}

	fmt.Printf("LandlockEnabled: %v\n", enabled)
	fmt.Printf("LandlockABI:     %d\n", abi)
	if enabled {
		fmt.Printf("Result: Landlock present (ABI %d) — sandbox will use primary tier\n", abi)
	} else {
		fmt.Printf("Result: Landlock NOT present — sandbox falls back to bwrap-only (degraded)\n")
	}
}
