package intake

import (
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

type OSInfo struct {
	Architecture string `json:"architecture"`
	Bitness      string `json:"bitness"`
	OSType       string `json:"os_type"`
	Version      string `json:"version"`
}

func CollectOSInfo() (OSInfo, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return OSInfo{}, fmt.Errorf("uname: %w", err)
	}

	arch := runtime.GOARCH
	bitness := "64-bit"
	if arch == "386" || arch == "arm" {
		bitness = "32-bit"
	}

	return OSInfo{
		Architecture: arch,
		Bitness:      bitness,
		OSType:       "Linux",
		Version:      strings.TrimRight(string(u.Release[:]), "\x00"),
	}, nil
}
