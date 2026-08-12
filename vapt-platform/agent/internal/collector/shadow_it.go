package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type ShadowITFlag struct {
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
}

// CollectShadowITSignals inspects remote access tools, personal cloud storage, browser extensions, and USBSTOR history.
func CollectShadowITSignals(softwareList []SoftwareItem) ([]ShadowITFlag, error) {
	var flags []ShadowITFlag

	// 1. Inspect Unauthorized Remote Access Tools & Personal Cloud Storage in Software List
	remoteAccessKeywords := []string{"anydesk", "teamviewer", "chrome remote desktop", "logmein", "tightvnc", "realvnc", "screenconnect", "parsec"}
	cloudStorageKeywords := []string{"dropbox", "mega.nz", "megasync", "baidu", "box sync"}

	for _, sw := range softwareList {
		nameLower := strings.ToLower(sw.Name)
		for _, kw := range remoteAccessKeywords {
			if strings.Contains(nameLower, kw) {
				flags = append(flags, ShadowITFlag{
					Type:        "RemoteAccess",
					Title:       fmt.Sprintf("Unauthorized Remote Access Tool Detected: %s", sw.Name),
					Severity:    "high",
					Evidence:    fmt.Sprintf("Application '%s' (Version: %s) installed at '%s'.", sw.Name, sw.Version, sw.InstallLocation),
					Remediation: "Remove unsanctioned remote access application or obtain formal security authorization.",
				})
			}
		}

		for _, kw := range cloudStorageKeywords {
			if strings.Contains(nameLower, kw) {
				flags = append(flags, ShadowITFlag{
					Type:        "CloudStorage",
					Title:       fmt.Sprintf("Unsanctioned Personal Cloud Storage Client Detected: %s", sw.Name),
					Severity:    "medium",
					Evidence:    fmt.Sprintf("Personal cloud storage tool '%s' installed.", sw.Name),
					Remediation: "Enforce corporate cloud storage policy and remove unauthorized sync clients.",
				})
			}
		}
	}

	// 2. USB Mass Storage Device History
	usbFlags := inspectUSBStorageHistory()
	flags = append(flags, usbFlags...)

	// 3. Browser Extensions (Chrome & Edge)
	extFlags := inspectBrowserExtensions()
	flags = append(flags, extFlags...)

	return flags, nil
}

func inspectUSBStorageHistory() []ShadowITFlag {
	var flags []ShadowITFlag
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\USBSTOR`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return flags
	}
	defer k.Close()

	deviceTypes, err := k.ReadSubKeyNames(-1)
	if err != nil || len(deviceTypes) == 0 {
		return flags
	}

	var usbList []string
	for _, devType := range deviceTypes {
		subK, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\USBSTOR\`+devType, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		serials, err := subK.ReadSubKeyNames(-1)
		subK.Close()
		if err == nil && len(serials) > 0 {
			usbList = append(usbList, devType)
		}
	}

	if len(usbList) > 0 {
		sample := usbList
		if len(sample) > 5 {
			sample = sample[:5]
		}
		flags = append(flags, ShadowITFlag{
			Type:        "USBStorageHistory",
			Title:       fmt.Sprintf("USB Mass Storage Devices Connected (%d Total Detected)", len(usbList)),
			Severity:    "info",
			Evidence:    fmt.Sprintf("Historical USB mass storage connections registered in USBSTOR registry key:\n%s", strings.Join(sample, "\n")),
			Remediation: "Verify USB storage usage complies with organizational data loss prevention policy.",
		})
	}
	return flags
}

func inspectBrowserExtensions() []ShadowITFlag {
	var flags []ShadowITFlag
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return flags
	}

	// Chrome & Edge Default Profile Extensions Paths
	paths := []struct {
		browser string
		path    string
	}{
		{"Google Chrome", filepath.Join(userProfile, `AppData\Local\Google\Chrome\User Data\Default\Extensions`)},
		{"Microsoft Edge", filepath.Join(userProfile, `AppData\Local\Microsoft\Edge\User Data\Default\Extensions`)},
	}

	for _, bInfo := range paths {
		entries, err := os.ReadDir(bInfo.path)
		if err != nil || len(entries) == 0 {
			continue
		}

		var extIDs []string
		for _, entry := range entries {
			if entry.IsDir() {
				extIDs = append(extIDs, entry.Name())
			}
		}

		if len(extIDs) > 0 {
			flags = append(flags, ShadowITFlag{
				Type:        "BrowserExtension",
				Title:       fmt.Sprintf("%s Extensions Detected (%d Installed)", bInfo.browser, len(extIDs)),
				Severity:    "low",
				Evidence:    fmt.Sprintf("Found %d extensions in %s profile directory.", len(extIDs), bInfo.browser),
				Remediation: "Review installed browser extensions against approved browser extension allowlist.",
			})
		}
	}

	return flags
}

// Unused dummy function to satisfy compiler imports if needed
func _() {
	var _ json.RawMessage
}
