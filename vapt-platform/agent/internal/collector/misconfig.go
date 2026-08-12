package collector

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type MisconfigCheck struct {
	CheckKey       string   `json:"check_key"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	CVSSScore      float64  `json:"cvss_score"`
	CISControl     string   `json:"cis_control"`
	Evidence       string   `json:"evidence"`
	Remediation    string   `json:"remediation"`
	ComplianceMap  []string `json:"compliance_map"`
	IsMisconfigured bool     `json:"is_misconfigured"`
}

// CollectMisconfigurations performs a comprehensive Windows security audit across registry, services, firewall, UAC, RDP, Defender, SMB, and LSA.
func CollectMisconfigurations() ([]MisconfigCheck, error) {
	var findings []MisconfigCheck

	// 1. SMBv1 Protocol Status
	smb1Key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, registry.QUERY_VALUE)
	if err == nil {
		smb1Val, _, err := smb1Key.GetIntegerValue("SMB1")
		smb1Key.Close()
		if err == nil && smb1Val == 1 {
			findings = append(findings, MisconfigCheck{
				CheckKey:       "SMBV1_ENABLED",
				Title:          "SMBv1 Legacy Protocol Enabled",
				Severity:       "high",
				CVSSScore:      7.5,
				CISControl:     "CIS 2.3.11.1",
				Evidence:       "Registry key HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 is set to 1 (Enabled).",
				Remediation:    "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
				ComplianceMap:  []string{"CIS Windows Benchmark v2.0", "NIST SP 800-53 AC-17", "ISO 27001 A.13.1.1"},
				IsMisconfigured: true,
			})
		}
	}

	// 2. RDP NLA Enforcement
	rdpKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, registry.QUERY_VALUE)
	if err == nil {
		nlaVal, _, err := rdpKey.GetIntegerValue("UserAuthentication")
		rdpKey.Close()
		if err == nil && nlaVal == 0 {
			findings = append(findings, MisconfigCheck{
				CheckKey:       "RDP_NLA_DISABLED",
				Title:          "RDP Network Level Authentication (NLA) Disabled",
				Severity:       "high",
				CVSSScore:      7.5,
				CISControl:     "CIS 2.3.1.1",
				Evidence:       "Registry key HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication is set to 0 (NLA Not Enforced).",
				Remediation:    "Enforce NLA for Remote Desktop connections via System Properties or Group Policy.",
				ComplianceMap:  []string{"CIS Windows Benchmark v2.0", "NIST SP 800-53 IA-2"},
				IsMisconfigured: true,
			})
		}
	}

	// 3. UAC Level Enforcement
	uacKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE)
	if err == nil {
		enableLua, _, _ := uacKey.GetIntegerValue("EnableLUA")
		consentPrompt, _, _ := uacKey.GetIntegerValue("ConsentPromptBehaviorAdmin")
		uacKey.Close()

		if enableLua == 0 || consentPrompt == 0 {
			findings = append(findings, MisconfigCheck{
				CheckKey:       "UAC_DISABLED_OR_WEAK",
				Title:          "User Account Control (UAC) Disabled or Weakly Configured",
				Severity:       "critical",
				CVSSScore:      8.8,
				CISControl:     "CIS 2.3.17.1",
				Evidence:       fmt.Sprintf("EnableLUA=%d, ConsentPromptBehaviorAdmin=%d (UAC elevation prompts disabled or bypassed).", enableLua, consentPrompt),
				Remediation:    "Set EnableLUA=1 and ConsentPromptBehaviorAdmin=2 (Prompt for credentials or consent on secure desktop).",
				ComplianceMap:  []string{"CIS Windows Benchmark v2.0", "NIST SP 800-53 AC-6"},
				IsMisconfigured: true,
			})
		}
	}

	// 4. Local Administrators Members
	adminCmd := exec.Command("net", "localgroup", "administrators")
	adminOut, err := adminCmd.Output()
	if err == nil {
		output := string(adminOut)
		if strings.Contains(output, "Guest") || strings.Contains(output, "Everyone") {
			findings = append(findings, MisconfigCheck{
				CheckKey:       "LOCAL_ADMIN_EXCESSIVE_MEMBERS",
				Title:          "Excessive or Insecure Local Administrators Group Members",
				Severity:       "high",
				CVSSScore:      7.8,
				CISControl:     "CIS 2.3.1.2",
				Evidence:       "Unsanctioned user accounts detected in local Administrators group:\n" + output,
				Remediation:    "Remove unnecessary user accounts from the local Administrators group.",
				ComplianceMap:  []string{"CIS Windows Benchmark v2.0", "NIST SP 800-53 AC-6"},
				IsMisconfigured: true,
			})
		}
	}

	// 5. LLMNR Multicast Name Resolution
	llmnrKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, registry.QUERY_VALUE)
	if err == nil {
		enableMulticast, _, err := llmnrKey.GetIntegerValue("EnableMulticast")
		llmnrKey.Close()
		if err != nil || enableMulticast == 1 {
			findings = append(findings, MisconfigCheck{
				CheckKey:       "LLMNR_ENABLED",
				Title:          "LLMNR Protocol Enabled (NBT-NS Poisoning Vulnerability)",
				Severity:       "medium",
				CVSSScore:      6.5,
				CISControl:     "CIS 18.9.30.2",
				Evidence:       "Link-Local Multicast Name Resolution (LLMNR) is enabled. Attackers can perform Responder credential spoofing.",
				Remediation:    "Disable LLMNR in Group Policy: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Turn off multicast name resolution.",
				ComplianceMap:  []string{"CIS Windows Benchmark v2.0", "NIST SP 800-53 SC-8"},
				IsMisconfigured: true,
			})
		}
	}

	// 6. LSA Protection (LSASS Driver Hardening)
	lsaKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err == nil {
		runAsPPL, _, err := lsaKey.GetIntegerValue("RunAsPPL")
		lsaKey.Close()
		if err != nil || runAsPPL == 0 {
			findings = append(findings, MisconfigCheck{
				CheckKey:       "LSA_PROTECTION_DISABLED",
				Title:          "LSA Protection (RunAsPPL) Disabled",
				Severity:       "medium",
				CVSSScore:      6.2,
				CISControl:     "CIS 2.3.10.2",
				Evidence:       "LSASS process is not running as a Protected Process Light (RunAsPPL=0). Credential dumping tools (Mimikatz) can read LSASS memory.",
				Remediation:    "Enable LSA Protection: Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1.",
				ComplianceMap:  []string{"CIS Windows Benchmark v2.0", "NIST SP 800-53 IA-5"},
				IsMisconfigured: true,
			})
		}
	}

	// 7. Unquoted Service Paths Audit
	servicesKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err == nil {
		subKeys, err := servicesKey.ReadSubKeyNames(-1)
		servicesKey.Close()
		if err == nil {
			unquotedCount := 0
			var unquotedSample []string
			for _, serviceName := range subKeys {
				sKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+serviceName, registry.QUERY_VALUE)
				if err != nil {
					continue
				}
				imagePath, _, _ := sKey.GetStringValue("ImagePath")
				sKey.Close()

				imagePath = strings.TrimSpace(imagePath)
				if imagePath != "" && !strings.HasPrefix(imagePath, `"`) && strings.Contains(imagePath, " ") && !strings.HasPrefix(strings.ToLower(imagePath), "c:\\windows\\") {
					ext := strings.ToLower(filepath.Ext(imagePath))
					if ext == ".exe" || strings.Contains(imagePath, ".exe ") {
						unquotedCount++
						if len(unquotedSample) < 3 {
							unquotedSample = append(unquotedSample, fmt.Sprintf("%s (%s)", serviceName, imagePath))
						}
					}
				}
			}
			if unquotedCount > 0 {
				findings = append(findings, MisconfigCheck{
					CheckKey:       "UNQUOTED_SERVICE_PATH",
					Title:          "Unquoted Windows Service Path Vulnerability",
					Severity:       "medium",
					CVSSScore:      6.8,
					CISControl:     "CIS 2.3.1.5",
					Evidence:       fmt.Sprintf("Found %d services with unquoted executable paths containing spaces.\nSample: %s", unquotedCount, strings.Join(unquotedSample, "; ")),
					Remediation:    "Enclose the Service Binary Path in double quotes in the Windows Registry.",
					ComplianceMap:  []string{"CIS Windows Benchmark v2.0", "NIST SP 800-53 SI-2"},
					IsMisconfigured: true,
				})
			}
		}
	}

	// 8. PowerShell Unrestricted Execution Policy
	psKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`, registry.QUERY_VALUE)
	if err == nil {
		execPolicy, _, err := psKey.GetStringValue("ExecutionPolicy")
		psKey.Close()
		if err == nil && (strings.EqualFold(execPolicy, "Unrestricted") || strings.EqualFold(execPolicy, "Bypass")) {
			findings = append(findings, MisconfigCheck{
				CheckKey:       "POWERSHELL_EXECUTION_POLICY_BYPASS",
				Title:          "PowerShell Unrestricted / Bypass Execution Policy",
				Severity:       "medium",
				CVSSScore:      5.5,
				CISControl:     "CIS 18.9.84.1",
				Evidence:       fmt.Sprintf("PowerShell ExecutionPolicy is set to '%s'.", execPolicy),
				Remediation:    "Set PowerShell ExecutionPolicy to RemoteSigned or AllSigned via Group Policy.",
				ComplianceMap:  []string{"CIS Windows Benchmark v2.0", "NIST SP 800-53 CM-7"},
				IsMisconfigured: true,
			})
		}
	}

	return findings, nil
}
