package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"vap-agent/internal/client"
)

const serviceName = "VAPAgent"
const serviceDesc = "VAP Endpoint Security & Misconfiguration Inventory Agent Service"

type vapService struct{}

func (m *vapService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	log.Println("VAP Agent Windows Service started.")

	cfg, _ := client.LoadConfigFromRegistry()
	agentClient := client.NewAgentClient(cfg)

	// Perform initial checkin upon service startup
	if err := agentClient.PerformCheckin(); err != nil {
		log.Printf("Initial checkin warning: %v\n", err)
	}

	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ticker.C:
			log.Println("Executing periodic VAP Agent checkin...")
			cfg, _ = client.LoadConfigFromRegistry()
			agentClient = client.NewAgentClient(cfg)
			if err := agentClient.PerformCheckin(); err != nil {
				log.Printf("Checkin error: %v\n", err)
			}
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Println("Stopping VAP Agent Windows Service...")
				changes <- svc.Status{State: svc.StopPending}
				break loop
			default:
				log.Printf("Unexpected service control request #%d\n", c.Cmd)
			}
		}
	}

	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

func main() {
	if len(os.Args) > 1 {
		cmd := strings.ToLower(os.Args[1])
		switch cmd {
		case "enroll":
			enrollFlags := flag.NewFlagSet("enroll", flag.ExitOnError)
			url := enrollFlags.String("url", "http://localhost:18080", "VAP Backend URL")
			token := enrollFlags.String("token", "", "Single-use Enrollment Token")
			_ = enrollFlags.Parse(os.Args[2:])

			if *token == "" {
				log.Fatal("Error: --token flag is required for enrollment.")
			}

			cfg := client.Config{BackendURL: *url}
			cli := client.NewAgentClient(cfg)
			if err := cli.Enroll(*token, *url); err != nil {
				log.Fatalf("Enrollment failed: %v", err)
			}
			return

		case "install":
			if err := installService(); err != nil {
				log.Fatalf("Failed to install service: %v", err)
			}
			fmt.Println("VAP Agent Windows Service installed successfully.")
			return

		case "uninstall":
			if err := removeService(); err != nil {
				log.Fatalf("Failed to uninstall service: %v", err)
			}
			fmt.Println("VAP Agent Windows Service uninstalled successfully.")
			return

		case "start":
			if err := startService(); err != nil {
				log.Fatalf("Failed to start service: %v", err)
			}
			fmt.Println("VAP Agent Windows Service started successfully.")
			return

		case "stop":
			if err := controlService(svc.Stop, svc.Stopped); err != nil {
				log.Fatalf("Failed to stop service: %v", err)
			}
			fmt.Println("VAP Agent Windows Service stopped successfully.")
			return

		case "run":
			log.Println("Running VAP Agent checkin in foreground...")
			cfg, _ := client.LoadConfigFromRegistry()
			cli := client.NewAgentClient(cfg)
			if err := cli.PerformCheckin(); err != nil {
				log.Fatalf("Checkin failed: %v", err)
			}
			fmt.Println("Foreground checkin completed successfully.")
			return
		}
	}

	inService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine service context: %v", err)
	}

	if inService {
		runService()
		return
	}

	printUsage()
}

func printUsage() {
	fmt.Println("VAP Windows Endpoint Agent v1.0.0")
	fmt.Println("Usage:")
	fmt.Println("  vap-agent.exe enroll --url <BACKEND_URL> --token <ENROLLMENT_TOKEN>")
	fmt.Println("  vap-agent.exe install    # Install Windows Service")
	fmt.Println("  vap-agent.exe start      # Start Windows Service")
	fmt.Println("  vap-agent.exe stop       # Stop Windows Service")
	fmt.Println("  vap-agent.exe uninstall  # Uninstall Windows Service")
	fmt.Println("  vap-agent.exe run        # Perform one-time checkin in foreground")
}

func runService() {
	elog, err := eventlog.Open(serviceName)
	if err == nil {
		defer elog.Close()
		elog.Info(1, "Starting VAP Agent Service")
	}

	err = svc.Run(serviceName, &vapService{})
	if err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("Service failed: %v", err))
		}
		log.Fatalf("Service execution failed: %v", err)
	}
}

func installService() error {
	exepath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exepath, mgr.Config{
		DisplayName: "VAP Endpoint Security Agent",
		Description: serviceDesc,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return err
	}
	defer s.Close()

	_ = eventlog.Install(serviceName, exepath, false, eventlog.Error|eventlog.Warning|eventlog.Info)
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return err
	}
	_ = eventlog.Remove(serviceName)
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	return s.Start()
}

func controlService(c svc.Cmd, to svc.State) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	status, err := s.Control(c)
	if err != nil {
		return fmt.Errorf("could not send control %d: %v", c, err)
	}

	if status.State != to {
		cmd := exec.Command("sc.exe", "stop", serviceName)
		_ = cmd.Run()
	}
	return nil
}
