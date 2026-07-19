//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName        = "FortrixAgent"
	installDirName = "Fortrix"
	uninstallKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FortrixAgent`
)

type fortrixService struct{}

func (s *fortrixService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Clean up stale backup from any previous update, then start agent.
	cleanupOldBackup()

	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		runAgent()
	}()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(done)
				<-agentDone
				return false, 0
			}
		case <-agentDone:
			// Agent loop exited on its own (e.g. update applied).
			// Report failure so SCM recovery actions restart us from the new binary.
			changes <- svc.Status{State: svc.StopPending}
			return false, 1
		}
	}
}

// maybeRunAsService returns true when the process is running under the
// Windows Service Control Manager, in which case it takes over execution.
func maybeRunAsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	setupServiceLog()
	if err := svc.Run(svcName, &fortrixService{}); err != nil {
		log.Fatalf("service: %v", err)
	}
	return true
}

// setupServiceLog redirects the standard logger to a file alongside the exe,
// since services have no console.
func setupServiceLog() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(exe), "fortrix-agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		log.SetOutput(f)
	}
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot get executable path: %w", err)
	}

	// Self-install to Program Files if not already there.
	targetDir := filepath.Join(os.Getenv("ProgramFiles"), installDirName)
	targetExe := filepath.Join(targetDir, filepath.Base(exe))

	if !sameFile(exe, targetExe) {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("cannot create %s: %w", targetDir, err)
		}
		if err := copyFile(exe, targetExe); err != nil {
			return fmt.Errorf("cannot copy to %s: %w", targetExe, err)
		}
		log.Printf("copied agent to %s", targetExe)
		exe = targetExe
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists; run -uninstall first", svcName)
	}
	s, err = m.CreateService(svcName, exe, mgr.Config{
		DisplayName: "Fortrix Agent",
		Description: "Fortrix Endpoint Protection Platform Agent — monitors for data exfiltration threats",
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("cannot create service: %w", err)
	}
	defer s.Close()
	// Set restart on failure.
	s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 60_000},
		{Type: mgr.ServiceRestart, Delay: 120_000},
		{Type: mgr.NoAction, Delay: 0},
	}, 86400)

	// Write Windows uninstall registry key (appears in Programs & Features).
	writeUninstallKey(targetExe)

	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %s not found", svcName)
	}
	defer s.Close()
	// Stop the service first if running.
	if _, err := s.Control(svc.Stop); err != nil {
		log.Printf("warning: could not stop service: %v", err)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("cannot delete service: %w", err)
	}

	// Remove uninstall registry key.
	deleteUninstallKey()

	// Remove install directory (clean).
	exe, _ := os.Executable()
	installDir := filepath.Dir(exe)
	if strings.EqualFold(filepath.Base(installDir), installDirName) {
		if err := os.RemoveAll(installDir); err != nil {
			log.Printf("warning: could not remove install dir: %v", err)
		}
	}
	return nil
}

func writeUninstallKey(exe string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE|registry.CREATE_SUB_KEY)
	if err != nil {
		log.Printf("warning: could not open uninstall registry key: %v", err)
		return
	}
	defer k.Close()
	setStr := func(name, value string) {
		if err := k.SetStringValue(name, value); err != nil {
			log.Printf("warning: could not set uninstall/%s: %v", name, err)
		}
	}
	setStr("DisplayName", "Fortrix Agent")
	setStr("Publisher", "Fortrix")
	setStr("DisplayVersion", agentVersion)
	setStr("UninstallString", fmt.Sprintf(`"%s" -uninstall`, exe))
	setStr("QuietUninstallString", fmt.Sprintf(`"%s" -uninstall`, exe))
	setStr("URLInfoAbout", "https://fortrix.xyz")
	setStr("InstallLocation", filepath.Dir(exe))
	setStr("NoModify", "1")
	setStr("NoRepair", "1")
	setStr("EstimatedSize", "10000")
	log.Printf("uninstall key written: %s", uninstallKey)
}

func deleteUninstallKey() {
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey); err != nil {
		log.Printf("warning: could not delete uninstall key: %v", err)
	}
}

func sameFile(a, b string) bool {
	aa, _ := filepath.Abs(a)
	bb, _ := filepath.Abs(b)
	return strings.EqualFold(aa, bb)
}
