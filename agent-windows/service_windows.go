//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const svcName = "FortrixAgent"

type fortrixService struct{}

func (s *fortrixService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
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
			// Agent loop exited on its own (fatal error). Report failure so
			// SCM recovery actions can restart us.
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
	return s.Delete()
}


