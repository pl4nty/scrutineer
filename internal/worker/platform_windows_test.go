//go:build windows

package worker

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestContainerUserArgsOmitted(t *testing.T) {
	if got := containerUserArgs(); len(got) != 0 {
		t.Errorf("containerUserArgs() = %v, want none (no host uid/gid to map)", got)
	}
}

func TestSetNewProcessGroupDetachesConsoleGroup(t *testing.T) {
	cmd := exec.Command("cmd")
	setNewProcessGroup(cmd)
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.CreationFlags&syscall.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Errorf("SysProcAttr = %+v, want CREATE_NEW_PROCESS_GROUP", cmd.SysProcAttr)
	}
}

func TestTerminateProcessGroupBeforeStart(t *testing.T) {
	// Must be a no-op, not a panic, when the command never started.
	terminateProcessGroup(exec.Command("cmd"))
}
