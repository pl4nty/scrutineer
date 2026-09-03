//go:build !windows

package worker

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"testing"
)

func TestContainerUserArgsMapHostUser(t *testing.T) {
	want := []string{"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())}
	if got := containerUserArgs(); !slices.Equal(got, want) {
		t.Errorf("containerUserArgs() = %v, want %v", got, want)
	}
}

func TestSetNewProcessGroupSetsPgid(t *testing.T) {
	cmd := exec.Command("true")
	setNewProcessGroup(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Errorf("SysProcAttr = %+v, want Setpgid", cmd.SysProcAttr)
	}
}

func TestTerminateProcessGroupBeforeStart(t *testing.T) {
	// Must be a no-op, not a panic, when the command never started.
	terminateProcessGroup(exec.Command("true"))
}
