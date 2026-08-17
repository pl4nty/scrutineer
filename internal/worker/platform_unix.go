//go:build !windows

package worker

// Unix side of the platform seam for launching runtime/harness child
// processes. See platform_windows.go for the Windows half; the two files
// must declare the same functions.

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// setNewProcessGroup places the about-to-start command in its own process
// group so terminateProcessGroup can later signal the whole tree (the engine
// or harness CLI plus any children it spawned), not just the direct child.
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateProcessGroup best-effort SIGTERMs the started command's process
// group, reaping stragglers the direct child left behind after Wait returned.
func terminateProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

// containerUserArgs returns the `--user uid:gid` run flags that make the scan
// container run as the invoking host user, so bind-mount writes (scan output,
// the resumable session store) land owned by that user rather than root.
func containerUserArgs() []string {
	return []string{"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())}
}
