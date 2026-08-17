//go:build windows

package worker

// Windows side of the platform seam for launching runtime/harness child
// processes. See platform_unix.go for the Unix half; the two files must
// declare the same functions.

import (
	"os/exec"
	"syscall"
)

// setNewProcessGroup detaches the child from the console's Ctrl+C group --
// the closest Windows analogue to Setpgid's intent on Unix -- so a console
// interrupt reaches scrutineer's own graceful shutdown first instead of
// being broadcast straight to every child.
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// terminateProcessGroup best-effort kills the direct child. Windows has no
// signalable process groups, so grandchildren a dead engine CLI left behind
// are not reaped here; container cleanup relies on `run --rm` instead.
func terminateProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}

// containerUserArgs returns no `--user` flag on Windows: there is no host
// uid/gid to map (os.Getuid reports -1), and Docker Desktop's Linux VM
// presents Windows bind mounts as world-writable regardless of container
// uid, so the runner image's own non-root `runner` user applies instead.
func containerUserArgs() []string {
	return nil
}
