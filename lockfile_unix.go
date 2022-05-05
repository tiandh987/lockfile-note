// +build darwin dragonfly freebsd linux nacl netbsd openbsd solaris aix

package lockfile

import (
	"os"
	"syscall"
)

func isRunning(pid int) (bool, error) {
	// FindProcess 通过其 pid 查找正在运行的进程。
	//
	// 它返回的 Process 可用于获取有关底层操作系统进程的信息。
	//
	//在 Unix 系统上，FindProcess 总是成功并为给定的 pid 返回一个 Process，无论该进程是否存在。
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}

	// Signal 向进程发送信号。
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false, nil
	}

	return true, nil
}
