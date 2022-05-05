// Package lockfile handles pid file based locking.
// While a sync.Mutex helps against concurrency issues within a single process,
// this package is designed to help against concurrency issues between cooperating processes
// or serializing multiple invocations of the same process. You can also combine sync.Mutex
// with Lockfile in order to serialize an action between different goroutines in a single program
// and also multiple invocations of this program.
package lockfile

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Lockfile is a pid file which can be locked
type Lockfile string

// TemporaryError is a type of error where a retry after a random amount of sleep should help to mitigate it.
type TemporaryError string

func (t TemporaryError) Error() string { return string(t) }

// Temporary returns always true.
// It exists, so you can detect it via
//	if te, ok := err.(interface{ Temporary() bool }); ok {
//		fmt.Println("I am a temporary error situation, so wait and retry")
//	}
func (t TemporaryError) Temporary() bool { return true }

// Various errors returned by this package
var (
	ErrBusy          = TemporaryError("Locked by other process")             // If you get this, retry after a short sleep might help
	ErrNotExist      = TemporaryError("Lockfile created, but doesn't exist") // If you get this, retry after a short sleep might help
	ErrNeedAbsPath   = errors.New("Lockfiles must be given as absolute path names")
	ErrInvalidPid    = errors.New("Lockfile contains invalid pid for system")
	ErrDeadOwner     = errors.New("Lockfile contains pid of process not existent on this system anymore")
	ErrRogueDeletion = errors.New("Lockfile owned by me has been removed unexpectedly")
)

// New describes a new filename located at the given absolute path.
func New(path string) (Lockfile, error) {
	if !filepath.IsAbs(path) {
		return Lockfile(""), ErrNeedAbsPath
	}

	return Lockfile(path), nil
}

// GetOwner returns who owns the lockfile.
// 谁拥有 lockfile
func (l Lockfile) GetOwner() (*os.Process, error) {
	name := string(l)

	// Ok, see, if we have a stale lockfile here
	// stale：过时的
	//
	// ReadFile 读取由 filename 命名的文件并返回内容。
	// 成功的调用返回 err == nil，而不是 err == EOF。 因为 ReadFile 读取整个文件，所以它不会将 Read 中的 EOF 视为要报告的错误。
	// 从 Go 1.16 开始，此函数仅调用 os.ReadFile。
	content, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	// try hard for pids. If no pid, the lockfile is junk anyway and we delete it.
	pid, err := scanPidLine(content)
	if err != nil {
		return nil, err
	}

	running, err := isRunning(pid)
	if err != nil {
		return nil, err
	}

	if running {
		proc, err := os.FindProcess(pid)
		if err != nil {
			return nil, err
		}

		return proc, nil
	}

	return nil, ErrDeadOwner
}

// TryLock tries to own the lock.
// It Returns nil, if successful and and error describing the reason, it didn't work out.
// Please note, that existing lockfiles containing pids of dead processes
// and lockfiles containing no pid at all are simply deleted.
// TryLock 尝试拥有锁。
// 它返回 nil，如果成功; 返回错误描述原因, 如果它没有成功。
// 请注意，包含死进程 pid 的现有锁文件和根本不包含 pid 的锁文件会被简单地删除。
func (l Lockfile) TryLock() error {
	name := string(l)

	// This has been checked by New already. If we trigger here,
	// the caller didn't use New and re-implemented it's functionality badly.
	// So panic, that he might find this easily during testing.
	// 这已经被 New 检查过了。
	// 如果我们在这里触发，调用者并没有使用 New 并且严重地重新实现了它的功能。
	// panic，他可能在测试期间很容易发现这一点。
	if !filepath.IsAbs(name) {
		panic(ErrNeedAbsPath)
	}

	tmplock, cleanup, err := makePidFile(name, os.Getpid())
	if err != nil {
		return err
	}

	defer cleanup()

	// EEXIST and similar error codes, caught by os.IsExist, are intentionally ignored,
	// as it means that someone was faster creating this link
	// and ignoring this kind of error is part of the algorithm.
	// Then we will probably fail the pid owner check later, if this process is still alive.
	// We cannot ignore ALL errors, since failure to support hard links, disk full
	// as well as many other errors can happen to a filesystem operation
	// and we really want to abort on those.
	//
	// 由 os.IsExist 捕获的 EEXIST 和类似错误代码被有意忽略，因为这意味着有人更快地创建了此链接，而忽略此类错误是算法的一部分。
	// 如果这个进程还活着，我们稍后可能会失败 pid 所有者检查。
	// 我们不能忽略所有错误，因为无法支持硬链接、磁盘已满以及许多其他错误都可能发生在文件系统操作中，我们真的想中止这些错误。

	// Link 创建新名称作为旧名称文件的硬链接。 如果有错误，它将是 *LinkError 类型。
	if err := os.Link(tmplock, name); err != nil {
		// IsExist 返回一个布尔值，指示是否已知错误以报告文件或目录已存在。 ErrExist 以及一些系统调用错误都满足了它。
		//
		// 此功能早于 errors.Is。 它只支持 os 包返回的错误。 新代码应该使用 errors.Is(err, fs.ErrExist)。
		if !os.IsExist(err) {
			return err
		}
	}

	// Lstat 返回描述命名文件的 FileInfo。
	// 如果文件是符号链接，则返回的 FileInfo 描述符号链接。 Lstat 不会尝试跟踪该链接。 如果有错误，它将是 *PathError 类型。
	fiTmp, err := os.Lstat(tmplock)
	if err != nil {
		return err
	}

	fiLock, err := os.Lstat(name)
	if err != nil {
		// tell user that a retry would be a good idea
		if os.IsNotExist(err) {
			return ErrNotExist
		}

		return err
	}

	// Success
	// SameFile 报告 fi1 和 fi2 是否描述同一个文件。
	// 例如，在 Unix 上，这意味着两个底层结构的 device 和 inode 字段是相同的；
	// 在其他系统上，该决定可能基于路径名。 SameFile 仅适用于此包的 Stat 返回的结果。 在其他情况下它返回 false。
	if os.SameFile(fiTmp, fiLock) {
		return nil
	}

	proc, err := l.GetOwner()
	switch err {
	default:
		// Other errors -> defensively fail and let caller handle this
		return err
	case nil:
		if proc.Pid != os.Getpid() {
			return ErrBusy
		}
	case ErrDeadOwner, ErrInvalidPid: // cases we can fix below
	}

	// pid 文件 进程不存在, 清理 pidfile, 并重新创建新的 pidfile 文件

	// clean stale/invalid lockfile
	err = os.Remove(name)
	if err != nil {
		// If it doesn't exist, then it doesn't matter who removed it.
		if !os.IsNotExist(err) {
			return err
		}
	}

	// now that the stale lockfile is gone, let's recurse
	return l.TryLock()
}

// Unlock a lock again, if we owned it. Returns any error that happened during release of lock.
func (l Lockfile) Unlock() error {
	proc, err := l.GetOwner()
	switch err {
	case ErrInvalidPid, ErrDeadOwner:
		return ErrRogueDeletion
	case nil:
		if proc.Pid == os.Getpid() {
			// we really own it, so let's remove it.
			return os.Remove(string(l))
		}
		// Not owned by me, so don't delete it.
		return ErrRogueDeletion
	default:
		// This is an application error or system error.
		// So give a better error for logging here.
		if os.IsNotExist(err) {
			return ErrRogueDeletion
		}
		// Other errors -> defensively fail and let caller handle this
		return err
	}
}

func scanPidLine(content []byte) (int, error) {
	if len(content) == 0 {
		return 0, ErrInvalidPid
	}

	var pid int
	// Sscanln 类似于 Sscan，但在换行处停止扫描，并且在最后一项之后必须有换行符或 EOF。
	//
	// Sscan 扫描参数字符串，将连 续的空格分隔值 存储到 连续的参数中。 换行符算作空格。
	// 它返回成功扫描的项目数。 如果这小于参数的数量，则 err 将报告原因。
	if _, err := fmt.Sscanln(string(content), &pid); err != nil {
		return 0, ErrInvalidPid
	}

	if pid <= 0 {
		return 0, ErrInvalidPid
	}

	return pid, nil
}

func makePidFile(name string, pid int) (tmpname string, cleanup func(), err error) {
	// TempFile 在目录 dir 中创建一个新的临时文件，打开文件进行读写，并返回生成的 *os.File。
	//
	// 文件名: 是通过采用 pattern 并在末尾添加一个随机字符串来生成的。
	// 如果 pattern 包含“*”，则随机字符串替换最后一个“*”。
	//
	// 如果 dir 是空字符串，则 TempFile 使用临时文件的默认目录（请参阅 os.TempDir）。
	//
	// 多个程序同时调用 TempFile 不会选择同一个文件。 调用者可以使用 f.Name() 来查找文件的路径名。
	//
	// 不再需要时删除文件是调用者的责任。
	tmplock, err := ioutil.TempFile(filepath.Dir(name), filepath.Base(name)+".")
	if err != nil {
		return "", nil, err
	}

	cleanup = func() {
		// Close 关闭文件，使其无法用于 I/O。
		// 在支持 SetDeadline 的文件上，任何挂起的 I/O 操作都将被取消并立即返回 ErrClosed 错误。
		// 如果它已经被调用，Close 将返回一个错误。
		_ = tmplock.Close()

		// Remove 删除命名文件或（空）目录。 如果有错误，它将是 *PathError 类型。
		_ = os.Remove(tmplock.Name())
	}

	// WriteString 将字符串 s 的内容写入 w，它接受一个字节切片。
	// 如果 w 实现了 StringWriter，则直接调用它的 WriteString 方法。
	// 否则，w.Write 只被调用一次。
	if _, err := io.WriteString(tmplock, fmt.Sprintf("%d\n", pid)); err != nil {
		cleanup() // Do cleanup here, so call doesn't have to.
		return "", nil, err
	}

	return tmplock.Name(), cleanup, nil
}
