//go:build windows

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procOpenMutexW          = kernel32.NewProc("OpenMutexW")
	procCreateMutexW        = kernel32.NewProc("CreateMutexW")
	procReleaseMutex        = kernel32.NewProc("ReleaseMutex")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")

	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
)

const (
	SYNCHRONIZE          = 0x00100000
	WAIT_ABANDONED       = 0x00000080
	WAIT_OBJECT_0        = 0x00000000
	WAIT_TIMEOUT         = 0x00000102
	WAIT_FAILED          = 0xFFFFFFFF
	ERROR_FILE_NOT_FOUND = 2
	MUTEX_TIMEOUT_MS     = 500
)

func IsAdmin() bool {
	ret, _, _ := procIsUserAnAdmin.Call()
	return ret != 0
}

func ApplyMkdtempPermissions(path string) {
	// subprocess.call(["icacls", dirpath, "/inheritance:e", "/grant", "*S-1-5-32-545:(OI)(CI)(RX)"])
	cmd := exec.Command("icacls", path, "/inheritance:e", "/grant", "*S-1-5-32-545:(OI)(CI)(RX)")
	cmd.Run()
}

// shellCommand runs command through cmd.exe the way Python's
// subprocess.Popen(shell=True) does: `%ComSpec% /c "command"`.
func shellCommand(command string) *exec.Cmd {
	comspec := os.Getenv("ComSpec")
	if comspec == "" {
		comspec = "cmd.exe"
	}
	cmd := exec.Command(comspec)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: fmt.Sprintf(`%s /c "%s"`, comspec, command)}
	return cmd
}

// findPython returns the interpreter for /execpy: the -python flag, else
// python.exe from PATH (skipping the Microsoft Store alias stub), else the
// install locations the Windows analyzer's python package searches, else py.exe.
func findPython() (string, error) {
	if pythonPath != "" {
		return pythonPath, nil
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "python.exe")
		if strings.Contains(strings.ToLower(p), `\microsoft\windowsapps\`) {
			continue
		}
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	globs := [][]string{
		{"LOCALAPPDATA", "Python", "pythoncore-*", "python.exe"},
		{"LOCALAPPDATA", "Programs", "Python", "Python*", "python.exe"},
		{"ProgramFiles", "Python*", "python.exe"},
		{"ProgramFiles(x86)", "Python*", "python.exe"},
		{"HOMEDRIVE", "Python*", "python.exe"},
	}
	for _, g := range globs {
		base := os.Getenv(g[0])
		if base == "" {
			continue
		}
		if g[0] == "HOMEDRIVE" {
			base += `\`
		}
		if matches, _ := filepath.Glob(filepath.Join(append([]string{base}, g[1:]...)...)); len(matches) > 0 {
			// Newest version first: Python313 over Python39.
			sort.Slice(matches, func(i, j int) bool { return naturalLess(matches[j], matches[i]) })
			return matches[0], nil
		}
	}
	if p := filepath.Join(os.Getenv("SystemRoot"), "py.exe"); fileExists(p) {
		return p, nil
	}
	if p, err := exec.LookPath("py.exe"); err == nil {
		return p, nil
	}
	return "", errors.New("no Python interpreter found; start the agent with -python <path>")
}

// naturalLess compares strings with digit runs ordered numerically.
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		na, nb := digitPrefix(a), digitPrefix(b)
		if na > 0 && nb > 0 {
			if na != nb {
				return na < nb
			}
			if a[:na] != b[:nb] {
				return a[:na] < b[:nb]
			}
			a, b = a[na:], b[nb:]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func digitPrefix(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Windows mutex ownership belongs to the OS thread that acquired it, and Go
// moves goroutines between threads, so a mutex acquired in one request could
// not be released in another. All mutex calls therefore run on one locked thread.
var mutexCalls = make(chan func())

// agentMutexes holds the handles of mutexes held by the agent; only touched on the mutex thread.
var agentMutexes = make(map[string]uintptr)

func init() {
	go func() {
		runtime.LockOSThread()
		for f := range mutexCalls {
			f()
		}
	}()
}

func onMutexThread(f func()) {
	done := make(chan struct{})
	mutexCalls <- func() {
		f()
		close(done)
	}
	<-done
}

func acquireMutex(name string) (int, string) {
	if _, ok := agentMutexes[name]; ok {
		return 200, fmt.Sprintf("have mutex: %s", name)
	}

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 500, fmt.Sprintf("error accessing mutex: %v", err)
	}
	h, _, err := procOpenMutexW.Call(uintptr(SYNCHRONIZE), 0, uintptr(unsafe.Pointer(namePtr)))
	if h == 0 {
		if err == syscall.Errno(ERROR_FILE_NOT_FOUND) {
			return 404, "mutex not found"
		}
		return 500, fmt.Sprintf("error accessing mutex: %v", err)
	}

	ret, _, err := procWaitForSingleObject.Call(h, uintptr(MUTEX_TIMEOUT_MS))
	switch uint32(ret) {
	case WAIT_ABANDONED, WAIT_OBJECT_0:
		agentMutexes[name] = h
		return 201, fmt.Sprintf("got mutex: %s", name)
	}
	syscall.CloseHandle(syscall.Handle(h))
	switch uint32(ret) {
	case WAIT_TIMEOUT:
		return 408, "timeout waiting for mutex"
	case WAIT_FAILED:
		return 500, fmt.Sprintf("failed waiting for mutex: %v", err)
	}
	return 500, fmt.Sprintf("failed waiting for mutex: %d", ret)
}

func releaseAgentMutex(name string) (int, string) {
	h, ok := agentMutexes[name]
	if !ok {
		return 404, fmt.Sprintf("mutex does not exist: %s", name)
	}
	delete(agentMutexes, name)

	ret, _, err := procReleaseMutex.Call(h)
	syscall.CloseHandle(syscall.Handle(h))
	if ret == 0 {
		return 500, fmt.Sprintf("failed releasing mutex: %v", err)
	}
	return 200, fmt.Sprintf("released mutex: %s", name)
}

func HandleMutexPlatform(w http.ResponseWriter, r *agentRequest) {
	mutexName := r.form["mutex"]
	if mutexName == "" {
		jsonError(w, 400, "no mutex provided")
		return
	}

	var code int
	var message string
	onMutexThread(func() {
		if r.Method == "POST" {
			code, message = acquireMutex(mutexName)
		} else {
			code, message = releaseAgentMutex(mutexName)
		}
	})
	if code >= 400 {
		jsonError(w, code, message)
		return
	}
	writeJSON(w, code, message, nil)
}
