//go:build !windows

package main

import (
	"net/http"
	"os/exec"
	"runtime"
)

func IsAdmin() bool {
	return false // Simplification for non-windows or non-root
}

func ApplyMkdtempPermissions(path string) {
	// No-op for unix usually, or chmod
}

func shellCommand(command string) *exec.Cmd {
	return exec.Command("/bin/sh", "-c", command)
}

func findPython() (string, error) {
	if pythonPath != "" {
		return pythonPath, nil
	}
	if p, err := exec.LookPath("python3"); err == nil {
		return p, nil
	}
	return exec.LookPath("python")
}

func HandleMutexPlatform(w http.ResponseWriter, r *agentRequest) {
	jsonError(w, 400, "mutex feature not supported on "+runtime.GOOS)
}
