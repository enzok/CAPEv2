package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	AgentVersion   = "0.25"
	Base64Encoding = "base64"

	// Uploaded files larger than this are spilled to a temporary file (same as agent.py).
	multipartMemoryLimit = 1024 * 1024
	// Captured agent output kept for /logs.
	maxLogBytes = 4 * 1024 * 1024
)

var (
	AgentFeatures = []string{
		"execpy",
		"execute",
		"pinning",
		"logs",
		"largefile",
		"unicodepath",
		"subdir_upload",
		"push",
		"update",
	}
)

func init() {
	if runtime.GOOS == "windows" {
		AgentFeatures = append(AgentFeatures, "mutex", "browser_extension")
	}
}

// Status enums, ordered by their numeric value in agent.py (init=1 ... exception=5).
const (
	StatusInit      = "init"
	StatusRunning   = "running"
	StatusComplete  = "complete"
	StatusFailed    = "failed"
	StatusException = "exception"
)

var statusOrder = []string{StatusInit, StatusRunning, StatusComplete, StatusFailed, StatusException}

var TerminalStatuses = map[string]bool{
	StatusComplete:  true,
	StatusFailed:    true,
	StatusException: true,
}

// parseStatus accepts a status name (any case) or its numeric value, like agent.py's Status enum.
func parseStatus(v string) (string, bool) {
	v = strings.ToLower(v)
	for i, s := range statusOrder {
		if v == s || v == strconv.Itoa(i+1) {
			return s, true
		}
	}
	return "", false
}

// asyncProcess is a subprocess whose exit is reported through GET /status.
type asyncProcess struct {
	cmd      *exec.Cmd
	done     chan struct{}
	exitCode int64
}

func startTracked(cmd *exec.Cmd) (*asyncProcess, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &asyncProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		cmd.Wait()
		p.exitCode = exitCode(cmd.ProcessState)
		close(p.done)
	}()
	return p, nil
}

// exitCode reports Windows exit codes unsigned like Python (e.g. 0xC0000005),
// also on 32-bit builds where int would overflow.
func exitCode(ps *os.ProcessState) int64 {
	code := ps.ExitCode()
	if runtime.GOOS == "windows" && code < -1 {
		return int64(uint32(code))
	}
	return int64(code)
}

// shlexSplit splits a command like Python's shlex.split (POSIX mode, no comments).
// Inside double quotes a backslash only escapes '"' and '\', so quoted Windows paths survive.
func shlexSplit(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inToken, escaped := false, false
	var quote rune
	for _, c := range s {
		switch {
		case escaped:
			if quote == '"' && c != '"' && c != '\\' {
				cur.WriteRune('\\')
			}
			cur.WriteRune(c)
			escaped = false
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteRune(c)
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			} else if c == '\\' {
				escaped = true
			} else {
				cur.WriteRune(c)
			}
		case c == '\\':
			escaped, inToken = true, true
		case c == '\'' || c == '"':
			quote, inToken = c, true
		case strings.ContainsRune(" \t\r\n", c):
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(c)
			inToken = true
		}
	}
	if escaped {
		return nil, errors.New("No escaped character")
	}
	if quote != 0 {
		return nil, errors.New("No closing quotation")
	}
	if inToken {
		args = append(args, cur.String())
	}
	return args, nil
}

// State holds the agent state
type State struct {
	sync.Mutex
	Status          string
	Description     string
	AsyncSubprocess *asyncProcess
	ClientIP        string
}

var state = State{
	Status: StatusInit,
}

// Browser Extension
var agentBrowserExtPath string
var agentBrowserLock sync.Mutex

// Python interpreter for /execpy (-python flag); auto-detected when empty.
var pythonPath string

// LogBuffer captures the agent's own output for /logs, like agent.py's StringIO
// redirection. Only the most recent maxLogBytes are kept.
type LogBuffer struct {
	sync.Mutex
	buf []byte
}

func (l *LogBuffer) Write(p []byte) (n int, err error) {
	l.Lock()
	defer l.Unlock()
	l.buf = append(l.buf, p...)
	if len(l.buf) > maxLogBytes {
		l.buf = l.buf[len(l.buf)-maxLogBytes:]
	}
	return len(p), nil
}

func (l *LogBuffer) String() string {
	l.Lock()
	defer l.Unlock()
	return string(l.buf)
}

var agentLogOut = &LogBuffer{}
var agentLogErr = &LogBuffer{}
var verboseMode bool

// logOut mirrors agent.py's print() (stdout); logErr its request log (stderr).
var logOut = log.New(os.Stdout, "", log.LstdFlags)
var logErr = log.New(os.Stderr, "", log.LstdFlags)

func writeJSON(w http.ResponseWriter, code int, message string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := make(map[string]interface{})
	resp["message"] = message
	for k, v := range data {
		resp[k] = v
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logErr.Printf("Error encoding JSON: %v", err)
	}
}

func jsonError(w http.ResponseWriter, code int, message string, extra ...map[string]interface{}) {
	data := make(map[string]interface{})
	if len(extra) > 0 && extra[0] != nil {
		data = extra[0]
	}
	data["error_code"] = code
	writeJSON(w, code, message, data)
}

// jsonException mirrors agent.py's json_exception: a 500 carrying the error as "traceback".
func jsonException(w http.ResponseWriter, message string, err error) {
	jsonError(w, 500, message, map[string]interface{}{"traceback": fmt.Sprint(err)})
}

func jsonSuccess(w http.ResponseWriter, message string, data map[string]interface{}) {
	writeJSON(w, 200, message, data)
}

// upload is a multipart file part, kept in memory up to multipartMemoryLimit
// and spilled to a temporary file beyond that.
type upload struct {
	mem  []byte
	path string
	size int64
}

func spoolUpload(src io.Reader) (*upload, error) {
	head, err := io.ReadAll(io.LimitReader(src, multipartMemoryLimit+1))
	if err != nil {
		return nil, err
	}
	if len(head) <= multipartMemoryLimit {
		return &upload{mem: head, size: int64(len(head))}, nil
	}
	f, err := os.CreateTemp("", "cape-part-")
	if err != nil {
		return nil, err
	}
	u := &upload{path: f.Name()}
	_, err = f.Write(head)
	if err == nil {
		var n int64
		n, err = io.Copy(f, src)
		u.size = int64(len(head)) + n
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		u.remove()
		return nil, err
	}
	return u, nil
}

// moveTo writes the upload to dest, renaming the spilled file when possible.
func (u *upload) moveTo(dest string) error {
	if u.path == "" {
		return os.WriteFile(dest, u.mem, 0o666)
	}
	if err := os.Rename(u.path, dest); err == nil {
		u.path = ""
		return nil
	}
	// Different volume: fall back to copying.
	src, err := os.Open(u.path)
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, src); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func (u *upload) readerAt() (io.ReaderAt, func(), error) {
	if u.path == "" {
		return bytes.NewReader(u.mem), func() {}, nil
	}
	f, err := os.Open(u.path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

func (u *upload) remove() {
	if u.path != "" {
		os.Remove(u.path)
		u.path = ""
	}
}

// agentRequest carries the parsed form, like agent.py's thread-local request object.
type agentRequest struct {
	*http.Request
	clientIP string
	form     map[string]string
	files    map[string]*upload
}

func (r *agentRequest) has(key string) bool {
	_, ok := r.form[key]
	return ok
}

// parseForm reads urlencoded or multipart bodies for any method (net/http skips
// DELETE bodies). The last value of a repeated field wins and blank urlencoded
// values are dropped, as in agent.py.
func parseForm(r *http.Request) (map[string]string, map[string]*upload, error) {
	form := map[string]string{}
	files := map[string]*upload{}
	mediaType, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mediaType {
	case "multipart/form-data":
		if r.ContentLength == 0 {
			return form, files, nil
		}
		boundary := params["boundary"]
		if boundary == "" {
			return nil, nil, errors.New("Missing boundary in multipart/form-data Content-Type")
		}
		mr := multipart.NewReader(r.Body, boundary)
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err == nil {
				err = readPart(part, form, files)
			}
			if err != nil {
				for _, u := range files {
					u.remove()
				}
				return nil, nil, err
			}
		}
	case "application/x-www-form-urlencoded":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, err
		}
		vals, _ := url.ParseQuery(string(body))
		for k, v := range vals {
			for _, val := range v {
				if val != "" {
					form[k] = val
				}
			}
		}
	}
	return form, files, nil
}

func readPart(part *multipart.Part, form map[string]string, files map[string]*upload) error {
	defer part.Close()
	name := part.FormName()
	if name == "" {
		_, err := io.Copy(io.Discard, part)
		return err
	}
	if part.FileName() == "" {
		b, err := io.ReadAll(part)
		form[name] = string(b)
		return err
	}
	u, err := spoolUpload(part)
	if err != nil {
		return err
	}
	if old := files[name]; old != nil {
		old.remove()
	}
	files[name] = u
	return nil
}

type handlerFunc func(http.ResponseWriter, *agentRequest)

// routes maps path -> method -> handler; anything else is a JSON 404 like agent.py.
var routes = map[string]map[string]handlerFunc{
	"/":                  {"GET": handleIndex},
	"/status":            {"GET": handleGetStatus, "POST": handlePostStatus},
	"/logs":              {"GET": handleLogs},
	"/system":            {"GET": handleSystem},
	"/environ":           {"GET": handleEnviron},
	"/path":              {"GET": handlePath},
	"/mkdir":             {"POST": handleMkdir},
	"/mktemp":            {"GET": handleMktemp, "POST": handleMktemp},
	"/mkdtemp":           {"GET": handleMkdtemp, "POST": handleMkdtemp},
	"/store":             {"POST": handleStore},
	"/retrieve":          {"POST": handleRetrieve},
	"/push":              {"POST": handlePush},
	"/update":            {"POST": handleUpdate},
	"/extract":           {"POST": handleExtract},
	"/remove":            {"POST": handleRemove},
	"/execute":           {"POST": handleExecute},
	"/execpy":            {"POST": handleExecPy},
	"/pinning":           {"GET": handlePinning},
	"/kill":              {"GET": handleKill},
	"/browser_extension": {"POST": handleBrowserExtension},
	"/mutex":             {"POST": HandleMutexPlatform, "DELETE": HandleMutexPlatform},
}

func serveAgent(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	logErr.Printf("%s \"%s %s %s\"", clientIP, r.Method, r.URL.RequestURI(), r.Proto)

	if !checkSecurity(w, r) {
		return
	}
	fn := routes[r.URL.Path][r.Method]
	if fn == nil {
		jsonError(w, 404, "Route not found")
		return
	}

	req := &agentRequest{Request: r, clientIP: clientIP, form: map[string]string{}, files: map[string]*upload{}}
	if r.Method == "POST" || r.Method == "DELETE" {
		form, files, err := parseForm(r)
		if err != nil {
			jsonError(w, 400, fmt.Sprintf("Invalid form data: %v", err))
			return
		}
		req.form, req.files = form, files
		defer func() {
			for _, u := range files {
				u.remove()
			}
		}()
	}
	fn(w, req)
}

var server *http.Server
var shutdownOnce sync.Once
var shutdownDone = make(chan struct{})

func main() {
	host := flag.String("host", "0.0.0.0", "Host to bind to")
	port := flag.Int("port", 8000, "Port to bind to")
	verbose := flag.Bool("v", false, "Verbose logging")
	python := flag.String("python", "", "Python interpreter used by /execpy (default: auto-detect)")
	flag.Parse()

	// Also accept agent.py's positional form: agent.exe [host] [port]
	if flag.NArg() > 0 {
		*host = flag.Arg(0)
	}
	if flag.NArg() > 1 {
		p, err := strconv.Atoi(flag.Arg(1))
		if err != nil {
			log.Fatalf("invalid port %q", flag.Arg(1))
		}
		*port = p
	}
	pythonPath = *python
	verboseMode = *verbose

	if !verboseMode {
		logOut.SetOutput(agentLogOut)
		logErr.SetOutput(agentLogErr)
		log.SetOutput(agentLogErr)
	}

	addr := net.JoinHostPort(*host, strconv.Itoa(*port))
	logOut.Printf("Starting CAPE Agent on %s\n", addr)

	server = &http.Server{Addr: addr, Handler: http.HandlerFunc(serveAgent)}

	// Retry logic for binding port (useful during self-update restart)
	var err error
	for i := 0; i < 10; i++ {
		err = server.ListenAndServe()
		if err == http.ErrServerClosed {
			// /kill: wait for in-flight responses to finish.
			<-shutdownDone
			break
		}
		if err != nil {
			// Check for "Address already in use"
			if strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "Only one usage of each socket address") {
				logOut.Printf("Port %d busy, retrying in 1s...\n", *port)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalf("ListenAndServe(): %v", err)
		}
		break
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe(): %v", err)
	}
}

// checkSecurity middleware-ish logic
func checkSecurity(w http.ResponseWriter, r *http.Request) bool {
	// 1. IP Security (Block Localhost / Own IP)
	// This prevents malware inside the VM from driving the agent.
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	// Like the Python agent, loopback may POST /status and /browser_extension
	// (analyzer and browser extension run inside the guest); all else is blocked.
	isLoopback := clientIP == "127.0.0.1" || clientIP == "::1"
	if isLoopback && r.Method == "POST" && (r.URL.Path == "/status" || r.URL.Path == "/browser_extension") {
		return true
	}

	// Always block loopback
	if isLoopback {
		// Exception: Status check might be useful locally?
		// Python agent allowed status/browser_ext from localhost.
		// Strict mode: Block all.
		// "The check seems to be preventing *malware inside the VM* (localhost) from using the Agent to escalate?"
		// Yes.
		// However, for debugging, maybe we want it. But for security, block it.
		// Let's stick to strict blocking unless specific minimal endpoints.
		if r.URL.Path != "/status" {
			http.Error(w, "Access Denied (Localhost)", http.StatusForbidden)
			return false
		}
	}

	// Check against own IP (if we can detect it easily).
	// GetLocalIP() gets the outbound IP.
	// If clientIP == GetLocalIP(), it's also a self-call.
	if clientIP == GetLocalIP() && r.URL.Path != "/status" {
		http.Error(w, "Access Denied (Self)", http.StatusForbidden)
		return false
	}

	// 2. IP Pinning (Legacy/Standard Feature)
	state.Lock()
	defer state.Unlock()

	if state.ClientIP != "" && state.ClientIP != clientIP {
		jsonError(w, 403, "Agent pinned to different IP")
		return false
	}

	return true
}

func handleIndex(w http.ResponseWriter, r *agentRequest) {
	isAdmin := IsAdmin()
	jsonSuccess(w, "CAPE Agent!", map[string]interface{}{
		"version":       AgentVersion,
		"features":      AgentFeatures,
		"is_user_admin": isAdmin,
	})
}

func handleGetStatus(w http.ResponseWriter, r *agentRequest) {
	state.Lock()
	defer state.Unlock()

	p := state.AsyncSubprocess
	if state.Status == StatusComplete || p == nil {
		jsonSuccess(w, "Analysis status", map[string]interface{}{
			"status":      state.Status,
			"description": state.Description,
		})
		return
	}

	select {
	case <-p.done:
		// Process completed; report its exit code once and reset async subprocess state.
		state.AsyncSubprocess = nil
		if p.exitCode == 0 {
			state.Status = StatusComplete
			state.Description = ""
		} else {
			state.Status = StatusFailed
			state.Description = fmt.Sprintf("Exited with exit code %d", p.exitCode)
		}
		jsonSuccess(w, "Analysis status", map[string]interface{}{
			"status":      state.Status,
			"description": state.Description,
			"exitcode":    p.exitCode,
		})
	default:
		state.Status = StatusRunning
		jsonSuccess(w, "Analysis status", map[string]interface{}{
			"status":      state.Status,
			"description": state.Description,
			"process_id":  p.cmd.Process.Pid,
		})
	}
}

func handlePostStatus(w http.ResponseWriter, r *agentRequest) {
	if expected := os.Getenv("X_CAPE_AUTH_TOKEN"); expected != "" {
		token := r.Header.Get("X-CAPE-Auth-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			jsonError(w, 403, "Unauthorized")
			return
		}
	}

	status, ok := parseStatus(r.form["status"])
	if !ok {
		jsonError(w, 400, "No valid status has been provided")
		return
	}

	state.Lock()
	defer state.Unlock()

	if TerminalStatuses[status] {
		// Reject in-guest attempts to set terminal statuses; the final state
		// comes from the async subprocess exit, not from HTTP POSTs.
		if r.clientIP == "127.0.0.1" || r.clientIP == "::1" {
			jsonError(w, 403, "Unauthorized")
			return
		}
		state.AsyncSubprocess = nil
	}

	state.Status = status
	state.Description = r.form["description"]

	jsonSuccess(w, "Analysis status updated", nil)
}

func handleLogs(w http.ResponseWriter, r *agentRequest) {
	stdout, stderr := "verbose mode, stdout not saved", "verbose mode, stderr not saved"
	if !verboseMode {
		stdout, stderr = agentLogOut.String(), agentLogErr.String()
	}
	jsonSuccess(w, "Agent logs", map[string]interface{}{
		"stdout": stdout,
		"stderr": stderr,
	})
}

func handleSystem(w http.ResponseWriter, r *agentRequest) {
	// Same spelling as Python's platform.system(), e.g. "Windows".
	jsonSuccess(w, "System", map[string]interface{}{
		"system": strings.ToUpper(runtime.GOOS[:1]) + runtime.GOOS[1:],
	})
}

func handleEnviron(w http.ResponseWriter, r *agentRequest) {
	envMap := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		// Skip Windows per-drive entries such as "=C:=C:\".
		if len(pair) == 2 && pair[0] != "" {
			key := pair[0]
			if runtime.GOOS == "windows" {
				// Python's os.environ upper-cases keys on Windows.
				key = strings.ToUpper(key)
			}
			envMap[key] = pair[1]
		}
	}
	jsonSuccess(w, "Environment variables", map[string]interface{}{
		"environ": envMap,
	})
}

func handlePath(w http.ResponseWriter, r *agentRequest) {
	ex, err := os.Executable()
	if err != nil {
		ex = os.Args[0]
	}
	path, _ := filepath.Abs(ex)
	jsonSuccess(w, "Agent path", map[string]interface{}{
		"filepath": path,
	})
}

func handleMkdir(w http.ResponseWriter, r *agentRequest) {
	if !r.has("dirpath") {
		jsonError(w, 400, "No dirpath has been provided")
		return
	}

	mode := 0o777
	if v, ok := r.form["mode"]; ok {
		m, err := strconv.Atoi(v)
		if err != nil {
			jsonException(w, "Error creating directory", err)
			return
		}
		mode = m
	}
	if err := os.MkdirAll(r.form["dirpath"], os.FileMode(mode)); err != nil {
		jsonException(w, "Error creating directory", err)
		return
	}
	jsonSuccess(w, "Successfully created directory", nil)
}

func handleMktemp(w http.ResponseWriter, r *agentRequest) {
	f, err := os.CreateTemp(r.form["dirpath"], r.form["prefix"]+"*"+r.form["suffix"])
	if err != nil {
		jsonException(w, "Error creating temporary file", err)
		return
	}
	f.Close()
	jsonSuccess(w, "Successfully created temporary file", map[string]interface{}{"filepath": f.Name()})
}

func handleMkdtemp(w http.ResponseWriter, r *agentRequest) {
	d, err := os.MkdirTemp(r.form["dirpath"], r.form["prefix"]+"*"+r.form["suffix"])
	if err != nil {
		jsonException(w, "Error creating temporary directory", err)
		return
	}

	// Windows ICACLS equivalent
	ApplyMkdtempPermissions(d)

	jsonSuccess(w, "Successfully created temporary directory", map[string]interface{}{"dirpath": d})
}

func handleStore(w http.ResponseWriter, r *agentRequest) {
	if !r.has("filepath") {
		jsonError(w, 400, "No filepath has been provided")
		return
	}
	file := r.files["file"]
	if file == nil {
		jsonError(w, 400, "No file has been provided")
		return
	}

	filepathStr := r.form["filepath"]
	if dirpath := filepath.Dir(filepathStr); dirpath != "." {
		if err := os.MkdirAll(dirpath, os.ModePerm); err != nil {
			jsonException(w, fmt.Sprintf("Error storing file: %v", err), err)
			return
		}
	}
	if err := file.moveTo(filepathStr); err != nil {
		jsonException(w, fmt.Sprintf("Error storing file: %v", err), err)
		return
	}

	jsonSuccess(w, "Successfully stored file", nil)
}

func handleRetrieve(w http.ResponseWriter, r *agentRequest) {
	if !r.has("filepath") {
		jsonError(w, 400, "No filepath has been provided")
		return
	}

	filepathStr := r.form["filepath"]
	fi, err := os.Stat(filepathStr)
	if err != nil || !fi.Mode().IsRegular() {
		jsonError(w, 404, "File not found")
		return
	}
	f, err := os.Open(filepathStr)
	if err != nil {
		jsonError(w, 404, "File not found")
		return
	}
	defer f.Close()

	switch {
	case r.form["streaming"] == "1":
		streamFile(w, r, f)
	case r.form["encoding"] == Base64Encoding:
		w.WriteHeader(200)
		encoder := base64.NewEncoder(base64.StdEncoding, w)
		io.Copy(encoder, f)
		encoder.Close()
	default:
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
		w.WriteHeader(200)
		io.Copy(w, f)
	}
}

// streamFile follows a growing file like `tail -f` until the client disconnects.
func streamFile(w http.ResponseWriter, r *agentRequest, f *os.File) {
	w.WriteHeader(200)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
			continue
		}
		if err != nil && err != io.EOF {
			logErr.Printf("Error reading file %s: %v", f.Name(), err)
			return
		}
		select {
		case <-r.Context().Done():
			logErr.Printf("Client disconnected while reading %s", f.Name())
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	logErr.Printf("Client disconnected while reading %s", f.Name())
}

func handleUpdate(w http.ResponseWriter, r *agentRequest) {
	file := r.files["file"]
	if file == nil {
		jsonError(w, 400, "No file provided")
		return
	}

	// 1. Determine paths
	currentExe, err := os.Executable()
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Cannot find own executable path: %v", err))
		return
	}

	// Check permissions/directory
	dir := filepath.Dir(currentExe)
	newExe := currentExe + ".new"
	oldExe := currentExe + ".old"

	// Clean up previous leftovers if any
	os.Remove(newExe)
	os.Remove(oldExe)

	// 2. Save new binary
	if err := file.moveTo(newExe); err != nil {
		jsonError(w, 500, fmt.Sprintf("Cannot save new file: %v", err))
		return
	}

	// Make executable (Linux/Mac)
	os.Chmod(newExe, 0755)

	// 3. Rename-Replace Dance
	// Windows allows renaming the running binary.
	if err := os.Rename(currentExe, oldExe); err != nil {
		jsonError(w, 500, fmt.Sprintf("Failed to move current exe: %v", err))
		os.Remove(newExe)
		return
	}

	if err := os.Rename(newExe, currentExe); err != nil {
		// Try to rollback
		os.Rename(oldExe, currentExe)
		jsonError(w, 500, fmt.Sprintf("Failed to replace exe: %v", err))
		return
	}

	// 4. Spawn new process
	// We pass the same arguments.
	cmd := exec.Command(currentExe, os.Args[1:]...)
	cmd.Dir = dir

	// Detach process logic varies by OS, but Start() usually leaves it running if we exit main.
	// On Windows, it's fine.
	if err := cmd.Start(); err != nil {
		// Rollback attempt
		os.Rename(oldExe, currentExe) // Might fail if locked now?
		jsonError(w, 500, fmt.Sprintf("Failed to restart agent: %v", err))
		return
	}

	jsonSuccess(w, "Agent updated and restarting", nil)

	// 5. Commit Suicide (Gracefully)
	go func() {
		time.Sleep(1 * time.Second) // Give the response time to flush
		os.Exit(0)
	}()
}

func handlePush(w http.ResponseWriter, r *agentRequest) {
	filepathStr := r.form["filepath"]

	// Security: We only upload back to the Caller (Requestor).
	// We ignore "target_url" if it points to a different IP.
	// Actually, let's just use the Caller IP and a provided port (or default 8000).

	if filepathStr == "" {
		jsonError(w, 400, "No filepath provided")
		return
	}

	// Open file
	f, err := os.Open(filepathStr)
	if err != nil {
		jsonError(w, 404, fmt.Sprintf("File not found: %v", err))
		return
	}
	defer f.Close()

	// Determine target
	clientIP := r.clientIP

	// Allow user to specify port?
	// For simplicity, let's assume standard CAPE resultserver port or provided in "port" param.
	targetPort := r.form["port"]
	if targetPort == "" {
		targetPort = "8000"
	} // Default CAPE port? Usually 2042 or 8000.

	// Allow specific path?
	uploadPath := r.form["upload_path"]
	if uploadPath == "" {
		uploadPath = "/upload"
	} // Standard path

	targetURL := fmt.Sprintf("http://%s%s", net.JoinHostPort(clientIP, targetPort), uploadPath)

	// Do upload
	req, err := http.NewRequest("POST", targetURL, f)
	if err != nil {
		jsonError(w, 500, fmt.Sprintf("Error creating request: %v", err))
		return
	}
	// Send Content-Length instead of chunked encoding, which simple receivers reject.
	if fi, err := f.Stat(); err == nil {
		req.ContentLength = fi.Size()
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Filename", filepath.Base(filepathStr))

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		jsonError(w, 502, fmt.Sprintf("Error uploading to %s: %v", targetURL, err))
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		jsonError(w, resp.StatusCode, fmt.Sprintf("Upload failed: %s", string(respBody)))
		return
	}

	jsonSuccess(w, "File uploaded successfully", nil)
}

func handleExtract(w http.ResponseWriter, r *agentRequest) {
	if !r.has("dirpath") {
		jsonError(w, 400, "No dirpath has been provided")
		return
	}
	file := r.files["zipfile"]
	if file == nil {
		jsonError(w, 400, "No zip file has been provided")
		return
	}

	ra, closeZip, err := file.readerAt()
	if err == nil {
		defer closeZip()
		var zr *zip.Reader
		if zr, err = zip.NewReader(ra, file.size); err == nil {
			err = extractZip(zr, r.form["dirpath"])
		}
	}
	if err != nil {
		jsonException(w, fmt.Sprintf("Error extracting zip file %v", err), err)
		return
	}

	jsonSuccess(w, "Successfully extracted zip file", nil)
}

var invalidWindowsNameChars = strings.NewReplacer(":", "_", "<", "_", ">", "_", "|", "_", "\"", "_", "?", "_", "*", "_")

// extractZip sanitizes member names the way Python's ZipFile.extractall does:
// drive letters, empty, "." and ".." components are dropped, so no entry can
// escape dirpath (ZipSlip).
func extractZip(zr *zip.Reader, dirpath string) error {
	for _, zf := range zr.File {
		name := filepath.FromSlash(strings.ReplaceAll(zf.Name, "\\", "/"))
		name = name[len(filepath.VolumeName(name)):]
		parts := []string{dirpath}
		for _, p := range strings.Split(name, string(os.PathSeparator)) {
			if runtime.GOOS == "windows" {
				// Also blocks NTFS alternate data streams ("file:stream").
				p = strings.TrimRight(invalidWindowsNameChars.Replace(p), ". ")
			}
			if p != "" && p != "." && p != ".." {
				parts = append(parts, p)
			}
		}
		if len(parts) == 1 {
			continue
		}
		fpath := filepath.Join(parts...)

		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}
		if err := extractZipFile(zf, fpath); err != nil {
			return err
		}
	}
	return nil
}

func extractZipFile(zf *zip.File, fpath string) error {
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(fpath)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func handleRemove(w http.ResponseWriter, r *agentRequest) {
	if !r.has("path") {
		jsonError(w, 400, "No path has been provided")
		return
	}
	path := r.form["path"]

	fi, err := os.Stat(path)
	if err != nil {
		jsonError(w, 404, "Path provided does not exist")
		return
	}

	var message string
	if fi.IsDir() {
		// Clear read-only attributes so everything can be deleted.
		filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				os.Chmod(p, 0o666)
			}
			return nil
		})
		err = os.RemoveAll(path)
		message = "Successfully deleted directory"
	} else {
		if err = os.Chmod(path, 0o666); err == nil {
			err = os.Remove(path)
		}
		message = "Successfully deleted file"
	}
	if err != nil {
		jsonException(w, "Error removing file or directory", err)
		return
	}
	jsonSuccess(w, message, nil)
}

func outputData(stdout, stderr []byte, b64 bool) map[string]interface{} {
	if b64 {
		return map[string]interface{}{
			"stdout": base64.StdEncoding.EncodeToString(stdout),
			"stderr": base64.StdEncoding.EncodeToString(stderr),
		}
	}
	return map[string]interface{}{
		"stdout": string(stdout),
		"stderr": string(stderr),
	}
}

func handleExecute(w http.ResponseWriter, r *agentRequest) {
	if !r.has("command") {
		jsonError(w, 400, "No command has been provided")
		return
	}
	command := r.form["command"]

	// Only allow the date command from the guest itself, so malware inside
	// the VM can't drive the agent (same rule as agent.py).
	localIP := GetLocalIP()
	allowedCommands := map[string]bool{"date": true, "cmd /c date /t": true}
	isLocal := r.clientIP == "127.0.0.1" || r.clientIP == "::1" || r.clientIP == localIP
	if isLocal && !allowedCommands[command] {
		jsonError(w, 500, "Not allowed to execute commands")
		return
	}

	var cmd *exec.Cmd
	if r.has("shell") {
		cmd = shellCommand(command)
	} else {
		// Robust splitting for quoted arguments
		parts, err := shlexSplit(command)
		if err != nil {
			jsonError(w, 400, fmt.Sprintf("Error parsing command: %v", err))
			return
		}
		if len(parts) == 0 {
			jsonError(w, 400, "Empty command")
			return
		}
		cmd = exec.Command(parts[0], parts[1:]...)
	}
	cmd.Dir = r.form["cwd"]

	data := map[string]interface{}{"stdout": nil, "stderr": nil}
	var err error
	if r.has("async") {
		// Like agent.py, not tracked by /status (that would block /execpy of the analyzer).
		if err = cmd.Start(); err == nil {
			go cmd.Wait()
		}
	} else {
		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
		err = cmd.Run()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// A non-zero exit code is not an error, as with Popen.communicate().
			err = nil
		}
		data = outputData(stdoutBuf.Bytes(), stderrBuf.Bytes(), r.form["encoding"] == Base64Encoding)
	}

	state.Lock()
	defer state.Unlock()
	if err != nil {
		state.Status = StatusFailed
		state.Description = "Error execute command"
		jsonException(w, fmt.Sprintf("Error executing command: %v", err), err)
		return
	}
	state.Status = StatusRunning
	state.Description = ""
	jsonSuccess(w, "Successfully executed command", data)
}

func handleExecPy(w http.ResponseWriter, r *agentRequest) {
	if !r.has("filepath") {
		jsonError(w, 400, "No Python file has been provided")
		return
	}

	failed := func(err error) {
		state.Status = StatusFailed
		state.Description = "Error executing Python command"
		jsonException(w, fmt.Sprintf("Error executing Python command: %v", err), err)
	}

	state.Lock()
	defer state.Unlock()

	python, err := findPython()
	if err != nil {
		failed(err)
		return
	}
	cmd := exec.Command(python, r.form["filepath"])
	cmd.Dir = r.form["cwd"]

	if r.has("async") {
		if state.Status == StatusRunning && state.AsyncSubprocess != nil {
			jsonError(w, 400, "Async process already running.")
			return
		}
		p, err := startTracked(cmd)
		if err != nil {
			failed(err)
			return
		}
		state.Status = StatusRunning
		state.Description = ""
		state.AsyncSubprocess = p
		jsonSuccess(w, "Successfully spawned command", map[string]interface{}{
			"process_id": cmd.Process.Pid,
		})
		return
	}

	// Sync: don't hold the state lock while the script runs.
	state.Unlock()
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err = cmd.Run()
	state.Lock()

	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		failed(err)
		return
	}
	data := outputData(stdoutBuf.Bytes(), stderrBuf.Bytes(), r.form["encoding"] == Base64Encoding)
	if err == nil {
		state.Status = StatusComplete
		state.Description = ""
		jsonSuccess(w, "Successfully executed command", data)
		return
	}
	// Process exited with non-zero result.
	message := "Error executing python command."
	state.Status = StatusFailed
	state.Description = message
	data["exitcode"] = exitCode(exitErr.ProcessState)
	jsonError(w, 400, message, data)
}

func handlePinning(w http.ResponseWriter, r *agentRequest) {
	state.Lock()
	defer state.Unlock()

	if state.ClientIP != "" {
		jsonError(w, 500, "Agent has already been pinned to an IP!")
		return
	}

	state.ClientIP = r.clientIP
	if token := r.Header.Get("X-CAPE-Auth-Token"); token != "" {
		os.Setenv("X_CAPE_AUTH_TOKEN", token)
	} else {
		logOut.Println("no auth token supplied during pinning; agent authentication is disabled")
	}

	jsonSuccess(w, "Successfully pinned Agent", map[string]interface{}{
		"client_ip": r.clientIP,
	})
}

func handleKill(w http.ResponseWriter, r *agentRequest) {
	jsonSuccess(w, "Quit the CAPE Agent", nil)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	// Graceful shutdown: stop accepting, let in-flight responses finish, then main() returns.
	shutdownOnce.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(ctx)
			close(shutdownDone)
		}()
	})
}

func handleBrowserExtension(w http.ResponseWriter, r *agentRequest) {
	agentBrowserLock.Lock()
	defer agentBrowserLock.Unlock()

	// (Re)create the log folder if it doesn't exist yet or was deleted.
	if fi, err := os.Stat(filepath.Dir(agentBrowserExtPath)); agentBrowserExtPath == "" || err != nil || !fi.IsDir() {
		tmpDir, err := os.MkdirTemp("", "")
		if err != nil {
			jsonException(w, "Error creating temporary directory", err)
			return
		}
		agentBrowserExtPath = filepath.Join(tmpDir, "bext_"+randomLetters(11)+".json")
	}

	data := r.form["networkData"]
	if data != "" {
		if token := os.Getenv("X_CAPE_AUTH_TOKEN"); token != "" {
			if signed, err := signNetworkData(data, token); err == nil {
				data = signed
			} else {
				logOut.Printf("failed to sign browser extension log: %v\n", err)
			}
		}
		if err := writeFileAtomic(agentBrowserExtPath, data); err != nil {
			jsonException(w, "Error writing the browser extension log", err)
			return
		}
	}

	jsonSuccess(w, "OK", nil)
}

func randomLetters(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// writeFileAtomic replaces path via a temp file, retrying while a reader
// (the analyzer's browsermonitor) briefly holds the destination open.
func writeFileAtomic(path, data string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		return err
	}
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if err = os.Rename(tmp, path); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

// Helpers

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

// signNetworkData adds an HMAC-SHA256 "signature" over the JSON payload so the
// guest-side browsermonitor can reject logs the agent did not originate. The
// canonical form must byte-match Python's
// json.dumps(data, sort_keys=True, separators=(",", ":")), which it verifies with.
func signNetworkData(data, token string) (string, error) {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", fmt.Errorf("trailing data after JSON value")
	}
	obj, ok := v.(map[string]interface{})
	if !ok {
		return data, nil
	}
	delete(obj, "signature")
	var canonical strings.Builder
	writePyJSON(&canonical, obj)
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(canonical.String()))
	obj["signature"] = hex.EncodeToString(mac.Sum(nil))
	// Written with the same ASCII-only encoder, as Python's json.dumps does.
	var out strings.Builder
	writePyJSON(&out, obj)
	return out.String(), nil
}

// writePyJSON encodes v like Python's json.dumps with sort_keys=True,
// separators=(",", ":") and the default ensure_ascii=True.
func writePyJSON(b *strings.Builder, v interface{}) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case json.Number:
		b.WriteString(pyNumber(t))
	case string:
		writePyString(b, t)
	case []interface{}:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writePyJSON(b, e)
		}
		b.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writePyString(b, k)
			b.WriteByte(':')
			writePyJSON(b, t[k])
		}
		b.WriteByte('}')
	}
}

// pyNumber renders a JSON number the way Python re-serializes it: integers
// verbatim, floats with repr() (exponent form when exp < -4 or >= 16).
func pyNumber(n json.Number) string {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		return s
	}
	f, err := n.Float64()
	if err != nil {
		return s
	}
	e := strconv.FormatFloat(f, 'e', -1, 64)
	exp, _ := strconv.Atoi(e[strings.IndexByte(e, 'e')+1:])
	if exp < -4 || exp >= 16 {
		return e
	}
	s = strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

func writePyString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
			} else if r > 0xffff {
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			} else {
				fmt.Fprintf(b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
}
