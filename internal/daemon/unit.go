package daemon

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	darwinServiceLabel     = "dev.qwts.agent-machine"
	darwinKeydServiceLabel = "dev.qwts.agent-bot.keyd"
)

// A system LaunchDaemon, a systemd system unit, and a Windows service
// registration all need a privilege this daemon does not have. The unit is
// a per-user service of the prefix owner: a LaunchAgent, a systemd user
// unit, or a Windows service description that is written and not registered.
func unitPath(goos, root string) (string, error) {
	switch goos {
	case "darwin":
		return filepath.Join(root, "Library", "LaunchAgents", darwinServiceLabel+".plist"), nil
	case "linux":
		return filepath.Join(root, ".config", "systemd", "user", "agent-machine.service"), nil
	case "windows":
		return filepath.Join(root, "AppData", "Local", "agent-machine", "agent-machine-service.xml"), nil
	default:
		return "", fmt.Errorf("unsupported operating system %q", goos)
	}
}

func unitBody(goos, root, executable, username string) (string, error) {
	exec := strings.TrimSpace(executable)
	if exec == "" {
		return "", fmt.Errorf("daemon executable is required")
	}
	switch goos {
	case "darwin":
		return darwinAgent(root, exec), nil
	case "linux":
		return linuxUserUnit(exec, username), nil
	case "windows":
		return windowsDescription(exec, username), nil
	default:
		return "", fmt.Errorf("unsupported operating system %q", goos)
	}
}

// KeydBinary is the agent-bot-keyd program shipped beside the agent-machine
// executable. A path inside GeniusBar.app is never that program.
func KeydBinary(executable string) (string, error) {
	exec := strings.TrimSpace(executable)
	if exec == "" {
		return "", fmt.Errorf("daemon executable is required")
	}
	bin := filepath.Join(filepath.Dir(exec), "agent-bot-keyd")
	if strings.Contains(bin, "GeniusBar.app") {
		return "", fmt.Errorf("agent-bot-keyd must ship with agent-machine, not GeniusBar")
	}
	return bin, nil
}

func keydUnitPath(goos, root string) (string, error) {
	if goos != "darwin" {
		return "", fmt.Errorf("agent-bot-keyd runs only on darwin")
	}
	return filepath.Join(root, "Library", "LaunchAgents", darwinKeydServiceLabel+".plist"), nil
}

// keyd must start for the prefix owner in either a GUI login or an SSH login.
const keydSessionTypes = `	<key>LimitLoadToSessionType</key>
	<array>
		<string>Aqua</string>
		<string>Background</string>
	</array>
`

func keydAgent(stateDir, bin string) string {
	return renderKeydAgent(stateDir, bin, keydSessionTypes)
}

func renderKeydAgent(stateDir, bin, sessions string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>serve</string>
		<string>--state-dir</string>
		<string>%s</string>
	</array>
%s	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`, darwinKeydServiceLabel, xmlEscape(bin), xmlEscape(stateDir), sessions)
}

func UninstallKeyd(goos, root string) error {
	path, err := keydUnitPath(goos, root)
	if err != nil {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// A change of keg may move the old executable. Compare the full Machine
// template without opening or executing the path in the previous plist.
func machineKeydRegistration(previous []byte, stateDir string) bool {
	var plist struct {
		Arrays []struct {
			Values []string `xml:"string"`
		} `xml:"dict>array"`
	}
	if xml.Unmarshal(previous, &plist) != nil || len(plist.Arrays) == 0 || len(plist.Arrays[0].Values) != 4 {
		return false
	}
	bin := plist.Arrays[0].Values[0]
	if !filepath.IsAbs(bin) || filepath.Base(bin) != "agent-bot-keyd" {
		return false
	}
	body := string(previous)
	// Releases before background login support wrote no session types.
	return body == keydAgent(stateDir, bin) || body == renderKeydAgent(stateDir, bin, "")
}

type keydUnitPlan struct {
	path      string
	body      string
	previous  []byte
	original  os.FileInfo
	published os.FileInfo
}

// A zero plan means that a manual installation will leave keyd alone,
// including during activation rollback.
func planKeydUnit(goos, root, executable, stateDir string) (keydUnitPlan, error) {
	var none keydUnitPlan
	if goos != "darwin" {
		return none, nil
	}
	bin, err := KeydBinary(executable)
	if err != nil {
		return none, err
	}
	_, err = os.Stat(bin)
	bundled := err == nil
	if err != nil && !os.IsNotExist(err) {
		return none, err
	}
	path, err := keydUnitPath(goos, root)
	if err != nil {
		return none, err
	}
	var prior []byte
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode().IsRegular() {
			prior, err = os.ReadFile(path)
			if err != nil {
				return none, err
			}
		}
		if !machineKeydRegistration(prior, stateDir) {
			if bundled {
				return none, fmt.Errorf("preserving an existing keyd LaunchAgent not managed by Machine; resolve the existing installation before starting bundled keyd")
			}
			return none, nil
		}
		if !bundled {
			return none, fmt.Errorf("the existing Machine-managed keyd LaunchAgent requires a bundled helper; restore agent-bot-keyd beside the current Machine executable and retry")
		}
	} else if !os.IsNotExist(err) {
		return none, err
	}
	if !bundled {
		return none, nil
	}
	return keydUnitPlan{path: path, previous: prior, original: info, body: keydAgent(stateDir, bin)}, nil
}

// Confirm both identity and contents before reusing, replacing or rolling
// back an existing registration. Other supervisors share this launchd label.
func (p *keydUnitPlan) verify(info os.FileInfo, body string) error {
	current, err := os.Lstat(p.path)
	if err == nil && current.Mode().IsRegular() && os.SameFile(current, info) {
		data, err := os.ReadFile(p.path)
		if err == nil && string(data) == body {
			return nil
		}
	}
	return fmt.Errorf("keyd LaunchAgent changed during install; preserving the current registration")
}

func (p *keydUnitPlan) write() error {
	if p.path == "" {
		return nil
	}
	if p.original != nil {
		if err := p.verify(p.original, string(p.previous)); err != nil {
			return err
		}
		if string(p.previous) == p.body {
			return nil
		}
	}
	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, info, err := stageUnit(p.path, []byte(p.body))
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if p.original == nil {
		// Another installer may have claimed the label after preflight.
		err = os.Link(tmp, p.path)
	} else if err = p.verify(p.original, string(p.previous)); err == nil {
		err = os.Rename(tmp, p.path)
	}
	if err == nil {
		p.published = info
	}
	return err
}

func (p *keydUnitPlan) rollback() error {
	if p.published == nil {
		return nil
	}
	if err := p.verify(p.published, p.body); err != nil {
		return err
	}
	return restoreUnit(p.path, p.previous)
}

// InstallKeyd installs the helper shipped beside Machine, when present.
func InstallKeyd(goos, root, executable, stateDir string) (string, error) {
	plan, err := planKeydUnit(goos, root, executable, stateDir)
	if err != nil {
		return "", err
	}
	if err := plan.write(); err != nil {
		return "", err
	}
	return plan.path, nil
}

func darwinAgent(root, executable string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>daemon</string>
		<string>run</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key>
		<string>%s</string>
	</dict>
	<key>LimitLoadToSessionType</key>
	<array>
		<string>Aqua</string>
		<string>Background</string>
		<string>StandardIO</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`, darwinServiceLabel, xmlEscape(executable), xmlEscape(root))
}

// linuxWritablePaths are the only paths ProtectSystem=strict leaves writable:
// the Linuxbrew prefix, the npm and uv prefixes under ~/.local, the
// Homebrew, uv and npm caches, and the daemon's state. systemd skips a "-"
// path that does not exist, which would leave a fresh home read-only, so
// Install creates every home-relative path before the unit first starts.
var linuxWritablePaths = []string{
	"-/home/linuxbrew/.linuxbrew",
	"-%h/.local",
	"-%h/.cache",
	"-%h/.npm",
	"%h/.config/agent-machine",
}

func linuxHomeDirs() []string {
	var dirs []string
	for _, path := range linuxWritablePaths {
		if rel, ok := strings.CutPrefix(strings.TrimPrefix(path, "-"), "%h/"); ok {
			dirs = append(dirs, filepath.FromSlash(rel))
		}
	}
	return dirs
}

func linuxUserUnit(executable, _ string) string {
	return fmt.Sprintf(`[Unit]
Description=agent-machine executor
After=default.target

[Service]
Type=simple
ExecStart=%s daemon run
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
ReadWritePaths=%s

[Install]
WantedBy=default.target
`, unitEscape(executable), strings.Join(linuxWritablePaths, " "))
}

func windowsDescription(executable, username string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!-- Written only. Registering a Windows service is a human action. -->
<service>
	<name>agent-machine</name>
	<account>%s</account>
	<command>%s daemon run</command>
</service>
`, xmlEscape(username), xmlEscape(executable))
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func unitEscape(s string) string {
	return strings.ReplaceAll(s, "\n", "")
}

// Install writes the per-user unit. A second call with the same contents
// leaves the file unchanged. The file mode is 0600.
func Install(goos, root, executable, username string) (string, error) {
	path, err := unitPath(goos, root)
	if err != nil {
		return "", err
	}
	body, err := unitBody(goos, root, executable, username)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if goos == "linux" {
		for _, dir := range linuxHomeDirs() {
			if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
				return "", err
			}
		}
	}
	existing, readErr := os.ReadFile(path)
	if readErr == nil && string(existing) == body {
		return path, nil
	}
	if err := replaceUnit(path, []byte(body)); err != nil {
		return "", err
	}
	return path, nil
}

// stageUnit writes a private file beside its destination. On success the caller
// owns the temporary name and must remove it after publication or failure.
func stageUnit(path string, body []byte) (string, os.FileInfo, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".machine-unit-*")
	if err != nil {
		return "", nil, err
	}
	info, statErr := tmp.Stat()
	_, writeErr := tmp.Write(body)
	if err := errors.Join(statErr, writeErr, tmp.Close()); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, err
	}
	return tmp.Name(), info, nil
}

func replaceUnit(path string, body []byte) error {
	tmp, _, err := stageUnit(path, body)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Rename(tmp, path)
}

// readUnit returns the unit file as it is before install, or nil when it is
// absent, so a failed activation can put it back.
func readUnit(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return body, err
}

// restoreUnit undoes Install after the service manager refused the unit:
// a unit that was absent is removed, and one that existed gets its old
// contents back, so status never reports a unit that is not loaded.
func restoreUnit(path string, previous []byte) error {
	if previous == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return replaceUnit(path, previous)
}

// Uninstall removes the unit. A missing unit is success.
func Uninstall(goos, root string) error {
	path, err := unitPath(goos, root)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Installed reports whether the unit file is present.
func Installed(goos, root string) (bool, error) {
	path, err := unitPath(goos, root)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func hostOS() string { return runtime.GOOS }
