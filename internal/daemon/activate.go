package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ActivateUserService loads the per-user unit. It does not use root.
// Windows only writes the description, so activation is a no-op there.
// Darwin bootstraps the GUI domain, then the user domain; "not found" on
// bootstrap is a failure. Kickstart follows a successful load.
func ActivateUserService(goos, path string) error {
	switch goos {
	case "darwin":
		return activateDarwin(path, os.Getuid())
	case "linux":
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
		return systemctl("enable", "--now", "agent-machine.service")
	default:
		return nil
	}
}

func activateDarwin(path string, uid int) error {
	gui := fmt.Sprintf("gui/%d", uid)
	user := fmt.Sprintf("user/%d", uid)
	_ = launchctl("bootout", gui, path)
	_ = launchctl("bootout", user, path)
	label := unitServiceLabel(path)
	if err := launchctl("bootstrap", gui, path); err == nil {
		return launchctl("kickstart", "-k", gui+"/"+label)
	} else {
		guiErr := err
		if err := launchctl("bootstrap", user, path); err == nil {
			return launchctl("kickstart", "-k", user+"/"+label)
		} else {
			return fmt.Errorf("launchctl bootstrap failed (gui: %v; user: %v)", guiErr, err)
		}
	}
}

// ReloadUserService makes systemd reread user units, so a unit file that
// install restored or removed replaces whatever an earlier daemon-reload
// loaded. launchd reads the plist only at bootstrap, so darwin needs nothing.
func ReloadUserService(goos string) error {
	if goos == "linux" {
		return systemctl("daemon-reload")
	}
	return nil
}

// DeactivateUserService unloads the per-user unit. A unit that is not
// loaded is success.
func DeactivateUserService(goos, path string) error {
	switch goos {
	case "darwin":
		uid := os.Getuid()
		err1 := launchctl("bootout", fmt.Sprintf("gui/%d", uid), path)
		err2 := launchctl("bootout", fmt.Sprintf("user/%d", uid), path)
		if err1 == nil || err2 == nil {
			return nil
		}
		return err1
	case "linux":
		err := systemctl("disable", "--now", "agent-machine.service")
		if err == nil || strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return err
	default:
		return nil
	}
}

func unitServiceLabel(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return darwinServiceLabel
	}
	text := string(body)
	const key = "<key>Label</key>"
	i := strings.Index(text, key)
	if i < 0 {
		return darwinServiceLabel
	}
	rest := text[i+len(key):]
	start := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if start < 0 || end < start {
		return darwinServiceLabel
	}
	label := strings.TrimSpace(rest[start+len("<string>") : end])
	if label == "" {
		return darwinServiceLabel
	}
	return label
}

func launchctl(args ...string) error {
	cmd := exec.Command("launchctl", args...)
	cmd.Env = minimalEnv(os.Getenv("HOME"), nil)
	out, err := cmd.CombinedOutput()
	return classifyLaunchctl(args[0], string(out), err)
}

func classifyLaunchctl(op, out string, err error) error {
	if err == nil {
		return nil
	}
	text := strings.ToLower(strings.TrimSpace(out))
	switch op {
	case "bootout":
		if strings.Contains(text, "no such process") ||
			strings.Contains(text, "could not find") ||
			strings.Contains(text, "not found") ||
			strings.Contains(text, "no such file") {
			return nil
		}
	case "bootstrap":
		if strings.Contains(text, "already") {
			return nil
		}
	}
	msg := strings.TrimSpace(out)
	if msg == "" {
		return fmt.Errorf("launchctl %s: %w", op, err)
	}
	return fmt.Errorf("%s: %w", msg, err)
}

func systemctl(args ...string) error {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	cmd.Env = minimalEnv(os.Getenv("HOME"), os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
