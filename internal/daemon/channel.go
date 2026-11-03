package daemon

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/qwts/managed-machine/internal/provider/brew"
)

const channelEnv = "AGENT_MACHINE_CHANNEL"

// ChannelDir is the traversable socket directory. It holds only the unix
// socket and daemon.pub. Private keys stay in the prefix owner's
// ~/.config/agent-machine (0700). Tests set AGENT_MACHINE_CHANNEL.
func ChannelDir() string {
	if p := os.Getenv(channelEnv); p != "" {
		return p
	}
	return defaultChannelDir()
}

func defaultChannelDir() string {
	prefix := brew.DefaultPrefix(runtime.GOOS + "/" + runtime.GOARCH)
	if prefix == "" {
		return ""
	}
	return filepath.Join(prefix, "var", "agent-machine")
}

// ChannelSocket is the path a client dials. On Windows it is the named pipe.
func ChannelSocket() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\agent-machine`
	}
	dir := ChannelDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "daemon.sock")
}

// EnrollDropDir is the world-writable sticky drop on the channel. The
// prefix owner creates it; a user writes <client>.pub there so enroll
// does not need to read the user's 0700 state directory.
func EnrollDropDir() string {
	if ch := ChannelDir(); ch != "" {
		return filepath.Join(ch, "enroll")
	}
	return ""
}

func ensureEnrollDir(channel string) error {
	if channel == "" {
		return nil
	}
	dir := filepath.Join(channel, "enroll")
	enrollMode := os.FileMode(0o733)
	if runtime.GOOS != "windows" {
		enrollMode |= os.ModeSticky
	}
	if err := os.MkdirAll(dir, enrollMode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	return os.Chmod(dir, enrollMode)
}

// defaultEnrollPub is the drop pair --enroll reads when no path is given.
func defaultEnrollPub(client string) string {
	if client == "" {
		client = "terminal"
	}
	dir := EnrollDropDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, client+".pub")
}
