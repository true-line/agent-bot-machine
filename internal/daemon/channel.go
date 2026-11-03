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
