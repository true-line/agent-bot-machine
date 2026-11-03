package daemon

import (
	"fmt"
	"time"
)

const healthyWait = 8 * time.Second

// SocketListening reports whether the executor accepts a connection.
func SocketListening(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	conn, err := dialDaemon(endpoint)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// WaitListening polls until the socket accepts or d elapses.
func WaitListening(endpoint string, d time.Duration) error {
	if d <= 0 {
		d = healthyWait
	}
	deadline := time.Now().Add(d)
	for {
		if SocketListening(endpoint) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("daemon socket %s did not accept within %s", endpoint, d)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func serviceState(unitOn, listening bool) string {
	if listening {
		return "running"
	}
	if unitOn {
		return "installed"
	}
	return "absent"
}
