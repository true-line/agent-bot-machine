package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const keydProtocol = "2025-06-18"

// initialize reads public server metadata. It does not enumerate tools or use a key.
const keydInitialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + keydProtocol + `","capabilities":{},"clientInfo":{"name":"managed-machine","version":"1"}}}` + "\n"

var (
	errKeydEndpoint = errors.New("cannot verify the administrator's private keyd endpoint")
	errKeydPeer     = errors.New("cannot verify the keyd peer account")
	errKeydReply    = errors.New("keyd did not return its expected initialize response")
)

func waitBundledKeyd(caller Caller, timeout time.Duration) error {
	if caller.UID <= 0 || !caller.DarwinAdmin || caller.PrefixOwner == "" || caller.UID != os.Geteuid() || caller.RegisteredHome == "" || filepath.Clean(caller.Home) != filepath.Clean(caller.RegisteredHome) {
		return errKeydEndpoint
	}
	until := time.Now().Add(timeout)
	for {
		err := probeBundledKeyd(caller.RegisteredHome, caller.UID, time.Now().Add(min(time.Second, time.Until(until))))
		if err == nil || errors.Is(err, errKeydPeer) || !time.Now().Before(until) {
			return err
		}
		time.Sleep(min(50*time.Millisecond, time.Until(until)))
	}
}

func probeBundledKeyd(home string, uid int, deadline time.Time) error {
	dir, err := openOwnerSubdir(home, filepath.Join(".local", "state", "agent-bot", "keyd"))
	if err != nil {
		return errKeydEndpoint
	}
	defer dir.Close()
	var parent, leaf unix.Stat_t
	fd := int(dir.Fd())
	if unix.Fstat(fd, &parent) != nil || parent.Mode&0777 != 0700 ||
		unix.Fstatat(fd, "keyd.sock", &leaf, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		leaf.Mode&(unix.S_IFMT|0777) != unix.S_IFSOCK|0600 || int(leaf.Uid) != uid {
		return errKeydEndpoint
	}
	path := filepath.Join(dir.Name(), "keyd.sock")
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.Dial("unix", path)
	if err != nil {
		return errKeydEndpoint
	}
	defer conn.Close()
	var current unix.Stat_t
	if unix.Lstat(path, &current) != nil || leaf.Dev != current.Dev || leaf.Ino != current.Ino {
		return errKeydEndpoint
	}
	return initializeKeyd(conn, uid, deadline)
}

func initializeKeyd(conn net.Conn, uid int, deadline time.Time) error {
	peer, err := peerCred(conn)
	if err != nil || peer != uid {
		return errKeydPeer
	}
	if conn.SetDeadline(deadline) != nil {
		return errKeydReply
	}
	if _, err := io.WriteString(conn, keydInitialize); err != nil {
		return errKeydReply
	}
	reader := bufio.NewReaderSize(conn, 8192)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return errKeydReply
	}
	var reply struct {
		JSONRPC string
		ID      int
		Error   json.RawMessage
		Result  struct {
			ProtocolVersion string
			ServerInfo      struct{ Name, Version string }
		}
	}
	if json.Unmarshal(line, &reply) != nil || reply.JSONRPC != "2.0" || reply.ID != 1 || reply.Error != nil || reply.Result.ProtocolVersion != keydProtocol ||
		reply.Result.ServerInfo.Name != "agent-bot-keyd" || reply.Result.ServerInfo.Version == "" {
		return errKeydReply
	}
	return nil
}
