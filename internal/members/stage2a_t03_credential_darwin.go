//go:build darwin

package members

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Only the sibling-UID child calls this. It never reads credential contents.
// Descriptor-relative no-follow traversal binds the reported metadata to a
// real file under that child's private home.
func observeStage2aT03Credential(home, path string, uid, gid uint32) (Stage2aT03CredentialMetadata, string, error) {
	var empty Stage2aT03CredentialMetadata
	if uid == 0 || gid == 0 || !stage2aAbsolutePath(home) || !stage2aAbsolutePath(path) ||
		!strings.HasPrefix(path, home+"/") {
		return empty, "", errStage2aReservationAuthority
	}
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, "../") {
		return empty, "", errStage2aReservationAuthority
	}
	parts := strings.Split(relative, "/")
	if len(parts) < 2 || len(parts) > 16 {
		return empty, "", errStage2aReservationAuthority
	}
	fd, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, "", errStage2aReservationAuthority
	}
	defer func() { unix.Close(fd) }()
	paths := []string{home}
	current := home
	checkDir := func(openFD int, name string) bool {
		var held, named unix.Stat_t
		return unix.Fstat(openFD, &held) == nil && unix.Lstat(name, &named) == nil &&
			stage2aSameNode(held, named) && held.Mode == unix.S_IFDIR|0700 &&
			held.Uid == uid && held.Gid == gid
	}
	if !checkDir(fd, home) {
		return empty, "", errStage2aReservationAuthority
	}
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return empty, "", errStage2aReservationAuthority
		}
		unix.Close(fd)
		fd = next
		paths = append(paths, current)
		if !checkDir(fd, current) {
			return empty, "", errStage2aReservationAuthority
		}
	}
	fileFD, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, "", errStage2aReservationAuthority
	}
	defer unix.Close(fileFD)
	var file, named unix.Stat_t
	if unix.Fstat(fileFD, &file) != nil || unix.Lstat(path, &named) != nil ||
		!stage2aSameNode(file, named) || file.Mode&unix.S_IFMT != unix.S_IFREG ||
		file.Mode&07777 != 0400 && file.Mode&07777 != 0600 ||
		file.Uid != uid || file.Gid != gid || file.Nlink != 1 || file.Size <= 0 ||
		checkDarwinACLs(append(paths, path)) != nil {
		return empty, "", errStage2aReservationAuthority
	}
	meta := Stage2aT03CredentialMetadata{
		Schema: "agent-bot-machine/stage2a-t03-credential-metadata/v1", Path: path,
		Device: strconv.FormatInt(int64(file.Dev), 10), Inode: strconv.FormatUint(file.Ino, 10),
		Generation: strconv.FormatUint(uint64(file.Gen), 10), UID: file.Uid, GID: file.Gid,
		Mode: fmt.Sprintf("%04o", file.Mode&07777), SizeBytes: strconv.FormatInt(file.Size, 10),
		BirthSeconds: strconv.FormatInt(file.Btim.Sec, 10), BirthNanos: strconv.FormatInt(file.Btim.Nsec, 10),
		ModifySeconds: strconv.FormatInt(file.Mtim.Sec, 10), ModifyNanos: strconv.FormatInt(file.Mtim.Nsec, 10),
		ChangeSeconds: strconv.FormatInt(file.Ctim.Sec, 10), ChangeNanos: strconv.FormatInt(file.Ctim.Nsec, 10),
	}
	raw, err := marshalStage2aReservationJCS(meta)
	if err != nil {
		return empty, "", errStage2aReservationAuthority
	}
	return meta, stage2aReservationSHA256(raw), nil
}
