package daemon

import "github.com/qwts/managed-machine/internal/statedir"

func safeMembersPlanACL(fd int, directory bool) bool {
	return statedir.SafeMacPathACL(fd, directory)
}
