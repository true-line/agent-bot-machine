//go:build darwin

package members

import (
	"fmt"
	"strings"
	"testing"
)

func TestCooperativeLaunchdObserverPinsLoadedJobAndPID(t *testing.T) {
	const id = "installation-1"
	paths, err := cooperativeLaunchPaths(id)
	if err != nil {
		t.Fatal(err)
	}
	job := fmt.Sprintf("system/%s = {\n\tpath = %s\n\tprogram = %s\n\targuments = {\n\t\t%s\n\t\tcooperative-dispatch\n\t\t%s\n\t}\n\tpid = 582\n}\n",
		paths.label, paths.plist, SoulLauncher, SoulLauncher, id)
	if pid, err := parseSoulCooperativeLaunchdPID([]byte(job), paths, id); err != nil || pid != 582 {
		t.Fatalf("fixed loaded job refused: pid=%d err=%v", pid, err)
	}
	for name, changed := range map[string]string{
		"different plist":        strings.Replace(job, paths.plist, "/tmp/other.plist", 1),
		"different executable":   strings.Replace(job, "program = "+SoulLauncher, "program = /tmp/other", 1),
		"different dispatcher":   strings.Replace(job, "cooperative-dispatch", "soul-run", 1),
		"different installation": strings.Replace(job, "\t\t"+id+"\n", "\t\tother\n", 1),
		"duplicate pid":          strings.Replace(job, "\tpid = 582\n", "\tpid = 582\n\tpid = 583\n", 1),
	} {
		if _, err := parseSoulCooperativeLaunchdPID([]byte(changed), paths, id); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
