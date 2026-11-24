//go:build !darwin

package members

import "os"

func syncSavedPlanFile(f *os.File) error { return f.Sync() }
