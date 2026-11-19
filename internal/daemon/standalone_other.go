//go:build !darwin

package daemon

func prepareMachineLifecycle(string) error { return nil }

func checkMachineAdmission() error { return nil }
