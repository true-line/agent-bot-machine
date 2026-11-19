//go:build !darwin

package daemon

func prepareMachineLifecycle(string) error { return nil }
