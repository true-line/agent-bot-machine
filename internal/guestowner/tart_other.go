//go:build !darwin

package guestowner

import (
	"context"
	"errors"
	"github.com/qwts/managed-machine/internal/daemon"
)

func ObserveTartGuest(context.Context, daemon.Caller, string, string, string, string, string) (daemon.GuestTartObservation, error) {
	return daemon.GuestTartObservation{}, errors.New("Tart observation requires macOS")
}
