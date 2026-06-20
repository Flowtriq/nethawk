package capture

import "time"

// Source is the interface that both live capture and demo mode implement.
type Source interface {
	Start()
	Stop()
	Ticker() <-chan Snapshot
	Interface() string
	Uptime() time.Duration
}
