// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package opsec provides operational-security helpers for the agent: timing
// jitter to break periodic beaconing, and process-name masquerade. These are
// for authorized red-team realism.
package opsec

import (
	"math/rand/v2"
	"time"
)

// Jitter returns d perturbed by up to ±frac (a fraction in [0,1]). It is used to
// avoid perfectly periodic reconnection/heartbeat signals, which are easy to
// fingerprint. frac<=0 returns d unchanged.
func Jitter(d time.Duration, frac float64) time.Duration {
	if frac <= 0 {
		return d
	}
	if frac > 1 {
		frac = 1
	}
	delta := (rand.Float64()*2 - 1) * frac // [-frac, +frac]
	j := time.Duration(float64(d) * (1 + delta))
	if j < 0 {
		j = 0
	}
	return j
}

// SetProcessName attempts to rename the running process so it blends in with
// normal system processes (e.g. "dbus-daemon"). It is best-effort and a no-op
// on platforms that do not support it. See the platform-specific files.
func SetProcessName(name string) {
	setProcessName(name)
}
