package auth

import (
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// testLogger is a no-op Logger for tests — keeps test output clean
// without needing to assert on log content.
type testLogger struct{}

func (testLogger) Debug(msg string, fields map[string]string) {}
func (testLogger) Info(msg string, fields map[string]string)  {}
func (testLogger) Warn(msg string, fields map[string]string)  {}
func (testLogger) Error(msg string, fields map[string]string) {}

func storeUser(id, email, passwordHash string) store.User {
	return store.User{ID: id, Email: email, PasswordHash: passwordHash}
}

// noAnomalyThresholds is what every test predating anomaly detection
// passes. Those tests all run with a nil store.AnomalyStore, which
// short-circuits detection before any threshold is consulted, so the
// zero value here is never actually read — it exists so those call
// sites say "detection off" instead of carrying a distracting
// security.AnomalyThresholds{} literal apiece.
var noAnomalyThresholds = security.AnomalyThresholds{}
