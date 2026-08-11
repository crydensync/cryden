package auth

import "github.com/crydensync/cryden/v2/store"

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
