package logger

// Logger defines operational logging — engine-internal debug/info/
// error messages for developers debugging their own deployment. This
// is distinct from store.AuditStore, which records queryable,
// security-relevant domain events (login, logout, token reuse, etc.).
//
// v2 ships one implementation: ConsoleJSONLogger. The consuming app
// wires whatever Logger it wants (file, cloud, console) — the engine
// never ships logs anywhere on its own. See project note on the
// zero-telemetry principle.
type Logger interface {
	Debug(msg string, fields map[string]string)
	Info(msg string, fields map[string]string)
	Warn(msg string, fields map[string]string)
	Error(msg string, fields map[string]string)
}
