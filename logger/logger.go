// Package logger is the engine's operational logging seam.
//
// The engine never ships a log line anywhere itself: it holds a Logger
// and calls it. Everything that leaves the machine belongs to the host
// app, exactly as with notify.EmailSender and
// security.BreachedPasswordChecker, and for the same reason — an
// embedded auth engine that opened its own connection to a third party
// would be making a decision that is not its to make.
//
// So there is no DatadogLogger here, and there will not be one. Sending
// records to a hosted aggregator is an outbound network call with an API
// key, a batching policy and a retry policy attached, and every host app
// large enough to want one already runs a client for it. What this
// package ships instead is the local half, which is the half that is
// awkward to write twice:
//
//   - ContextLogger and LogFunc, so a host sink can be written in one
//     method and receives the context of the call being logged — the
//     only way an engine log line can land in the same trace as the host
//     app's own lines.
//   - LevelFilter, so debug records are dropped before a vendor charges
//     for them.
//   - Redactor, so a person's IP address is masked or hashed before it
//     leaves your infrastructure, without giving up the ability to
//     correlate.
//   - MultiLogger, so full-detail records can stay on stdout while a
//     redacted, filtered copy goes out.
//
// The intended composition, and the order that matters:
//
//	Logger: logger.NewMultiLogger(
//		logger.NewConsoleJSONLogger(),                     // full detail, stays here
//		logger.NewLevelFilter(                             // shipped out, cheaply
//			logger.NewMaskingRedactor(vendorSink),         // and without the PII
//			logger.LevelInfo,
//		),
//	)
//
// Redacting inside the fan-out rather than around it is the point: your
// own stdout keeps the IP address you need for debugging, and only the
// copy that leaves the building loses it.
//
// Note that flushing is not in this package. A sink that batches is
// constructed by the host, so the host holds it and can flush or close
// it at shutdown; wrapping it here would not change that, and the engine
// owning a third party's lifecycle is what every other injected
// dependency here deliberately avoids.
package logger

// Logger defines operational logging — engine-internal debug/info/
// error messages for developers debugging their own deployment. This
// is distinct from store.AuditStore, which records queryable,
// security-relevant domain events (login, logout, token reuse, etc.).
//
// The engine's default is ConsoleJSONLogger: one JSON object per line
// on stdout, the 12-factor shape any log shipper can already tail. The
// consuming app wires whatever Logger it wants instead (file, cloud,
// console, several at once) — the engine never ships logs anywhere on
// its own. See project note on the zero-telemetry principle.
//
// This is the interface every call site in the engine holds, and it is
// frozen: a Logger written against the first release still compiles and
// still works. Anything added since is either a separate optional
// interface a Logger may also implement (ContextLogger) or a wrapper
// around one (LevelFilter, Redactor, MultiLogger).
type Logger interface {
	Debug(msg string, fields map[string]string)
	Info(msg string, fields map[string]string)
	Warn(msg string, fields map[string]string)
	Error(msg string, fields map[string]string)
}
