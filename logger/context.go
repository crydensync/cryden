package logger

import "context"

// ContextLogger is an optional second interface a Logger may also
// implement. It is not part of Logger and never will be: adding a
// method to an interface host apps have already implemented breaks
// their build at compile time — the same reasoning that kept
// notify.MagicLinkSender out of notify.EmailSender, and that made
// security.Rehasher a second interface beside security.Hasher rather
// than a fifth method on it.
//
// The engine calls Log in preference to the four Logger methods
// whenever the Logger it holds has it, passing the context of the call
// being served. That context is the only way a sink shipping records to
// Datadog, Better Stack, Cloud Logging or an OpenTelemetry collector
// can put an engine log line in the same trace as the host app's own
// lines: trace and request IDs live in the context under keys the
// engine cannot know and must not invent. Without it, a log line saying
// "login: rate limited" is unattachable to the request it came from,
// which is most of what a hosted aggregator is bought for.
//
// A Logger that does not implement this sees no change of any kind.
type ContextLogger interface {
	Logger
	// Log records one event. Implementations must treat a nil ctx as
	// context.Background() rather than dereferencing it — the four bare
	// Logger methods have no context to give, and a wrapper standing in
	// for one of them will pass exactly that.
	Log(ctx context.Context, level Level, msg string, fields map[string]string)
}

// LogFunc adapts a single function into a complete ContextLogger, so a
// host writing a cloud sink implements one method instead of five:
//
//	var sink logger.ContextLogger = logger.LogFunc(
//		func(ctx context.Context, level logger.Level, msg string, fields map[string]string) {
//			myVendorClient.Send(ctx, level.String(), msg, fields)
//		})
//
// This is the whole of what this package ships toward any particular
// vendor, and deliberately so — the engine makes no outbound network
// call, holds no API key, and has no opinion about batching, retries or
// payload shape. Those belong to whatever client the host already runs.
type LogFunc func(ctx context.Context, level Level, msg string, fields map[string]string)

func (f LogFunc) Log(ctx context.Context, level Level, msg string, fields map[string]string) {
	f(ctx, level, msg, fields)
}

// The four bare methods pass context.Background(), which is what they
// mean: no call in scope to correlate against.
func (f LogFunc) Debug(msg string, fields map[string]string) {
	f(context.Background(), LevelDebug, msg, fields)
}

func (f LogFunc) Info(msg string, fields map[string]string) {
	f(context.Background(), LevelInfo, msg, fields)
}

func (f LogFunc) Warn(msg string, fields map[string]string) {
	f(context.Background(), LevelWarn, msg, fields)
}

func (f LogFunc) Error(msg string, fields map[string]string) {
	f(context.Background(), LevelError, msg, fields)
}

var _ ContextLogger = LogFunc(nil)

// ForContext binds ctx to l, returning a Logger whose four methods
// forward that context to l.Log. This is how the engine keeps its 91
// existing log call sites — every one of them holding a plain Logger
// and no context — while still handing a context-aware sink the context
// of the call being served.
//
// Returns l untouched when it is not a ContextLogger, or when ctx is
// nil, so the console default and every host Logger written before this
// existed keep behaving exactly as they did.
//
// The returned value stores a context in a struct, which is normally
// wrong. It is sound here for the reason that exception exists: the
// binding is created inside one facade call, used only by log statements
// made during that call, and dropped when it returns. Nothing retains
// it, nothing outlives the request, and it is never handed to a
// goroutine that does.
func ForContext(ctx context.Context, l Logger) Logger {
	cl, ok := l.(ContextLogger)
	if !ok || ctx == nil {
		return l
	}
	return contextBound{inner: cl, ctx: ctx}
}

type contextBound struct {
	inner ContextLogger
	ctx   context.Context
}

func (c contextBound) Debug(msg string, fields map[string]string) {
	c.inner.Log(c.ctx, LevelDebug, msg, fields)
}

func (c contextBound) Info(msg string, fields map[string]string) {
	c.inner.Log(c.ctx, LevelInfo, msg, fields)
}

func (c contextBound) Warn(msg string, fields map[string]string) {
	c.inner.Log(c.ctx, LevelWarn, msg, fields)
}

func (c contextBound) Error(msg string, fields map[string]string) {
	c.inner.Log(c.ctx, LevelError, msg, fields)
}

// Log forwards the context it is given rather than the bound one, which
// makes rebinding work: ForContext(inner, ForContext(outer, l)) logs
// against inner, the same as if l had been bound once. Without this a
// second binding would be silently ignored, since the outer wrapper
// would satisfy ContextLogger and swallow the new context.
func (c contextBound) Log(ctx context.Context, level Level, msg string, fields map[string]string) {
	if ctx == nil {
		ctx = c.ctx
	}
	c.inner.Log(ctx, level, msg, fields)
}

var _ ContextLogger = contextBound{}

// emit sends one record to l, using its ContextLogger method when it has
// one so that ctx survives every wrapper in this package. A wrapper that
// forwarded through the four bare methods instead would silently drop
// the context of every host sink placed behind it — filtering by level
// would cost you your trace IDs, which is not a trade anyone would make
// on purpose.
//
// A Level outside the four constants is clamped to the nearest end,
// never dropped: an unrecognized severity is still a record.
func emit(ctx context.Context, l Logger, level Level, msg string, fields map[string]string) {
	if cl, ok := l.(ContextLogger); ok {
		cl.Log(ctx, level, msg, fields)
		return
	}
	switch clamp(level) {
	case LevelDebug:
		l.Debug(msg, fields)
	case LevelInfo:
		l.Info(msg, fields)
	case LevelWarn:
		l.Warn(msg, fields)
	default:
		l.Error(msg, fields)
	}
}
