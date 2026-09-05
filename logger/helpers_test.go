package logger

import "context"

// record is one captured log call. ctx is non-nil only when the record
// arrived through ContextLogger.Log, which is how these tests tell the
// two paths apart.
type record struct {
	level  Level
	msg    string
	fields map[string]string
	ctx    context.Context
}

// ctxKey is the sort of key a host app's tracing middleware would use —
// its own unexported type, which is exactly why the engine cannot read
// the trace ID itself and has to hand the whole context over.
type ctxKey struct{}

func traceContext(id string) context.Context {
	return context.WithValue(context.Background(), ctxKey{}, id)
}

func traceOf(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// plainLogger implements Logger only — the shape of every host Logger
// written before ContextLogger existed, and the shape that must keep
// working untouched.
type plainLogger struct {
	records []record
}

func (p *plainLogger) Debug(msg string, fields map[string]string) {
	p.records = append(p.records, record{level: LevelDebug, msg: msg, fields: fields})
}

func (p *plainLogger) Info(msg string, fields map[string]string) {
	p.records = append(p.records, record{level: LevelInfo, msg: msg, fields: fields})
}

func (p *plainLogger) Warn(msg string, fields map[string]string) {
	p.records = append(p.records, record{level: LevelWarn, msg: msg, fields: fields})
}

func (p *plainLogger) Error(msg string, fields map[string]string) {
	p.records = append(p.records, record{level: LevelError, msg: msg, fields: fields})
}

var _ Logger = (*plainLogger)(nil)

// ctxLogger implements both interfaces, like a real cloud sink would.
// bare counts calls that came in through the four context-free methods,
// so a test can prove a wrapper did not quietly drop the context.
type ctxLogger struct {
	records []record
	bare    int
}

func (c *ctxLogger) Log(ctx context.Context, level Level, msg string, fields map[string]string) {
	c.records = append(c.records, record{level: level, msg: msg, fields: fields, ctx: ctx})
}

func (c *ctxLogger) Debug(msg string, fields map[string]string) {
	c.recordBare(LevelDebug, msg, fields)
}
func (c *ctxLogger) Info(msg string, fields map[string]string) { c.recordBare(LevelInfo, msg, fields) }
func (c *ctxLogger) Warn(msg string, fields map[string]string) { c.recordBare(LevelWarn, msg, fields) }
func (c *ctxLogger) Error(msg string, fields map[string]string) {
	c.recordBare(LevelError, msg, fields)
}

func (c *ctxLogger) recordBare(level Level, msg string, fields map[string]string) {
	c.bare++
	c.records = append(c.records, record{level: level, msg: msg, fields: fields})
}

var _ ContextLogger = (*ctxLogger)(nil)

func (c *ctxLogger) last() record {
	if len(c.records) == 0 {
		return record{}
	}
	return c.records[len(c.records)-1]
}
