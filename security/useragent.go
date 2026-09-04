package security

import "strings"

// Form factor values reported by Device.Form. Deliberately coarse — a
// User-Agent string cannot reliably distinguish more than this, and a
// "your devices" list does not need it to.
const (
	FormDesktop = "desktop"
	FormMobile  = "mobile"
	FormTablet  = "tablet"
	FormBot     = "bot"
)

// Device is what ParseUserAgent recovered from a User-Agent header:
// enough for someone to recognize their own login in a session list,
// and nothing more.
//
// Every field is best-effort and may be empty. A User-Agent is
// unauthenticated, client-supplied text that browsers actively lie in
// — Chrome's own string claims to be Safari, Edge's claims to be
// Chrome, and anything at all can send anything at all. Treat this as
// a recognition aid for a human reading a list, never as an identity,
// a device fingerprint, or an input to a security decision.
type Device struct {
	// Browser is a display name like "Chrome", "Safari", "Firefox",
	// "Googlebot" or "curl". Empty when nothing recognizable matched.
	Browser string
	// OS is a display name like "Windows", "macOS", "iOS", "Android",
	// "Linux" or "ChromeOS". Empty when nothing recognizable matched,
	// and always empty for bots and command-line clients — "Bingbot on
	// Windows" would read as a device claim the string cannot support.
	OS string
	// Form is one of the Form* constants above, or "" when it can't be
	// told.
	Form string
}

// IsZero reports whether nothing at all was recognized.
func (d Device) IsZero() bool { return d == Device{} }

// String renders the device as a short human-readable phrase:
// "Chrome on Windows", or just "Chrome"/"Windows" when only one half
// was recognized, or "Unknown device" when neither was. Never returns
// an empty string — a session list needs something to print in every
// row, including the row for a client that sent no User-Agent at all.
func (d Device) String() string {
	switch {
	case d.Browser != "" && d.OS != "":
		return d.Browser + " on " + d.OS
	case d.Browser != "":
		return d.Browser
	case d.OS != "":
		return d.OS
	default:
		return "Unknown device"
	}
}

// ParseUserAgent extracts a Device from a raw User-Agent header. Pure
// string matching: no network call, no external service, no lookup
// table to keep updated — an unrecognized string degrades to an empty
// Device (which still prints as "Unknown device") rather than being
// an error, because a login already happened and the UI still has a
// row to fill.
//
// The engine ships this rather than an interface with no
// implementation because parsing is something it can do from data it
// already stores. A host app that wants richer or more current parsing
// than this can run its own library over store.Session.UserAgent,
// which stays exposed verbatim for exactly that reason.
func ParseUserAgent(ua string) Device {
	lower := strings.ToLower(strings.TrimSpace(ua))
	if lower == "" {
		return Device{}
	}

	// Bots and command-line clients are matched first and exit early:
	// several of them embed a full browser string (HeadlessChrome, and
	// Bingbot's modern UA) and would otherwise be reported as the
	// browser they are imitating.
	if name, ok := match(lower, botSignatures); ok {
		return Device{Browser: name, Form: FormBot}
	}

	d := Device{}
	d.Browser, _ = match(lower, browserSignatures)
	d.OS, _ = match(lower, osSignatures)

	// The generic "…bot"/"…crawler" heuristic runs only when nothing
	// browser-shaped matched, because real device names contain "bot"
	// — Android UAs from CUBOT handsets being the reason this guard is
	// here rather than at the top with the explicit signatures.
	if d.Browser == "" && looksLikeBot(lower) {
		return Device{Browser: "Bot", Form: FormBot}
	}

	d.Form = formFactor(lower, d.OS)
	return d
}

// match returns the display name of the first signature whose needle
// appears in lower. Order within each table is significant and is the
// whole mechanism by which overlapping strings resolve correctly.
func match(lower string, table []signature) (string, bool) {
	for _, s := range table {
		if strings.Contains(lower, s.needle) {
			return s.name, true
		}
	}
	return "", false
}

type signature struct {
	needle string // already lowercase
	name   string
}

var botSignatures = []signature{
	{"googlebot", "Googlebot"},
	{"bingbot", "Bingbot"},
	{"slurp", "Yahoo! Slurp"},
	{"duckduckbot", "DuckDuckBot"},
	{"baiduspider", "Baiduspider"},
	{"yandexbot", "YandexBot"},
	{"applebot", "Applebot"},
	{"petalbot", "PetalBot"},
	{"ahrefsbot", "AhrefsBot"},
	{"semrushbot", "SemrushBot"},
	{"facebookexternalhit", "facebookexternalhit"},
	{"twitterbot", "Twitterbot"},
	{"slackbot", "Slackbot"},
	{"discordbot", "Discordbot"},
	{"telegrambot", "TelegramBot"},
	{"headlesschrome", "HeadlessChrome"},
	{"curl/", "curl"},
	{"wget/", "Wget"},
	{"httpie", "HTTPie"},
	{"postmanruntime", "Postman"},
	{"insomnia", "Insomnia"},
	{"python-requests", "python-requests"},
	{"python-urllib", "python-urllib"},
	{"go-http-client", "Go-http-client"},
	{"okhttp", "OkHttp"},
	{"axios/", "axios"},
	{"node-fetch", "node-fetch"},
	{"libwww-perl", "libwww-perl"},
	{"java/", "Java"},
}

// Chromium-based browsers all carry "chrome/", and Chrome itself
// carries "safari/", so the specific ones must be checked before the
// generic ones — Edge before Chrome, Chrome before Safari.
var browserSignatures = []signature{
	{"edg/", "Edge"},
	{"edga/", "Edge"},
	{"edgios/", "Edge"},
	{"edge/", "Edge"},
	{"opr/", "Opera"},
	{"opios/", "Opera"},
	{"opera", "Opera"},
	{"samsungbrowser/", "Samsung Internet"},
	{"yabrowser/", "Yandex Browser"},
	{"ucbrowser/", "UC Browser"},
	{"vivaldi", "Vivaldi"},
	{"brave/", "Brave"},
	{"duckduckgo/", "DuckDuckGo"},
	{"crios/", "Chrome"},
	{"chromium/", "Chromium"},
	{"chrome/", "Chrome"},
	{"fxios/", "Firefox"},
	{"firefox/", "Firefox"},
	{"seamonkey/", "SeaMonkey"},
	{"trident/", "Internet Explorer"},
	{"msie", "Internet Explorer"},
	{"safari/", "Safari"},
}

// iOS entries precede macOS because an iPhone's UA says "like Mac OS
// X"; Android precedes Linux because an Android UA says "Linux".
var osSignatures = []signature{
	{"windows phone", "Windows Phone"},
	{"windows nt", "Windows"},
	{"windows", "Windows"},
	{"android", "Android"},
	{"cros ", "ChromeOS"},
	{"iphone", "iOS"},
	{"ipad", "iOS"},
	{"ipod", "iOS"},
	{"crios/", "iOS"},
	{"fxios/", "iOS"},
	{"mac os x", "macOS"},
	{"macintosh", "macOS"},
	{"freebsd", "FreeBSD"},
	{"openbsd", "OpenBSD"},
	{"linux", "Linux"},
	{"x11", "Linux"},
}

func looksLikeBot(lower string) bool {
	for _, needle := range []string{"bot/", "bot ", "crawler", "spider", "scraper", "+http"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return strings.HasSuffix(lower, "bot")
}

func formFactor(lower, os string) string {
	switch {
	case strings.Contains(lower, "ipad"),
		strings.Contains(lower, "tablet"),
		strings.Contains(lower, "kindle"),
		strings.Contains(lower, "playbook"):
		return FormTablet
	// An Android UA without the "Mobile" token is the conventional
	// tablet marker, so this has to be decided before the mobile case
	// below rather than after it.
	case os == "Android" && !strings.Contains(lower, "mobile"):
		return FormTablet
	case strings.Contains(lower, "mobile"),
		strings.Contains(lower, "iphone"),
		strings.Contains(lower, "ipod"),
		os == "Windows Phone":
		return FormMobile
	case os == "Windows", os == "macOS", os == "Linux", os == "ChromeOS", os == "FreeBSD", os == "OpenBSD":
		return FormDesktop
	default:
		return ""
	}
}
