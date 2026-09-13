package security

import "testing"

// Real strings, not invented ones: the whole risk in this parser is
// that browsers deliberately impersonate each other inside the header
// (Chrome claims Safari, Edge claims Chrome, an iPhone claims Mac OS
// X), so a table of authentic UAs is the only thing that proves the
// signature ordering resolves them the right way round.
func TestParseUserAgent(t *testing.T) {
	cases := []struct {
		name    string
		ua      string
		browser string
		os      string
		form    string
		label   string
	}{
		{
			name:    "chrome on windows",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			browser: "Chrome", os: "Windows", form: FormDesktop, label: "Chrome on Windows",
		},
		{
			// Carries "Chrome/" AND "Safari/" — both must lose to Edg/.
			name:    "edge on windows is not chrome",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
			browser: "Edge", os: "Windows", form: FormDesktop, label: "Edge on Windows",
		},
		{
			name:    "opera on windows is not chrome",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0",
			browser: "Opera", os: "Windows", form: FormDesktop, label: "Opera on Windows",
		},
		{
			name:    "safari on macos",
			ua:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
			browser: "Safari", os: "macOS", form: FormDesktop, label: "Safari on macOS",
		},
		{
			name:    "chrome on macos is not safari",
			ua:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			browser: "Chrome", os: "macOS", form: FormDesktop, label: "Chrome on macOS",
		},
		{
			// "like Mac OS X" is in the string — iOS has to win anyway.
			name:    "safari on iphone is ios not macos",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
			browser: "Safari", os: "iOS", form: FormMobile, label: "Safari on iOS",
		},
		{
			name:    "chrome on iphone",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.111 Mobile/15E148 Safari/604.1",
			browser: "Chrome", os: "iOS", form: FormMobile, label: "Chrome on iOS",
		},
		{
			name:    "ipad is a tablet",
			ua:      "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
			browser: "Safari", os: "iOS", form: FormTablet, label: "Safari on iOS",
		},
		{
			// Android's own UA says "Linux" — Android has to win.
			name:    "chrome on android phone is not linux",
			ua:      "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
			browser: "Chrome", os: "Android", form: FormMobile, label: "Chrome on Android",
		},
		{
			// Same string minus the "Mobile" token: that absence is the
			// only thing marking an Android tablet.
			name:    "android without the mobile token is a tablet",
			ua:      "Mozilla/5.0 (Linux; Android 13; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			browser: "Chrome", os: "Android", form: FormTablet, label: "Chrome on Android",
		},
		{
			name:    "samsung internet on android is not chrome",
			ua:      "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
			browser: "Samsung Internet", os: "Android", form: FormMobile, label: "Samsung Internet on Android",
		},
		{
			name:    "firefox on linux",
			ua:      "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
			browser: "Firefox", os: "Linux", form: FormDesktop, label: "Firefox on Linux",
		},
		{
			// Also X11, also Chrome — ChromeOS must beat the Linux entry.
			name:    "chromeos is not linux",
			ua:      "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			browser: "Chrome", os: "ChromeOS", form: FormDesktop, label: "Chrome on ChromeOS",
		},
		{
			name:    "internet explorer 11 advertises neither msie nor a browser name",
			ua:      "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
			browser: "Internet Explorer", os: "Windows", form: FormDesktop, label: "Internet Explorer on Windows",
		},
		{
			// An in-app webview: no browser token at all, but the OS is
			// still recoverable and still worth showing.
			name:    "ios webview degrades to the os alone",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
			browser: "", os: "iOS", form: FormMobile, label: "iOS",
		},
		{
			name:    "curl reports no os",
			ua:      "curl/8.6.0",
			browser: "curl", os: "", form: FormBot, label: "curl",
		},
		{
			name:    "go http client",
			ua:      "Go-http-client/2.0",
			browser: "Go-http-client", os: "", form: FormBot, label: "Go-http-client",
		},
		{
			name:    "googlebot",
			ua:      "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			browser: "Googlebot", os: "", form: FormBot, label: "Googlebot",
		},
		{
			// Headless Chrome embeds a complete Chrome UA; the explicit
			// signature has to be checked before the browser table.
			name:    "headless chrome is a bot",
			ua:      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36",
			browser: "HeadlessChrome", os: "", form: FormBot, label: "HeadlessChrome",
		},
		{
			name:    "an unrecognized crawler still reads as a bot",
			ua:      "SomeRandomCrawler/1.0 (+http://example.com/about)",
			browser: "Bot", os: "", form: FormBot, label: "Bot",
		},
		{
			// The reason the generic bot heuristic runs last: CUBOT is a
			// real handset brand, and this is a person's phone.
			name:    "a cubot handset is a phone not a bot",
			ua:      "Mozilla/5.0 (Linux; Android 11; CUBOT NOTE 20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.74 Mobile Safari/537.36",
			browser: "Chrome", os: "Android", form: FormMobile, label: "Chrome on Android",
		},
		{
			name:    "no user agent at all",
			ua:      "",
			browser: "", os: "", form: "", label: "Unknown device",
		},
		{
			name:    "unparseable junk",
			ua:      "??? ???",
			browser: "", os: "", form: "", label: "Unknown device",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUserAgent(tc.ua)
			if got.Browser != tc.browser {
				t.Errorf("Browser: got %q, want %q", got.Browser, tc.browser)
			}
			if got.OS != tc.os {
				t.Errorf("OS: got %q, want %q", got.OS, tc.os)
			}
			if got.Form != tc.form {
				t.Errorf("Form: got %q, want %q", got.Form, tc.form)
			}
			if got.String() != tc.label {
				t.Errorf("String(): got %q, want %q", got.String(), tc.label)
			}
		})
	}
}

// Nothing guarantees a client sends the canonical casing, and every
// signature in the tables is lowercase.
func TestParseUserAgent_IsCaseInsensitive(t *testing.T) {
	got := ParseUserAgent("MOZILLA/5.0 (WINDOWS NT 10.0; WIN64; X64) APPLEWEBKIT/537.36 (KHTML, LIKE GECKO) CHROME/124.0.0.0 SAFARI/537.36")
	if got.Browser != "Chrome" || got.OS != "Windows" {
		t.Errorf("expected Chrome on Windows regardless of casing, got %+v", got)
	}
}

// A session list has a row to fill for every session, including one
// created by a client that sent nothing.
func TestDevice_StringIsNeverEmpty(t *testing.T) {
	if (Device{}).String() != "Unknown device" {
		t.Errorf("expected a printable fallback, got %q", (Device{}).String())
	}
	if !(Device{}).IsZero() {
		t.Error("expected the zero Device to report IsZero")
	}
	if ParseUserAgent("curl/8.6.0").IsZero() {
		t.Error("expected a recognized client not to report IsZero")
	}
}
