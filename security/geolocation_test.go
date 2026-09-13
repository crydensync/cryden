package security

import "testing"

// Location.String() is the whole contract between the engine and a
// host-supplied geolocator: whatever fields the host fills in are what
// gets printed, in that order, with nothing invented and nothing
// dropped. Granularity is therefore the host's choice, which is why
// there is no case here for "abbreviate the region" or "hide the
// country" — the engine does neither.
func TestLocation_String(t *testing.T) {
	cases := []struct {
		name string
		loc  Location
		want string
	}{
		{"city region country", Location{City: "San Francisco", Region: "CA", Country: "US"}, "San Francisco, CA, US"},
		{"city and region only", Location{City: "San Francisco", Region: "CA"}, "San Francisco, CA"},
		{"city and country only", Location{City: "Berlin", Country: "DE"}, "Berlin, DE"},
		{"country alone is still worth printing", Location{Country: "DE"}, "DE"},
		{"region alone", Location{Region: "Bavaria"}, "Bavaria"},
		{"nothing known", Location{}, ""},
		{"whitespace-only fields are not fields", Location{City: "  ", Country: "US"}, "US"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.loc.String(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLocation_IsZero(t *testing.T) {
	if !(Location{}).IsZero() {
		t.Error("the zero Location must report IsZero")
	}
	// A geolocator that returns padding rather than nothing is still
	// returning nothing, and a label must not gain a trailing dash for
	// it.
	if !(Location{City: " ", Region: "\t"}).IsZero() {
		t.Error("whitespace-only fields must count as unknown")
	}
	if (Location{Country: "US"}).IsZero() {
		t.Error("a known country is not a zero Location")
	}
}
