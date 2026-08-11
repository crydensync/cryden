package security

import "testing"

func TestUUIDv7Generator_ProducesUniqueIDs(t *testing.T) {
	g := NewUUIDv7Generator()
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := g.New()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate ID generated: %s", id)
		}
		seen[id] = true
	}
}

func TestUUIDv7Generator_IDsAreRoughlySortable(t *testing.T) {
	// UUIDv7 embeds a timestamp prefix, so IDs generated in sequence
	// should sort lexicographically in the order they were created —
	// the property that motivated choosing it over UUIDv4.
	g := NewUUIDv7Generator()
	first, _ := g.New()
	second, _ := g.New()
	if first >= second {
		t.Errorf("expected sequential UUIDv7s to sort in creation order, got %s then %s", first, second)
	}
}
