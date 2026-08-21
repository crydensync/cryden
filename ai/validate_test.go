package ai

import "testing"

func TestEntityColumnsMatchesAllowedFields(t *testing.T) {
	// EntityColumns and AllowedFields must describe exactly the same
	// set of fields per entity. If they ever drift apart, either a
	// field becomes selectable without being allowlisted, or an
	// allowlisted field silently stops being returned — both are
	// bugs worth catching immediately, not at query time.
	for entity, fields := range AllowedFields {
		cols, ok := EntityColumns[entity]
		if !ok {
			t.Errorf("entity %q has AllowedFields but no EntityColumns", entity)
			continue
		}
		colSet := map[string]bool{}
		for _, c := range cols {
			colSet[c] = true
		}
		if len(colSet) != len(cols) {
			t.Errorf("entity %q has duplicate columns in EntityColumns: %v", entity, cols)
		}
		for f := range fields {
			if !colSet[f] {
				t.Errorf("entity %q: field %q is in AllowedFields but missing from EntityColumns", entity, f)
			}
		}
		for c := range colSet {
			if !fields[c] {
				t.Errorf("entity %q: column %q is in EntityColumns but missing from AllowedFields", entity, c)
			}
		}
	}
	for entity := range EntityColumns {
		if _, ok := AllowedFields[entity]; !ok {
			t.Errorf("entity %q has EntityColumns but no AllowedFields", entity)
		}
	}
}
