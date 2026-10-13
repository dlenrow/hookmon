package suppress

import "testing"

func TestAddGetSnapshot(t *testing.T) {
	Add("test_b", "r1")
	Add("test_a", "r2")
	Add("test_a", "r1")
	Add("test_a", "r1")

	if got := Get("test_a", "r1"); got != 2 {
		t.Errorf("Get(test_a, r1) = %d, want 2", got)
	}
	if got := Get("test_a", "missing"); got != 0 {
		t.Errorf("Get(test_a, missing) = %d, want 0", got)
	}

	var mine []Count
	for _, c := range Snapshot() {
		if c.Sensor == "test_a" || c.Sensor == "test_b" {
			mine = append(mine, c)
		}
	}
	want := []Count{{"test_a", "r1", 2}, {"test_a", "r2", 1}, {"test_b", "r1", 1}}
	if len(mine) != len(want) {
		t.Fatalf("Snapshot = %v, want %v", mine, want)
	}
	for i := range want {
		if mine[i] != want[i] {
			t.Errorf("Snapshot[%d] = %v, want %v", i, mine[i], want[i])
		}
	}
}
