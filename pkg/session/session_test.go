package session

import (
	"sync"
	"testing"
)

func TestRegistryCreateAndResume(t *testing.T) {
	r := NewRegistry()
	s := r.Create("deadbeef", nil)
	if s.ID == "" || s.ResumeToken == "" {
		t.Fatal("create did not assign id/token")
	}

	// Wrong token must not resume.
	if _, ok := r.Resume(s.ID, "wrong", nil); ok {
		t.Error("resume succeeded with wrong token")
	}
	// Correct token resumes.
	if got, ok := r.Resume(s.ID, s.ResumeToken, nil); !ok || got.ID != s.ID {
		t.Error("resume failed with correct token")
	}

	r.Remove(s.ID)
	if _, ok := r.Get(s.ID); ok {
		t.Error("session still present after remove")
	}
}

func TestIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
}

func TestNextConnIDIsRaceFree(t *testing.T) {
	s := newSession("k")
	const goroutines, perG = 50, 200
	var wg sync.WaitGroup
	results := make(chan uint64, goroutines*perG)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				results <- s.NextConnID()
			}
		}()
	}
	wg.Wait()
	close(results)
	seen := map[uint64]bool{}
	for id := range results {
		if seen[id] {
			t.Fatalf("duplicate conn id %d", id)
		}
		seen[id] = true
	}
	if len(seen) != goroutines*perG {
		t.Fatalf("expected %d unique ids, got %d", goroutines*perG, len(seen))
	}
}
