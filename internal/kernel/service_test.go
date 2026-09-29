package kernel

import (
	"testing"
	"time"
)

func TestCapabilityReturnsOnlyAllowedSemanticView(t *testing.T) {
	s := NewService(NewMemoryStore())
	if err := s.RegisterSource(Source{ID: "mock-profile", Facts: map[string]any{"employment.current": "Context Kernel", "finances.balance": 100}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPolicy(Policy{ID: "employment", Effect: "allow", Scope: "employment.current", Purpose: "salary_negotiation"}); err != nil {
		t.Fatal(err)
	}
	cap, err := s.RequestAccess(AccessRequest{Scopes: []string{"employment.current"}, Purpose: "salary_negotiation", TTL: "1m"})
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.View(cap.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(view) != 1 || view["employment.current"] != "Context Kernel" {
		t.Fatalf("unexpected minimal view: %#v", view)
	}
}
func TestDenyOverridesAllow(t *testing.T) {
	s := NewService(NewMemoryStore())
	_ = s.AddPolicy(Policy{ID: "allow", Effect: "allow", Scope: "work.*", Purpose: "*"})
	_ = s.AddPolicy(Policy{ID: "deny", Effect: "deny", Scope: "work.*", Purpose: "export"})
	if _, err := s.RequestAccess(AccessRequest{Scopes: []string{"work.*"}, Purpose: "export", TTL: "1m"}); err == nil {
		t.Fatal("expected deny")
	}
}
func TestExpiredCapabilityCannotRead(t *testing.T) {
	s := NewService(NewMemoryStore())
	cap := Capability{Token: "expired", Scopes: []string{"work"}, ExpiresAt: time.Now().UTC().Add(-time.Second)}
	s.store.PutCapability(cap)
	if _, err := s.View(cap.Token); err == nil {
		t.Fatal("expected expired capability to fail")
	}
}
