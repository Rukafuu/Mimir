package kernel

import (
	"testing"
	"time"
)

func TestCapabilityReturnsOnlyAllowedSemanticView(t *testing.T) {
	s := NewService(NewMemoryStore())
	if err := s.RegisterSource(Source{ID: "mock-profile", Facts: map[string]any{"employment.current": "Mímir", "finances.balance": 100}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPolicy(Policy{ID: "employment", Effect: "allow", Scope: "employment.current", Purpose: "salary_negotiation"}); err != nil {
		t.Fatal(err)
	}
	draft, err := s.CreateCapability(CapabilityDefinition{Name: "employment.read_current", Scopes: []string{"employment.current"}, Purposes: []string{"salary_negotiation"}, MaxTTL: "5m", Access: "read_only", Classification: "sensitive", CreatedBy: "agent_context"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCapabilityStatus(draft.Name, draft.Version, CapabilityActive, "amari"); err != nil {
		t.Fatal(err)
	}
	cap, err := s.RequestAccess(AccessRequest{Capability: draft.Name, Purpose: "salary_negotiation", TTL: "1m"})
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.View(cap.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(view) != 1 || view["employment.current"] != "Mímir" {
		t.Fatalf("unexpected minimal view: %#v", view)
	}
}
func TestDenyOverridesAllow(t *testing.T) {
	s := NewService(NewMemoryStore())
	_ = s.AddPolicy(Policy{ID: "allow", Effect: "allow", Scope: "work.summary", Purpose: "export"})
	_ = s.AddPolicy(Policy{ID: "deny", Effect: "deny", Scope: "work.summary", Purpose: "export"})
	draft, _ := s.CreateCapability(CapabilityDefinition{Name: "work.read_summary", Scopes: []string{"work.summary"}, Purposes: []string{"export"}, MaxTTL: "5m", Access: "read_only", Classification: "internal", CreatedBy: "agent_context"})
	_ = s.SetCapabilityStatus(draft.Name, draft.Version, CapabilityActive, "amari")
	if _, err := s.RequestAccess(AccessRequest{Capability: draft.Name, Purpose: "export", TTL: "1m"}); err == nil {
		t.Fatal("expected deny")
	}
}

func TestAgentDraftCannotIssueUntilApproved(t *testing.T) {
	s := NewService(NewMemoryStore())
	draft, err := s.CreateCapability(CapabilityDefinition{Name: "calendar.read_availability", Scopes: []string{"calendar.availability"}, Purposes: []string{"meeting_scheduling"}, MaxTTL: "15m", Access: "read_only", Classification: "sensitive", CreatedBy: "agent_context"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestAccess(AccessRequest{Capability: draft.Name, Purpose: "meeting_scheduling", TTL: "1m"}); err == nil {
		t.Fatal("draft capability must not issue tokens")
	}
	if err := s.SetCapabilityStatus(draft.Name, draft.Version, CapabilityActive, "agent_context"); err == nil {
		t.Fatal("creator cannot approve its own draft")
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
