package kernel

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sort"
	"time"
)

type Service struct{ store Store }

func NewService(store Store) *Service                 { return &Service{store: store} }
func (s *Service) RegisterSource(source Source) error { return s.store.AddSource(source) }
func (s *Service) AddPolicy(policy Policy) error      { return s.store.AddPolicy(policy) }
func (s *Service) Audit() []AuditEvent                { return s.store.Audits() }

func (s *Service) RequestAccess(req AccessRequest) (Capability, error) {
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 || ttl > 24*time.Hour {
		return Capability{}, errors.New("ttl must be a positive duration no longer than 24h")
	}
	if req.Purpose == "" || len(req.Scopes) == 0 {
		return Capability{}, errors.New("purpose and at least one scope are required")
	}
	for _, scope := range req.Scopes {
		if !s.allowed(scope, req.Purpose) {
			s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "access.request", Scopes: req.Scopes, Purpose: req.Purpose, Outcome: "denied"})
			return Capability{}, errors.New("policy denied requested scope: " + scope)
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return Capability{}, err
	}
	cap := Capability{Token: base64.RawURLEncoding.EncodeToString(buf), Scopes: append([]string(nil), req.Scopes...), Purpose: req.Purpose, ExpiresAt: time.Now().UTC().Add(ttl)}
	s.store.PutCapability(cap)
	s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "access.request", TokenID: cap.Token[:8], Scopes: cap.Scopes, Purpose: cap.Purpose, Outcome: "granted"})
	return cap, nil
}

func (s *Service) View(token string) (map[string]any, error) {
	cap, ok := s.store.Capability(token)
	if !ok || time.Now().UTC().After(cap.ExpiresAt) {
		s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "context.read", Outcome: "denied"})
		return nil, errors.New("invalid or expired capability")
	}
	allowed := map[string]bool{}
	for _, scope := range cap.Scopes {
		allowed[scope] = true
	}
	view := map[string]any{}
	for _, source := range s.store.Sources() {
		for scope, fact := range source.Facts {
			if allowed[scope] {
				view[scope] = fact
			}
		}
	}
	keys := make([]string, 0, len(view))
	for k := range view {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "context.read", TokenID: cap.Token[:8], Scopes: keys, Purpose: cap.Purpose, Outcome: "granted"})
	return view, nil
}

// Deny wins. Requests need an explicit matching allow policy.
func (s *Service) allowed(scope, purpose string) bool {
	allowed := false
	for _, p := range s.store.Policies() {
		if matches(p.Scope, scope) && matches(p.Purpose, purpose) {
			if p.Effect == "deny" {
				return false
			}
			allowed = true
		}
	}
	return allowed
}
func matches(pattern, value string) bool { return pattern == "*" || pattern == value }
