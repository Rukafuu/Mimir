package kernel

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Service struct{ store Store }

func NewService(store Store) *Service                 { return &Service{store: store} }
func (s *Service) RegisterSource(source Source) error { return s.store.AddSource(source) }
func (s *Service) AddPolicy(policy Policy) error      { return s.store.AddPolicy(policy) }
func (s *Service) Audit() []AuditEvent                { return s.store.Audits() }
func (s *Service) CapabilityDefinitions() []CapabilityDefinition {
	return s.store.CapabilityDefinitions()
}

var capabilityNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:_[a-z0-9]+)*)+$`)
var snakeCasePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)

// CreateCapability always creates a draft. Callers cannot self-activate a contract.
func (s *Service) CreateCapability(d CapabilityDefinition) (CapabilityDefinition, error) {
	if !capabilityNamePattern.MatchString(d.Name) || !strings.Contains(d.Name, ".read_") {
		return CapabilityDefinition{}, errors.New("capability name must be namespaced snake_case and end with a read_ action")
	}
	if d.Version != 0 && d.Version != 1 {
		return CapabilityDefinition{}, errors.New("new capability version must be 1")
	}
	if d.Access != "read_only" {
		return CapabilityDefinition{}, errors.New("CCP/0.1 capabilities must be read_only")
	}
	if d.Classification != "public" && d.Classification != "internal" && d.Classification != "sensitive" && d.Classification != "restricted" {
		return CapabilityDefinition{}, errors.New("invalid classification")
	}
	if d.CreatedBy == "" || len(d.Scopes) == 0 || len(d.Purposes) == 0 {
		return CapabilityDefinition{}, errors.New("created_by, scopes and purposes are required")
	}
	if _, err := time.ParseDuration(d.MaxTTL); err != nil {
		return CapabilityDefinition{}, errors.New("max_ttl must be a duration")
	}
	maxTTL, _ := time.ParseDuration(d.MaxTTL)
	if maxTTL <= 0 || maxTTL > 24*time.Hour {
		return CapabilityDefinition{}, errors.New("max_ttl must be positive and no longer than 24h")
	}
	for _, scope := range d.Scopes {
		if scope == "*" || !capabilityNamePattern.MatchString(scope) {
			return CapabilityDefinition{}, errors.New("scopes must be exact namespaced snake_case values")
		}
	}
	for _, purpose := range d.Purposes {
		if !snakeCasePattern.MatchString(purpose) {
			return CapabilityDefinition{}, errors.New("purposes must be snake_case")
		}
	}
	d.Version = 1
	d.Status = CapabilityDraft
	if err := s.store.AddCapabilityDefinition(d); err != nil {
		return CapabilityDefinition{}, err
	}
	s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "capability.create", Capability: d.Name, Version: d.Version, Actor: d.CreatedBy, Outcome: "draft"})
	return d, nil
}

func (s *Service) SetCapabilityStatus(name string, version int, status CapabilityStatus, actor string) error {
	d, ok := s.store.CapabilityDefinition(name, version)
	if !ok {
		return errors.New("capability version not found")
	}
	if actor == "" || actor == d.CreatedBy {
		return errors.New("administrator approval must be a distinct named actor")
	}
	if status == CapabilityActive && d.Status != CapabilityDraft {
		return errors.New("only draft capabilities can be activated")
	}
	if status == CapabilityDeprecated && d.Status != CapabilityActive {
		return errors.New("only active capabilities can be deprecated")
	}
	if status == CapabilityRevoked && d.Status != CapabilityActive && d.Status != CapabilityDeprecated {
		return errors.New("only active or deprecated capabilities can be revoked")
	}
	if err := s.store.SetCapabilityStatus(name, version, status); err != nil {
		return err
	}
	s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "capability." + string(status), Capability: name, Version: version, Actor: actor, Outcome: string(status)})
	return nil
}

func (s *Service) RequestAccess(req AccessRequest) (Capability, error) {
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 || ttl > 24*time.Hour {
		return Capability{}, errors.New("ttl must be a positive duration no longer than 24h")
	}
	if req.Purpose == "" || req.Capability == "" {
		return Capability{}, errors.New("capability and purpose are required")
	}
	d, ok := s.latestActiveCapability(req.Capability)
	if !ok {
		s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "access.request", Capability: req.Capability, Purpose: req.Purpose, Outcome: "denied"})
		return Capability{}, errors.New("capability is not active")
	}
	if !contains(d.Purposes, req.Purpose) {
		s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "access.request", Capability: d.Name, Version: d.Version, Purpose: req.Purpose, Outcome: "denied"})
		return Capability{}, errors.New("purpose is not allowed by capability")
	}
	maxTTL, _ := time.ParseDuration(d.MaxTTL)
	if ttl > maxTTL {
		return Capability{}, errors.New("ttl exceeds capability maximum")
	}
	for _, scope := range d.Scopes {
		if !s.allowed(scope, req.Purpose) {
			s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "access.request", Capability: d.Name, Version: d.Version, Scopes: d.Scopes, Purpose: req.Purpose, Outcome: "denied"})
			return Capability{}, errors.New("policy denied capability scope: " + scope)
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return Capability{}, err
	}
	cap := Capability{Token: base64.RawURLEncoding.EncodeToString(buf), Name: d.Name, Version: d.Version, Scopes: append([]string(nil), d.Scopes...), Purpose: req.Purpose, ExpiresAt: time.Now().UTC().Add(ttl)}
	s.store.PutCapability(cap)
	s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "access.request", TokenID: cap.Token[:8], Capability: cap.Name, Version: cap.Version, Scopes: cap.Scopes, Purpose: cap.Purpose, Outcome: "granted"})
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
	s.store.AddAudit(AuditEvent{At: time.Now().UTC(), Action: "context.read", TokenID: cap.Token[:8], Capability: cap.Name, Version: cap.Version, Scopes: keys, Purpose: cap.Purpose, Outcome: "granted"})
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
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func (s *Service) latestActiveCapability(name string) (CapabilityDefinition, bool) {
	var latest CapabilityDefinition
	for _, d := range s.store.CapabilityDefinitions() {
		if d.Name == name && d.Status == CapabilityActive && d.Version > latest.Version {
			latest = d
		}
	}
	return latest, latest.Version != 0
}
