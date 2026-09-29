package kernel

import (
	"errors"
	"sync"
)

type MemoryStore struct {
	mu           sync.RWMutex
	sources      map[string]Source
	policies     []Policy
	definitions  map[string]map[int]CapabilityDefinition
	capabilities map[string]Capability
	audits       []AuditEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sources: map[string]Source{}, definitions: map[string]map[int]CapabilityDefinition{}, capabilities: map[string]Capability{}}
}
func (m *MemoryStore) AddSource(s Source) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == "" {
		return errors.New("source id is required")
	}
	m.sources[s.ID] = s
	return nil
}
func (m *MemoryStore) Sources() []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Source, 0, len(m.sources))
	for _, s := range m.sources {
		out = append(out, s)
	}
	return out
}
func (m *MemoryStore) AddPolicy(p Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.ID == "" || (p.Effect != "allow" && p.Effect != "deny") || p.Scope == "" || p.Purpose == "" {
		return errors.New("policy needs id, allow/deny effect, scope and purpose")
	}
	m.policies = append(m.policies, p)
	return nil
}
func (m *MemoryStore) Policies() []Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Policy(nil), m.policies...)
}
func (m *MemoryStore) AddCapabilityDefinition(d CapabilityDefinition) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.definitions[d.Name] == nil {
		m.definitions[d.Name] = map[int]CapabilityDefinition{}
	}
	if _, exists := m.definitions[d.Name][d.Version]; exists {
		return errors.New("capability version already exists")
	}
	m.definitions[d.Name][d.Version] = d
	return nil
}
func (m *MemoryStore) CapabilityDefinition(name string, version int) (CapabilityDefinition, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.definitions[name][version]
	return d, ok
}
func (m *MemoryStore) CapabilityDefinitions() []CapabilityDefinition {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []CapabilityDefinition{}
	for _, versions := range m.definitions {
		for _, d := range versions {
			out = append(out, d)
		}
	}
	return out
}
func (m *MemoryStore) SetCapabilityStatus(name string, version int, status CapabilityStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	versions := m.definitions[name]
	d, ok := versions[version]
	if !ok {
		return errors.New("capability version not found")
	}
	d.Status = status
	versions[version] = d
	return nil
}
func (m *MemoryStore) PutCapability(c Capability) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.capabilities[c.Token] = c
}
func (m *MemoryStore) Capability(t string) (Capability, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.capabilities[t]
	return c, ok
}
func (m *MemoryStore) AddAudit(e AuditEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audits = append(m.audits, e)
}
func (m *MemoryStore) Audits() []AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]AuditEvent(nil), m.audits...)
}
