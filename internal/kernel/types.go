package kernel

import "time"

type Source struct {
	ID    string         `json:"id"`
	Facts map[string]any `json:"facts"` // mock connector payload; keys are semantic scopes
}

type Policy struct {
	ID      string `json:"id"`
	Effect  string `json:"effect"`  // allow or deny
	Scope   string `json:"scope"`   // exact scope or *
	Purpose string `json:"purpose"` // exact purpose or *
}

type AccessRequest struct {
	Scopes  []string `json:"scopes"`
	Purpose string   `json:"purpose"`
	TTL     string   `json:"ttl"`
}

type Capability struct {
	Token     string    `json:"token"`
	Scopes    []string  `json:"scopes"`
	Purpose   string    `json:"purpose"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AuditEvent struct {
	At      time.Time `json:"at"`
	Action  string    `json:"action"`
	TokenID string    `json:"token_id,omitempty"`
	Scopes  []string  `json:"scopes,omitempty"`
	Purpose string    `json:"purpose,omitempty"`
	Outcome string    `json:"outcome"`
}

type Store interface {
	AddSource(Source) error
	Sources() []Source
	AddPolicy(Policy) error
	Policies() []Policy
	PutCapability(Capability)
	Capability(string) (Capability, bool)
	AddAudit(AuditEvent)
	Audits() []AuditEvent
}
