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
	Capability string `json:"capability"`
	Purpose    string `json:"purpose"`
	TTL        string `json:"ttl"`
}

type Capability struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	Scopes    []string  `json:"scopes"`
	Purpose   string    `json:"purpose"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CapabilityStatus string

const (
	CapabilityDraft      CapabilityStatus = "draft"
	CapabilityActive     CapabilityStatus = "active"
	CapabilityDeprecated CapabilityStatus = "deprecated"
	CapabilityRevoked    CapabilityStatus = "revoked"
)

// CapabilityDefinition is an immutable authorization contract once active.
// Agents may create drafts, but only an administrator can change lifecycle state.
type CapabilityDefinition struct {
	Name           string           `json:"name"`
	Version        int              `json:"version"`
	Scopes         []string         `json:"scopes"`
	Purposes       []string         `json:"purposes"`
	MaxTTL         string           `json:"max_ttl"`
	Access         string           `json:"access"`
	Classification string           `json:"classification"`
	Status         CapabilityStatus `json:"status"`
	CreatedBy      string           `json:"created_by"`
}

type AuditEvent struct {
	At         time.Time `json:"at"`
	Action     string    `json:"action"`
	TokenID    string    `json:"token_id,omitempty"`
	Capability string    `json:"capability,omitempty"`
	Version    int       `json:"version,omitempty"`
	Scopes     []string  `json:"scopes,omitempty"`
	Purpose    string    `json:"purpose,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	Outcome    string    `json:"outcome"`
}

type Store interface {
	AddSource(Source) error
	Sources() []Source
	AddPolicy(Policy) error
	Policies() []Policy
	AddCapabilityDefinition(CapabilityDefinition) error
	CapabilityDefinition(name string, version int) (CapabilityDefinition, bool)
	CapabilityDefinitions() []CapabilityDefinition
	SetCapabilityStatus(name string, version int, status CapabilityStatus) error
	PutCapability(Capability)
	Capability(string) (Capability, bool)
	AddAudit(AuditEvent)
	Audits() []AuditEvent
}
