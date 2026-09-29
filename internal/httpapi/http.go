package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Rukafuu/Mimir/internal/kernel"
)

func New(service *kernel.Service, adminToken string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/sources", func(w http.ResponseWriter, r *http.Request) {
		var source kernel.Source
		if err := decode(r, &source); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err := service.RegisterSource(source); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		respond(w, http.StatusCreated, source)
	})
	mux.HandleFunc("POST /v1/policies", func(w http.ResponseWriter, r *http.Request) {
		var policy kernel.Policy
		if err := decode(r, &policy); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err := service.AddPolicy(policy); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		respond(w, http.StatusCreated, policy)
	})
	mux.HandleFunc("POST /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		var definition kernel.CapabilityDefinition
		if err := decode(r, &definition); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		created, err := service.CreateCapability(definition)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		respond(w, http.StatusCreated, created)
	})
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, map[string]any{"capabilities": service.CapabilityDefinitions()})
	})
	lifecycle := func(status kernel.CapabilityStatus) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if adminToken == "" || r.Header.Get("X-Mimir-Admin-Token") != adminToken {
				fail(w, http.StatusUnauthorized, errors.New("administrator token is required"))
				return
			}
			var approval struct {
				Actor string `json:"actor"`
			}
			if err := decode(r, &approval); err != nil {
				fail(w, http.StatusBadRequest, err)
				return
			}
			var version int
			if _, err := fmt.Sscan(r.PathValue("version"), &version); err != nil {
				fail(w, http.StatusBadRequest, errors.New("invalid capability version"))
				return
			}
			if err := service.SetCapabilityStatus(r.PathValue("name"), version, status, approval.Actor); err != nil {
				fail(w, http.StatusConflict, err)
				return
			}
			respond(w, http.StatusOK, map[string]string{"status": string(status)})
		}
	}
	mux.HandleFunc("POST /v1/capabilities/{name}/versions/{version}/activate", lifecycle(kernel.CapabilityActive))
	mux.HandleFunc("POST /v1/capabilities/{name}/versions/{version}/deprecate", lifecycle(kernel.CapabilityDeprecated))
	mux.HandleFunc("POST /v1/capabilities/{name}/versions/{version}/revoke", lifecycle(kernel.CapabilityRevoked))
	mux.HandleFunc("POST /v1/access-requests", func(w http.ResponseWriter, r *http.Request) {
		var req kernel.AccessRequest
		if err := decode(r, &req); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		cap, err := service.RequestAccess(req)
		if err != nil {
			fail(w, http.StatusForbidden, err)
			return
		}
		respond(w, http.StatusCreated, cap)
	})
	mux.HandleFunc("GET /v1/context", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			fail(w, http.StatusUnauthorized, errors.New("bearer capability is required"))
			return
		}
		view, err := service.View(token)
		if err != nil {
			fail(w, http.StatusUnauthorized, err)
			return
		}
		respond(w, http.StatusOK, map[string]any{"context": view})
	})
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, map[string]any{"events": service.Audit()})
	})
	return mux
}
func decode(r *http.Request, target any) error {
	defer r.Body.Close()
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("content-type must be application/json")
	}
	return json.NewDecoder(r.Body).Decode(target)
}
func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func fail(w http.ResponseWriter, status int, err error) {
	respond(w, status, map[string]string{"error": err.Error()})
}
