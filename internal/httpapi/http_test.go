package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Rukafuu/Mimir/internal/kernel"
)

func TestAccessFlowReturnsMinimalView(t *testing.T) {
	h := New(kernel.NewService(kernel.NewMemoryStore()))
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := request(http.MethodPost, "/v1/sources", `{"id":"mock","facts":{"work.role":"builder","private.note":"never leak"}}`); got.Code != http.StatusCreated {
		t.Fatalf("source: %d", got.Code)
	}
	if got := request(http.MethodPost, "/v1/policies", `{"id":"work","effect":"allow","scope":"work.role","purpose":"portfolio"}`); got.Code != http.StatusCreated {
		t.Fatalf("policy: %d", got.Code)
	}
	access := request(http.MethodPost, "/v1/access-requests", `{"scopes":["work.role"],"purpose":"portfolio","ttl":"1m"}`)
	if access.Code != http.StatusCreated {
		t.Fatalf("access: %d: %s", access.Code, access.Body.String())
	}
	var cap kernel.Capability
	if err := json.NewDecoder(access.Body).Decode(&cap); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/context", nil)
	r.Header.Set("Authorization", "Bearer "+cap.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("context: %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		Context map[string]any `json:"context"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Context) != 1 || response.Context["work.role"] != "builder" {
		t.Fatalf("not minimal: %#v", response.Context)
	}
}
