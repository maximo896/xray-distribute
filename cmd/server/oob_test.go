package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xray-distribute/internal/api"
	"github.com/xray-distribute/internal/model"
	"github.com/xray-distribute/internal/store"
)

func TestMatchedOOBInteractionIsVisibleThroughVulnsAPI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.New(t.TempDir(), logger)
	defer st.TrafficDB().Close()

	fullID := "i-smoke1234-abcd.session123456789.ukukk.uk"
	targetURL := "https://target.example/vuln?next=https://" + fullID + "/cb"
	_, err := st.TrafficDB().RecordXRayRequest("GET", targetURL, map[string][]string{
		"User-Agent": {"xray-smoke"},
	}, nil, 200, "ok")
	if err != nil {
		t.Fatalf("record xray request: %v", err)
	}

	interaction := model.OOBInteraction{
		Protocol:      "dns",
		FullID:        fullID + ".",
		RawRequest:    ";; QUESTION SECTION:\n;" + fullID + ". IN A",
		RawResponse:   ";; ANSWER SECTION:\n" + fullID + ". 60 IN A 127.0.0.1",
		RemoteAddress: "127.0.0.1",
		Timestamp:     time.Now(),
	}

	match, err := st.RecordOOBInteraction(interaction)
	if err != nil {
		t.Fatalf("record oob interaction: %v", err)
	}
	if match == nil {
		t.Fatal("expected OOB interaction to match recorded xray request")
	}

	vuln := buildOOBVulnerability(interaction, match)
	if vuln == nil {
		t.Fatal("expected OOB vulnerability")
	}
	st.AddVuln(vuln)

	apiServer := api.New(st, nil, nil, nil, nil, nil, "smoke-token", logger)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulns?token=smoke-token&page=1&page_size=20", nil)
	rec := httptest.NewRecorder()
	apiServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "OOB interaction received (dns)") {
		t.Fatalf("API response did not include OOB vulnerability: %s", rec.Body.String())
	}

	var response model.APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	payload, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected response data: %#v", response.Data)
	}
	if total, ok := payload["total"].(float64); !ok || total != 1 {
		t.Fatalf("expected total=1, got %#v", payload["total"])
	}
}

func TestUnmatchedOOBInteractionIsVisibleThroughVulnsAPI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.New(t.TempDir(), logger)
	defer st.TrafficDB().Close()

	interaction := model.OOBInteraction{
		Protocol:      "dns",
		FullID:        "unmatched123456.ukukk.uk.",
		RawRequest:    ";; QUESTION SECTION:\n;unmatched123456.ukukk.uk. IN A",
		RawResponse:   ";; ANSWER SECTION:\nunmatched123456.ukukk.uk. 60 IN A 127.0.0.1",
		RemoteAddress: "127.0.0.1",
		Timestamp:     time.Now(),
	}

	match, err := st.RecordOOBInteraction(interaction)
	if err != nil {
		t.Fatalf("record oob interaction: %v", err)
	}
	if match != nil {
		t.Fatalf("expected no matching request, got %#v", match)
	}

	vuln := buildOOBVulnerability(interaction, match)
	if vuln == nil {
		t.Fatal("expected unmatched OOB vulnerability")
	}
	if vuln.URL != interaction.FullID {
		t.Fatalf("expected unmatched OOB URL to be full id, got %q", vuln.URL)
	}
	st.AddVuln(vuln)

	apiServer := api.New(st, nil, nil, nil, nil, nil, "smoke-token", logger)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulns?token=smoke-token&page=1&page_size=20", nil)
	rec := httptest.NewRecorder()
	apiServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unmatched123456.ukukk.uk") {
		t.Fatalf("API response did not include unmatched OOB vulnerability: %s", rec.Body.String())
	}
}
