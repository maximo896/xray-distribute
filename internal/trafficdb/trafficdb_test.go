package trafficdb

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xray-distribute/internal/model"
)

func TestRecordOOBPrefersExactHTTPInteractionPath(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	firstRaw := `<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "http://abc123.oast.fun/i/first/">]><a>&content;</a>`
	firstID, err := db.RecordXRayRequest("POST", "http://target.local/xxe", map[string][]string{"Content-Type": {"application/xml"}}, []byte(firstRaw), 0, "")
	if err != nil {
		t.Fatal(err)
	}

	secondRaw := `<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "http://abc123.oast.fun/i/second/">]><a>&content;</a>`
	if _, err := db.RecordXRayRequest("POST", "http://target.local/xxe", map[string][]string{"Content-Type": {"application/xml"}}, []byte(secondRaw), 0, ""); err != nil {
		t.Fatal(err)
	}

	match, err := db.RecordOOB(model.OOBInteraction{
		Protocol:      "http",
		FullID:        "abc123",
		RawRequest:    "GET /i/first/ HTTP/1.1\r\nHost: abc123.oast.fun\r\n\r\n",
		RawResponse:   "HTTP/1.1 200 OK\r\n\r\n",
		RemoteAddress: "127.0.0.1",
		Timestamp:     time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if match == nil {
		t.Fatal("expected OOB interaction to match a recorded request")
	}
	if match.ID != firstID {
		t.Fatalf("expected exact path to match request %d, got %d", firstID, match.ID)
	}
}

func TestRecordOOBDoesNotMatchCommonShortSubdomainLabels(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.RecordXRayRequest("CONNECT", "www.google.com:443", map[string][]string{"User-Agent": {"Go-http-client/1.1"}}, nil, 0, ""); err != nil {
		t.Fatal(err)
	}

	for _, interaction := range []model.OOBInteraction{
		{
			Protocol:      "dns",
			FullID:        "WWw.ukuKk.Uk.",
			RawRequest:    ";; QUESTION SECTION:\n;WWw.ukuKk.Uk.\tIN\tAAAA\n",
			RemoteAddress: "172.253.4.21",
			Timestamp:     time.Now(),
		},
		{
			Protocol:      "https",
			FullID:        "www.ukukk.uk",
			RawRequest:    "GET /favicon.ico HTTP/2.0\r\nHost: www.ukukk.uk\r\n\r\n",
			RemoteAddress: "45.142.154.61",
			Timestamp:     time.Now(),
		},
	} {
		match, err := db.RecordOOB(interaction)
		if err != nil {
			t.Fatal(err)
		}
		if match != nil {
			t.Fatalf("expected %s to be ignored, matched %s %s", interaction.FullID, match.Method, match.URL)
		}
	}
}

func TestCandidateIDsOnlyIncludesLikelyCorrelationPrefix(t *testing.T) {
	cases := map[string][]string{
		"www.ukukk.uk":            {"www.ukukk.uk"},
		"ns1.ukukk.uk.":           {"ns1.ukukk.uk"},
		"abc12345.ukukk.uk":       {"abc12345.ukukk.uk", "abc12345"},
		"abc123.oast.fun":         {"abc123.oast.fun"},
		"a-b-c-d-1.example.test":  {"a-b-c-d-1.example.test", "a-b-c-d-1"},
		"bad_label!.example.test": {"bad_label!.example.test"},
	}
	for input, want := range cases {
		got := candidateIDs(input)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("candidateIDs(%q) = %#v, want %#v", input, got, want)
		}
	}
}

func TestConcurrentRecordXRayRequestsDoesNotBusy(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const workers = 64
	const perWorker = 50

	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_, err := db.RecordXRayRequest(
					"GET",
					"http://target.local/path",
					map[string][]string{"X-Worker": {strconv.Itoa(worker)}},
					[]byte("body"),
					200,
					"ok",
				)
				if err != nil {
					errs <- err
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent insert failed: %v", err)
	}
}

func TestRawMirrorIncludesRequestHost(t *testing.T) {
	raw := rawMirror(&model.MirrorRequest{
		Method:  "GET",
		URL:     "https://10.0.0.1/path",
		Host:    "app.example.com",
		Headers: map[string][]string{"User-Agent": {"test"}},
	})

	if !strings.Contains(raw, "\r\nHost: app.example.com\r\n") {
		t.Fatalf("expected raw mirror request to include Host header, got:\n%s", raw)
	}
}

func TestRawMirrorDoesNotDuplicateLegacyHostHeader(t *testing.T) {
	raw := rawMirror(&model.MirrorRequest{
		Method: "GET",
		URL:    "https://10.0.0.1/path",
		Host:   "app.example.com",
		Headers: map[string][]string{
			"host": {"legacy.example.com"},
		},
	})

	if strings.Count(strings.ToLower(raw), "\r\nhost:") != 1 {
		t.Fatalf("expected one Host header, got:\n%s", raw)
	}
	if !strings.Contains(raw, "\r\nhost: legacy.example.com\r\n") {
		t.Fatalf("expected legacy Host header to be preserved, got:\n%s", raw)
	}
}
