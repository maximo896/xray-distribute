package trafficdb

import (
	"path/filepath"
	"strconv"
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
