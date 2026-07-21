package afclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// conflictServer answers every create with the given 409 envelope, after failing the first `transient` attempts with a 503.
func conflictServer(t *testing.T, code, message string, transient int32) *httptest.Server {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) <= transient {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":"GEN00503","message":"unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprintf(w, `{"code":%q,"message":%q,"log_id":"0198c1f0-0000-7000-8000-000000000000"}`, code, message)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func createAgainst(t *testing.T, srv *httptest.Server) error {
	t.Helper()
	c, err := New(srv.URL, "token", WithRetry(3, time.Millisecond, time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.CreateSBOMVersion(context.Background(), "acme-platform", SBOMVersionInput{Version: "1.0.0", ReleaseStatus: "released"})
	return err
}

// Every 409 a create can answer with is told apart by its code, never by its wording. The blocked release is the case that matters: it used to be read as "version exists", which `if-exists: skip` then turned into a passing step.
func TestCreateConflictsAreClassifiedByCode(t *testing.T) {
	cases := []struct {
		name, code, message string
		want                error
	}{
		{"version exists", codeVersionExists, "version 1.0.0 already exists for this SBOM", ErrVersionExists},
		{"draft exists", codeDraftExists, "a draft version already exists: 0.9.0", ErrDraftExists},
		{"release blocked", codeReleaseBlocked, "release blocked: the SBOM version violates one or more blocking policies", ErrReleaseBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := createAgainst(t, conflictServer(t, tc.code, tc.message, 0))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A conflict the action does not know is reported with the API's wording, and is none of the known kinds, so `if-exists: skip` cannot tolerate it.
func TestUnknownConflictIsNotReportedAsAnExistingVersion(t *testing.T) {
	err := createAgainst(t, conflictServer(t, "SBOM09999", "something else entirely already exists", 0))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, known := range []error{ErrVersionExists, ErrDraftExists, ErrReleaseBlocked, ErrCreatedByOwnRetry} {
		if errors.Is(err, known) {
			t.Fatalf("err = %v, must not be %v", err, known)
		}
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != "SBOM09999" {
		t.Fatalf("err = %v, want the API's StatusError carried through", err)
	}
}

// After a transient failure, an "already exists" conflict is the earlier attempt landing. A blocked release created nothing on any attempt, so it stays a failure.
func TestConflictAfterRetry(t *testing.T) {
	if err := createAgainst(t, conflictServer(t, codeVersionExists, "version 1.0.0 already exists for this SBOM", 1)); !CreatedByOwnRetry(err) {
		t.Fatalf("version exists after a retry: err = %v, want ErrCreatedByOwnRetry", err)
	}
	err := createAgainst(t, conflictServer(t, codeReleaseBlocked, "release blocked", 1))
	if CreatedByOwnRetry(err) || !errors.Is(err, ErrReleaseBlocked) {
		t.Fatalf("release blocked after a retry: err = %v, want ErrReleaseBlocked", err)
	}
}
