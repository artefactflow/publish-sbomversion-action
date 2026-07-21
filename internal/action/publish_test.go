package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/artefactflow/publish-sbomversion-action/internal/afclient"
)

type failingAPI struct{ err error }

func (f failingAPI) CreateSBOMVersion(context.Context, string, afclient.SBOMVersionInput) (*afclient.SBOMVersion, string, error) {
	return nil, "", f.err
}

func publishWith(err error, ifExists IfExists) (Result, error) {
	cfg := Config{
		APIURL:   "https://api.example.test",
		SBOMName: "acme-platform",
		Version:  afclient.SBOMVersionInput{Version: "1.0.0", ReleaseStatus: "released"},
		IfExists: ifExists,
	}
	return Publish(context.Background(), cfg, failingAPI{err: err}, io.Discard)
}

// `if-exists: skip` tolerates a version that already exists and nothing else. A blocked release and an outstanding draft both mean the requested version does not exist, so the step must fail.
func TestSkipToleratesOnlyAnExistingVersion(t *testing.T) {
	res, err := publishWith(fmt.Errorf("%w: conflict", afclient.ErrVersionExists), IfExistsSkip)
	if err != nil || res.Created {
		t.Fatalf("existing version under skip: created=%v err=%v, want a tolerated skip", res.Created, err)
	}
	for _, kind := range []error{afclient.ErrReleaseBlocked, afclient.ErrDraftExists} {
		if _, err := publishWith(fmt.Errorf("%w: conflict", kind), IfExistsSkip); !errors.Is(err, kind) {
			t.Fatalf("%v under skip: err = %v, want the step to fail with it", kind, err)
		}
	}
}
