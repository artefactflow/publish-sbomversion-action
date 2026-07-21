package afclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrVersionExists reports that the SBOM already has a version with that value. It is separated from other failures because it is the one error a pipeline may legitimately want to treat as success — a re-run of the same release should not have to fail.
var ErrVersionExists = errors.New("version already exists")

// ErrDraftExists reports the other thing a 409 can mean: the SBOM already holds its one permitted draft, so no second draft can be created. The remedy is different from ErrVersionExists — release or delete the outstanding draft, or create as `released` and skip the draft slot altogether — which is exactly why the two are distinguished rather than reported as one generic conflict.
var ErrDraftExists = errors.New("the SBOM already has an outstanding draft version")

// ErrCreatedByOwnRetry is returned alongside a usable SBOMVersion when the create reported a conflict only after an earlier attempt had failed transiently. It is not a failure: the version exists because this call put it there. It is a distinct value rather than a plain nil so the caller can say so in the log — the alternative reading, that the version pre-dated this run, cannot be ruled out from the outside.
var ErrCreatedByOwnRetry = errors.New("the version was created by an earlier attempt of this same request, whose response was lost")

// CreatedByOwnRetry reports whether err is the not-really-an-error above.
func CreatedByOwnRetry(err error) bool { return errors.Is(err, ErrCreatedByOwnRetry) }

// CreateSBOMVersion creates a version of the named SBOM and returns it along with the value of the Location header, which points at the new version's URL.
//
// The SBOM is addressed by its name, not by an id — unlike an artefact, which is addressed by its 24-hex ObjectID. There is no resolve step.
//
// A 409 is classified into ErrVersionExists or ErrDraftExists so the caller can say which one it was, unless it arrived on a retry — in which case it is this call's own earlier attempt landing. See ErrCreatedByOwnRetry.
func (c *Client) CreateSBOMVersion(ctx context.Context, sbomName string, in SBOMVersionInput) (*SBOMVersion, string, error) {
	path := "/v1/sboms/" + url.PathEscape(sbomName) + "/versions"
	res, err := c.sendJSON(ctx, http.MethodPost, path, in, http.StatusCreated, http.StatusOK)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusConflict {
			if se.AfterRetry {
				// The first attempt failed transiently, and the version now exists. Overwhelmingly the likeliest explanation is that the first attempt's write did land and only its response was lost — a genuine duplicate would have been rejected on the first attempt, before any retry. Reporting failure here would fail a pipeline that published correctly.
				return &SBOMVersion{Version: in.Version, ReleaseStatus: in.ReleaseStatus}, "", ErrCreatedByOwnRetry
			}
			return nil, "", fmt.Errorf("%w: %w", classifyConflict(se), se)
		}
		return nil, "", fmt.Errorf("create version %s of SBOM %s: %w", in.Version, sbomName, err)
	}

	var v SBOMVersion
	// A create that stores correctly but answers with a shape we do not recognise is still a successful create; the Location header and the requested version string carry enough for the action to report the essentials, so a decode failure is not fatal here. The resolved component list is the one output that would be lost, which the caller reports as unknown rather than as empty.
	_ = json.Unmarshal(res.body, &v)
	if v.Version == "" {
		v.Version = in.Version
	}
	return &v, res.header.Get("Location"), nil
}

// classifyConflict decides which of the two meanings a 409 carried. The API's error code is authoritative when it names one; the message is the fallback, because reporting the wrong remedy is worse than reporting a slightly hedged one — so an unrecognisable conflict is reported as a duplicate version, which is by far the commoner cause and the one whose remedy (pick another version) is harmless to suggest wrongly.
func classifyConflict(se *StatusError) error {
	haystack := strings.ToLower(se.Code + " " + se.Message)
	if strings.Contains(haystack, "draft") {
		return ErrDraftExists
	}
	return ErrVersionExists
}
