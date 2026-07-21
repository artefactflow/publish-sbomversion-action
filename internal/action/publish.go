package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/artefactflow/publish-sbomversion-action/internal/afclient"
)

// API is the slice of the ArtefactFlow client this action drives, named as an interface so the sequencing below can be exercised without a server.
type API interface {
	CreateSBOMVersion(ctx context.Context, sbomName string, in afclient.SBOMVersionInput) (*afclient.SBOMVersion, string, error)
}

// Result is what the run produced, and what becomes the action's outputs.
type Result struct {
	SBOMName      string
	Version       string
	VersionURL    string
	ReleaseStatus string
	// Created is false when the version already existed and `if-exists` was `skip`.
	Created bool
	// Components is the resolved component set the API reported: every artefact in the SBOM with the version this release captured, including the ones that auto-resolved. Nil means the API did not report one, which is reported as unknown rather than as an empty set: a workflow reading an empty list would conclude the release captured nothing.
	Components []afclient.ResolvedComponent
}

// Publish creates the SBOM version.
//
// The interesting behaviour is all in how a conflict is handled. A 409 means one of three things with different remedies (the version already exists, the SBOM already holds its one permitted draft, or a blocking policy refused the release), so they are reported separately. `if-exists: skip` tolerates only the first: in the other two the version this run was asked to create does not exist, and a re-run must not quietly accept that.
//
// log receives the progress lines that go to the step log; a failed run returns both the partial result and the error.
func Publish(ctx context.Context, cfg Config, api API, log io.Writer) (Result, error) {
	res := Result{
		SBOMName:      cfg.SBOMName,
		Version:       cfg.Version.Version,
		ReleaseStatus: cfg.Version.ReleaseStatus,
	}

	created, location, err := api.CreateSBOMVersion(ctx, cfg.SBOMName, cfg.Version)
	switch {
	case err == nil, afclient.CreatedByOwnRetry(err):
		res.Created = true
		res.VersionURL = location
		if created.Version != "" {
			res.Version = created.Version
		}
		if created.ReleaseStatus != "" {
			res.ReleaseStatus = created.ReleaseStatus
		}
		res.Components = created.Components
		fmt.Fprintf(log, "Created %s version %s of SBOM %s with %s\n", res.ReleaseStatus, res.Version, res.SBOMName, describeComponents(res.Components))
		if afclient.CreatedByOwnRetry(err) {
			// Worth saying out loud: the create was retried and the version was already there when the retry arrived. Treating it as this run's own work is the right call, but someone reading a log after an incident should not have to infer that.
			fmt.Fprintf(log, "::warning::The create was retried after a transient failure and the version already existed on the retry. It has been treated as created by this run, which is the likeliest explanation: a version published earlier would have conflicted on the first attempt. Check the version if you need certainty.\n")
		}

	case errors.Is(err, afclient.ErrVersionExists) && cfg.IfExists == IfExistsSkip:
		fmt.Fprintf(log, "Version %s of SBOM %s already exists; continuing because `if-exists` is `skip`. Nothing on the existing version was changed, and its component set is not reported, because this run did not resolve one.\n", res.Version, res.SBOMName)

	case errors.Is(err, afclient.ErrVersionExists):
		// The version is there, so its URL is still worth reporting: it is where someone will go to see what is already recorded.
		res.VersionURL = versionURL(cfg.APIURL, res.SBOMName, res.Version, "")
		return res, fmt.Errorf("version %s of SBOM %s already exists. Pick another version, or set `if-exists: skip` to treat this as success on a re-run: %w", res.Version, res.SBOMName, err)

	case errors.Is(err, afclient.ErrDraftExists):
		// A different conflict with a different remedy, which is why it is never covered by `if-exists: skip`. The requested version was not created, so treating this as success would report a release that does not exist.
		return res, fmt.Errorf("SBOM %s already has an outstanding draft version, and only one draft may exist at a time, so version %s was not created. Release or delete that draft, or set `release-status: released` so this step does not need the draft slot at all: %w", res.SBOMName, res.Version, err)

	case errors.Is(err, afclient.ErrReleaseBlocked):
		// Never covered by `if-exists: skip`: nothing was created, so a passing step would report a release the policies refused.
		return res, fmt.Errorf("version %s of SBOM %s was not created: creating it as released ran the SBOM's policies, and at least one blocking policy failed. Fix what the policy reports, or have an exception approved, then run this step again. Creating it as a draft stores the version and its policy evaluation without releasing it: %w", res.Version, res.SBOMName, err)

	default:
		return res, err
	}

	res.VersionURL = versionURL(cfg.APIURL, res.SBOMName, res.Version, res.VersionURL)
	return res, nil
}

// versionURL settles on the URL to report for a version. The API's Location header wins when it gave one, resolved against the base URL if it was relative; otherwise the URL is derived, because a workflow reading the output should never get an empty string back for a version that demonstrably exists.
func versionURL(apiURL, sbomName, version, location string) string {
	switch {
	case location == "":
		return fmt.Sprintf("%s/v1/sboms/%s/versions/%s", apiURL, sbomName, version)
	case strings.HasPrefix(location, "http://"), strings.HasPrefix(location, "https://"):
		return location
	default:
		return apiURL + "/" + strings.TrimPrefix(location, "/")
	}
}

// describeComponents renders the resolved component count for the step log. A nil set is reported as unknown rather than as zero: the API not telling us what it captured is a different thing from it capturing nothing.
func describeComponents(components []afclient.ResolvedComponent) string {
	if components == nil {
		return "an unreported component set"
	}
	return fmt.Sprintf("%d resolved component(s)", len(components))
}
