package afclient

// The types here mirror the ArtefactFlow API schema for creating an SBOM version.
//
// Every optional field on the request body is a pointer or an omitempty scalar so that an unset field is omitted entirely rather than sent as a zero value — the API distinguishes "not provided" from "explicitly empty", and the distinction is load-bearing for `components` in particular. Omitting it means "resolve every artefact in the SBOM to its latest stable version"; sending an empty array means something else entirely. See SBOMVersionInput.Components.

// SBOMVersionInput is the request body for POST /v1/sboms/{sbomName}/versions.
type SBOMVersionInput struct {
	Version       string `json:"version"`
	ReleaseStatus string `json:"release_status,omitempty"`

	// Components pins specific artefact versions. A nil slice is omitted from the body, which is what makes every artefact in the parent SBOM auto-resolve to its latest stable version. A partial list is a set of overrides, not a subset: the artefacts it does not mention are still included, auto-resolved. An artefact that is not already a component of the parent SBOM is rejected — this action pins versions of what the SBOM already holds, it cannot add artefacts to it.
	Components []Component `json:"components,omitempty"`

	BaseVersion      string    `json:"base_version,omitempty"`
	BOMRef           string    `json:"bom_ref,omitempty"`
	Lifecycles       []string  `json:"lifecycles,omitempty"`
	Tools            []Tool    `json:"tools,omitempty"`
	Authors          []Contact `json:"authors,omitempty"`
	Note             string    `json:"note,omitempty"`
	ComplianceStatus string    `json:"compliance_status,omitempty"`
	// HotfixFlag is a pointer so an explicit false is distinguishable from an unset field.
	HotfixFlag         *bool       `json:"hotfix_flag,omitempty"`
	DeployedEnvs       []string    `json:"deployed_envs,omitempty"`
	ExternalReferences []Reference `json:"external_references,omitempty"`
}

// Component is one artefact/version pin. ArtefactID is the artefact's 24-hex ObjectID; VersionID is a SemVer string, and leaving it empty auto-resolves that artefact just as omitting it entirely would.
type Component struct {
	ArtefactID string `json:"artefact_id"`
	VersionID  string `json:"version_id,omitempty"`
}

// Tool records what generated or validated the BOM. For this action that is the CI pipeline itself — the SBOM version body has no build or pipeline fields of its own.
type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Contact is one author of the BOM.
type Contact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// Reference is a typed link recorded against the version, such as the CI run that assembled it. With no commit or build fields on the body, this is where that provenance is carried.
type Reference struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

// ReferenceTypes are the values the API accepts for an external reference's type.
var ReferenceTypes = []string{
	"vcs", "website", "distribution", "issue-tracker", "license", "mailing-list",
	"bom", "build-system", "release-notes", "vulnerability-disclosure",
	"security-contact", "social", "chat", "support", "documentation", "other",
}

// ReferenceTypeBuildSystem is the type used for the link back to the run that assembled the version.
const ReferenceTypeBuildSystem = "build-system"

// Release statuses an SBOM version can be created with.
const (
	// ReleaseStatusDraft is the API's own default. Only one draft may exist per SBOM at a time, so a second concurrent draft create fails with 409.
	ReleaseStatusDraft = "draft"
	// ReleaseStatusReleased freezes the version immediately and bypasses the single-draft limit. It is one-way: a released version cannot be modified or reverted to draft.
	ReleaseStatusReleased = "released"
)

// ReleaseStatuses are the values the API accepts for release_status.
var ReleaseStatuses = []string{ReleaseStatusDraft, ReleaseStatusReleased}

// Lifecycles are the CycloneDX lifecycle phases the API accepts.
var Lifecycles = []string{"design", "build", "operations", "discovery", "decommission", "end-of-life"}

// ComplianceStatuses are the values the API accepts for compliance_status.
var ComplianceStatuses = []string{"compliant", "pending", "review", "non_compliant"}

// Limits the API enforces on the create body.
const (
	MaxComponents         = 1000
	MaxTools              = 20
	MaxAuthors            = 10
	MaxExternalReferences = 20
	MaxNoteLength         = 4096
)

// SBOMVersion is the created version as the API echoes it back, which is a CycloneDX document. Only the fields the action reports on are modelled; unknown fields in a response are ignored, so additions upstream do not break this.
type SBOMVersion struct {
	Version       string `json:"version"`
	BOMRef        string `json:"bom_ref"`
	ReleaseStatus string `json:"release_status"`
	// Components is the resolved set — every artefact in the SBOM with the version that was actually captured, including the ones the caller left to auto-resolve. It is the whole reason the create response is decoded at all: with auto-resolution the caller has no other way to learn what the release pinned.
	Components []ResolvedComponent `json:"components"`
}

// ResolvedComponent is one artefact and the version of it this SBOM version captured.
type ResolvedComponent struct {
	ArtefactID   string `json:"artefact_id"`
	ArtefactName string `json:"artefact_name"`
	Version      string `json:"version"`
}
