// Package action adapts this action to the GitHub Actions runner: it reads the action inputs from the environment, assembles the SBOM version create body, and writes the outputs in the runner's file format.
package action

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/artefactflow/publish-sbomversion-action/internal/afclient"
)

// DefaultAPIURL is the hosted ArtefactFlow API, used when neither the `api-url` input nor ARTEFACTFLOW_API_URL is set. Self-hosted operators override it; nothing else in the action assumes a particular instance.
const DefaultAPIURL = "https://api.artefactflow.app"

// IfExists selects what happens when the version already exists on the SBOM.
type IfExists string

const (
	// IfExistsFail treats an existing version as an error. This is the default: silently accepting a duplicate hides a pipeline that is releasing the same version twice.
	IfExistsFail IfExists = "fail"
	// IfExistsSkip treats an existing version as success. The create is not retried and nothing on the existing version is changed, so a re-run of the same release converges rather than failing.
	IfExistsSkip IfExists = "skip"
)

var validIfExists = map[IfExists]bool{IfExistsFail: true, IfExistsSkip: true}

// Config is the validated set of action inputs, with the SBOM version create body already assembled.
type Config struct {
	APIURL string
	// Service-account client credentials, exchanged for a short-lived token before anything else happens. They are the only way in: the action deliberately does not accept an already-minted token, so every run authenticates as a machine principal with its own scopes rather than borrowing a human's.
	ClientID     string
	ClientSecret string
	// SBOMName is how the SBOM is always addressed. Unlike an artefact, an SBOM is addressed by name in the path, so there is no resolve step.
	SBOMName string

	// Version is the create body, merged from the inputs and the workflow context.
	Version afclient.SBOMVersionInput

	IfExists IfExists
}

var (
	// objectIDRE matches a 24-hex ObjectID: the form of a service account's client id, of an artefact id in a component pin, and of an environment id.
	objectIDRE = regexp.MustCompile(`^[a-f0-9]{24}$`)
	// sbomNameRE mirrors the character set the API accepts for an SBOM name. Rejecting a bad name here means the create call is only made when it has a chance of succeeding.
	sbomNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	// semverRE is a pragmatic SemVer check, so an obviously wrong value fails before a request is made. Pre-release and build metadata are allowed.
	semverRE = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

// EnvVar returns the environment variable that backs an input: `sbom-name` is backed by ARTEFACTFLOW_SBOM_NAME. Keeping the mapping mechanical means a new input gets its variable for free.
func EnvVar(input string) string {
	return "ARTEFACTFLOW_" + strings.ToUpper(strings.ReplaceAll(input, "-", "_"))
}

// LoadConfig reads and validates the action inputs. getenv is injected so tests do not have to mutate the process environment.
//
// Each input can come from two places: the `with:` block, which the runner exposes as INPUT_<NAME> (so `sbom-name` arrives as INPUT_SBOM-NAME — the runner uppercases the name but does not touch hyphens), or an ARTEFACTFLOW_-prefixed environment variable set at workflow, job, or step level. An explicit `with:` value wins, so a single job-level `env:` block can configure every step while one step still overrides, say, the version.
//
// This is also why no input carrying a default declares one in action.yml. The runner substitutes a declared default before the action ever runs, which would make the input always non-empty and the environment fallback dead code. Those defaults are applied here instead.
//
// Validation failures are collected rather than returned one at a time, so a misconfigured workflow reports everything wrong in a single run.
func LoadConfig(getenv func(string) string) (Config, error) {
	input := func(name string) string {
		if v := strings.TrimSpace(getenv("INPUT_" + strings.ToUpper(name))); v != "" {
			return v
		}
		return strings.TrimSpace(getenv(EnvVar(name)))
	}

	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	cfg := Config{
		APIURL:       strings.TrimRight(input("api-url"), "/"),
		ClientID:     strings.ToLower(input("client-id")),
		ClientSecret: input("client-secret"),
		SBOMName:     input("sbom-name"),
	}

	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	if !strings.HasPrefix(cfg.APIURL, "http://") && !strings.HasPrefix(cfg.APIURL, "https://") {
		fail("input `api-url` must be an absolute http(s) URL, got %q", cfg.APIURL)
	}
	if err := cfg.validateCredentials(); err != nil {
		fail("%s", err)
	}
	if cfg.SBOMName == "" {
		fail("input `sbom-name` is required (or the %s environment variable)", EnvVar("sbom-name"))
	} else if err := validateSBOMName(cfg.SBOMName); err != nil {
		fail("%s", err)
	}

	// An empty `if-exists` is the unset default rather than an error.
	cfg.IfExists = IfExists(strings.ToLower(input("if-exists")))
	if cfg.IfExists == "" {
		cfg.IfExists = IfExistsFail
	}
	if !validIfExists[cfg.IfExists] {
		fail("input `if-exists` must be one of %s, got %q", strings.Join(ifExistsNames(), ", "), cfg.IfExists)
	}

	version := input("version")
	switch {
	case version == "":
		fail("input `version` is required (or the %s environment variable)", EnvVar("version"))
	case !semverRE.MatchString(version):
		fail("input `version` must be a SemVer string such as 1.2.3, got %q", version)
	}

	// The API's own default is `draft`, and an SBOM permits only one draft at a time. A pipeline that took that default would contend for that single slot with every other run, so this action defaults to `released` instead: the one-shot flow, frozen on creation, with nothing to contend over. Note that it is one-way — a released version cannot be modified or reverted to draft.
	releaseStatus := strings.ToLower(input("release-status"))
	if releaseStatus == "" {
		releaseStatus = afclient.ReleaseStatusReleased
	}
	if !slices.Contains(afclient.ReleaseStatuses, releaseStatus) {
		fail("input `release-status` must be one of %s, got %q", strings.Join(afclient.ReleaseStatuses, ", "), releaseStatus)
	}

	components, err := loadComponents(input("components"), input("components-file"))
	if err != nil {
		fail("%s", err)
	}

	baseVersion := input("base-version")
	if baseVersion != "" && !semverRE.MatchString(baseVersion) {
		fail("input `base-version` must be a SemVer string such as 1.2.3, got %q", baseVersion)
	}

	note := input("note")
	if n := utf8.RuneCountInString(note); n > afclient.MaxNoteLength {
		fail("input `note` must be at most %d characters, got %d", afclient.MaxNoteLength, n)
	}

	hotfix, err := parseBool("hotfix-flag", input("hotfix-flag"), false)
	if err != nil {
		fail("%s", err)
	}

	complianceStatus := strings.ToLower(input("compliance-status"))
	if complianceStatus != "" && !slices.Contains(afclient.ComplianceStatuses, complianceStatus) {
		fail("input `compliance-status` must be one of %s, got %q", strings.Join(afclient.ComplianceStatuses, ", "), complianceStatus)
	}

	lifecycles, err := parseLifecycles(input("lifecycles"))
	if err != nil {
		fail("input `lifecycles`: %s", err)
	}

	deployedEnvs, err := parseObjectIDs(input("deployed-envs"))
	if err != nil {
		fail("input `deployed-envs`: %s", err)
	}

	references, err := parseReferences(input("external-references"))
	if err != nil {
		fail("input `external-references`: %s", err)
	}

	cfg.Version = afclient.SBOMVersionInput{
		Version:            version,
		ReleaseStatus:      releaseStatus,
		Components:         components,
		BaseVersion:        baseVersion,
		BOMRef:             input("bom-ref"),
		Lifecycles:         lifecycles,
		Note:               note,
		ComplianceStatus:   complianceStatus,
		HotfixFlag:         &hotfix,
		DeployedEnvs:       deployedEnvs,
		ExternalReferences: withBuildReference(references, getenv),
		// TODO: `tools` and `authors` have no inputs yet. `tools` is the natural place to record the pipeline that assembled the BOM; decide on its shape before exposing it, since it is the only field that describes the assembling process itself.
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return Config{}, fmt.Errorf("invalid action inputs: %s", strings.Join(problems, "; "))
	}
	return cfg, nil
}

// validateCredentials checks that a complete pair of service-account credentials was supplied.
//
// An already-minted bearer token is deliberately not accepted. Accepting one would make it easy to hand the action a human user's token, which carries that person's full scope set, attributes releases to a person rather than a machine identity, and stops working when they leave. Requiring a service account makes least privilege the only option rather than the diligent one.
//
// No message here ever quotes the secret — errors become annotations in a public log.
func (c Config) validateCredentials() error {
	switch {
	case c.ClientID == "" && c.ClientSecret == "":
		return fmt.Errorf("service-account credentials are required: set `client-id` and `client-secret` (or the %s / %s environment variables)", EnvVar("client-id"), EnvVar("client-secret"))
	case c.ClientID == "":
		return fmt.Errorf("`client-secret` was set without `client-id`")
	case c.ClientSecret == "":
		return fmt.Errorf("`client-id` was set without `client-secret`")
	// The client id is the service account's own 24-hex id. Checking it locally catches the common mistake of pasting the account name, which the API would answer with an indistinguishable "invalid credentials".
	case !objectIDRE.MatchString(c.ClientID):
		return fmt.Errorf("input `client-id` must be the service account's 24-character hex id, got %q", c.ClientID)
	}
	return nil
}

// validateSBOMName applies the limits the API documents for an SBOM name, so an unusable value fails before a request is made. The name goes in the request path, which is the other reason to check it here.
func validateSBOMName(name string) error {
	if n := utf8.RuneCountInString(name); n < 4 || n > 128 {
		return fmt.Errorf("input `sbom-name` must be between 4 and 128 characters, got %d", n)
	}
	if !sbomNameRE.MatchString(name) {
		return fmt.Errorf("input `sbom-name` may only contain letters, digits, underscores, and hyphens, got %q", name)
	}
	return nil
}

// loadComponents reads the component pins from whichever of the two inputs was given.
//
// A nil result is meaningful and is the common case: it omits `components` from the create body entirely, which is what makes every artefact in the SBOM resolve to its latest stable version. Because of that, an input that produced no pins must never be silently treated as "no pins" — a components-file that parses to an empty list is a pipeline that generated nothing and is reported as an error rather than quietly falling back to auto-resolution.
func loadComponents(inline, path string) ([]afclient.Component, error) {
	switch {
	case inline == "" && path == "":
		return nil, nil
	case inline != "" && path != "":
		return nil, fmt.Errorf("inputs `components` and `components-file` are mutually exclusive; set one or neither")
	}

	var (
		components []afclient.Component
		err        error
	)
	if inline != "" {
		components, err = parseComponents(inline)
		if err != nil {
			return nil, fmt.Errorf("input `components`: %s", err)
		}
	} else {
		components, err = readComponentsFile(path)
		if err != nil {
			return nil, fmt.Errorf("input `components-file`: %s", err)
		}
	}

	if len(components) == 0 {
		return nil, fmt.Errorf("no component pins were read; omit the input entirely to let every artefact in the SBOM auto-resolve")
	}
	if len(components) > afclient.MaxComponents {
		return nil, fmt.Errorf("at most %d component pins are accepted, got %d", afclient.MaxComponents, len(components))
	}

	seen := make(map[string]bool, len(components))
	for _, c := range components {
		if seen[c.ArtefactID] {
			return nil, fmt.Errorf("artefact %s is pinned more than once", c.ArtefactID)
		}
		seen[c.ArtefactID] = true
	}
	return components, nil
}

// parseComponents reads the `components` input: one pin per line as `artefact-id[=version]`. A line with no version pins nothing and lets that artefact auto-resolve, which is the same outcome as leaving it out — it is accepted because a pipeline generating this list should not have to filter its own output.
func parseComponents(s string) ([]afclient.Component, error) {
	var out []afclient.Component
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		id, version, _ := strings.Cut(line, "=")
		id, version = strings.ToLower(strings.TrimSpace(id)), strings.TrimSpace(version)
		if err := validateComponent(id, version); err != nil {
			return nil, err
		}
		out = append(out, afclient.Component{ArtefactID: id, VersionID: version})
	}
	return out, nil
}

// readComponentsFile reads the same pins from a JSON file, for pipelines that generate them. See examples/components.json.
//
// Unknown fields are rejected: a file using a key this action does not read would otherwise pin nothing while looking like it pinned everything, and on a release SBOM that is a silently wrong bill of materials rather than a formatting mistake.
func readComponentsFile(path string) ([]afclient.Component, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()

	var file struct {
		Components []afclient.Component `json:"components"`
	}
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, c := range file.Components {
		if err := validateComponent(strings.ToLower(c.ArtefactID), c.VersionID); err != nil {
			return nil, fmt.Errorf("%s: %s", path, err)
		}
	}
	return file.Components, nil
}

func validateComponent(artefactID, version string) error {
	if !objectIDRE.MatchString(artefactID) {
		return fmt.Errorf("artefact id must be 24 hex characters, got %q", artefactID)
	}
	if version != "" && !semverRE.MatchString(version) {
		return fmt.Errorf("version pinned for artefact %s must be a SemVer string such as 1.2.3, got %q", artefactID, version)
	}
	return nil
}

// parseLifecycles reads the `lifecycles` input, accepting either one value per line or a comma-separated list.
func parseLifecycles(s string) ([]string, error) {
	var out []string
	for _, v := range splitList(s) {
		v = strings.ToLower(v)
		if !slices.Contains(afclient.Lifecycles, v) {
			return nil, fmt.Errorf("unknown lifecycle %q; use one of %s", v, strings.Join(afclient.Lifecycles, ", "))
		}
		out = append(out, v)
	}
	return out, nil
}

// parseObjectIDs reads a list of 24-hex ids, one per line or comma-separated.
func parseObjectIDs(s string) ([]string, error) {
	var out []string
	for _, v := range splitList(s) {
		v = strings.ToLower(v)
		if !objectIDRE.MatchString(v) {
			return nil, fmt.Errorf("each id must be 24 hex characters, got %q", v)
		}
		out = append(out, v)
	}
	return out, nil
}

// splitList splits an input on newlines and commas, dropping empty entries. Accepting both keeps a short list writable inline while a generated one stays readable a line at a time.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' }) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// withBuildReference appends a link back to the workflow run that assembled the SBOM version. The create body carries no commit, build, or pipeline fields of its own, so this reference is the only provenance the version records — which makes it worth adding by default rather than on request.
//
// It is skipped outside a workflow run, where the pieces are not available, and skipped when the caller supplied a build-system reference of their own — a version carrying two contradictory answers to "which build made this?" is worse than one that trusts what the workflow said.
func withBuildReference(refs []afclient.Reference, getenv func(string) string) []afclient.Reference {
	for _, r := range refs {
		if r.Type == afclient.ReferenceTypeBuildSystem {
			return refs
		}
	}
	server := firstNonEmpty(getenv("GITHUB_SERVER_URL"), "https://github.com")
	repo, runID := getenv("GITHUB_REPOSITORY"), getenv("GITHUB_RUN_ID")
	if repo == "" || runID == "" {
		return refs
	}
	return append(refs, afclient.Reference{
		Type:    afclient.ReferenceTypeBuildSystem,
		URL:     fmt.Sprintf("%s/%s/actions/runs/%s", server, repo, runID),
		Comment: "GitHub Actions workflow run",
	})
}

// parseReferences reads the `external-references` input: one reference per line as `<type> <url> [comment]`. Neither a type nor a URL can contain a space, so splitting on whitespace and treating everything after the second field as the comment reads naturally and leaves the comment free to be a sentence.
func parseReferences(s string) ([]afclient.Reference, error) {
	var out []afclient.Reference
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("each line must be `type url [comment]`, got %q", line)
		}
		refType, refURL := strings.ToLower(fields[0]), fields[1]
		if !slices.Contains(afclient.ReferenceTypes, refType) {
			return nil, fmt.Errorf("unknown type %q; use one of %s", fields[0], strings.Join(afclient.ReferenceTypes, ", "))
		}
		if !hasURIScheme(refURL) {
			return nil, fmt.Errorf("reference %q must have an absolute URL, got %q", refType, refURL)
		}
		comment := strings.Join(fields[2:], " ")
		if n := utf8.RuneCountInString(comment); n > 500 {
			return nil, fmt.Errorf("comment for %q must be at most 500 characters, got %d", refType, n)
		}
		out = append(out, afclient.Reference{Type: refType, URL: refURL, Comment: comment})
	}
	if len(out) > afclient.MaxExternalReferences {
		return nil, fmt.Errorf("at most %d external references are accepted, got %d", afclient.MaxExternalReferences, len(out))
	}
	return out, nil
}

// hasURIScheme reports whether a value looks like an absolute URI. The API accepts more than http(s) here — a `mailto:` support contact, for instance — so the check is for a scheme rather than for a protocol.
func hasURIScheme(s string) bool {
	scheme, rest, ok := strings.Cut(s, ":")
	return ok && scheme != "" && rest != "" && !strings.ContainsAny(scheme, " /?#")
}

// parseBool reads a boolean input, returning def when it is unset. Anything that is not a recognised boolean is an error rather than a silent false — a typo in `hotfix-flag: ture` must not quietly record the wrong thing.
func parseBool(name, value string, def bool) (bool, error) {
	switch strings.ToLower(value) {
	case "":
		return def, nil
	case "true", "yes", "1":
		return true, nil
	case "false", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("input `%s` must be true or false, got %q", name, value)
	}
}

// ifExistsNames lists the accepted values in a stable order, for error messages.
func ifExistsNames() []string {
	names := make([]string, 0, len(validIfExists))
	for v := range validIfExists {
		names = append(names, string(v))
	}
	sort.Strings(names)
	return names
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
