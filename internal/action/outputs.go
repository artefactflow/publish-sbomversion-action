package action

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Output is one action output. A slice keeps the write order stable, which makes the step log and the tests readable.
type Output struct {
	Name  string
	Value string
}

// Outputs maps a run's result to the full set of action outputs.
func Outputs(res Result) []Output {
	return []Output{
		{"version", res.Version},
		{"version-url", res.VersionURL},
		{"sbom-name", res.SBOMName},
		{"release-status", res.ReleaseStatus},
		{"created", strconv.FormatBool(res.Created)},
		{"components", encodeComponents(res)},
	}
}

// encodeComponents renders the resolved component set as compact JSON, which is what a later step can feed to jq.
//
// An unreported set becomes an empty string rather than `[]`. With auto-resolution a workflow cannot know what the release captured except from this output, and `[]` is a claim — that the release pinned nothing — where an empty value is an admission that this run does not know.
func encodeComponents(res Result) string {
	if res.Components == nil {
		return ""
	}
	encoded, err := json.Marshal(res.Components)
	if err != nil {
		return ""
	}
	return string(encoded)
}

// WriteOutputs renders outputs in the runner's $GITHUB_OUTPUT file format.
//
// Every value here is single-line by construction — a SemVer string, a URL, a boolean, compact JSON — so the plain `name=value` form is used, and a value that is not single-line is rejected rather than written, because a newline in that file is how an untrusted value would forge additional outputs.
func WriteOutputs(w io.Writer, outputs []Output) error {
	var b strings.Builder
	for _, o := range outputs {
		if strings.ContainsAny(o.Value, "\r\n") {
			return fmt.Errorf("refusing to write output %q: the API returned a value containing a line break", o.Name)
		}
		fmt.Fprintf(&b, "%s=%s\n", o.Name, o.Value)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write outputs: %w", err)
	}
	return nil
}
