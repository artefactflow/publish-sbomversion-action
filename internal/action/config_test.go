package action

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/artefactflow/publish-sbomversion-action/internal/afclient"
)

const (
	testClientID   = "0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0"
	testArtefactID = "0198e2c3-9a21-7b8e-90f5-6c1d4e2a8301"
	testEnvID      = "0198e2c3-9a21-7b8e-90f5-6c1d4e2a83e1"
)

// Ids that are not the API's UUID form and that lowercasing cannot repair: a legacy hex id from before UUIDs and an unhyphenated UUID.
var rejectedIDs = map[string]string{
	"legacy hex id":     "507f191e810c19729de860ed",
	"unhyphenated UUID": "0198e2c39a217b8e90f56c1d4e2a83b0",
}

// validEnv is the minimum a workflow must supply. Tests copy it and change the one thing under test.
func validEnv() map[string]string {
	return map[string]string{
		"INPUT_CLIENT-ID":     testClientID,
		"INPUT_CLIENT-SECRET": "afsa_pretend-this-is-a-real-secret",
		"INPUT_SBOM-NAME":     "acme-platform",
		"INPUT_VERSION":       "2.0.0",
	}
}

func load(vars map[string]string) (Config, error) {
	return LoadConfig(func(k string) string { return vars[k] })
}

func TestValidResourceIDsAreAccepted(t *testing.T) {
	vars := validEnv()
	vars["INPUT_COMPONENTS"] = testArtefactID + "=1.4.2"
	vars["INPUT_DEPLOYED-ENVS"] = testEnvID
	cfg, err := load(vars)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ClientID != testClientID {
		t.Errorf("client-id = %q, want %q", cfg.ClientID, testClientID)
	}
	if want := []afclient.Component{{ArtefactID: testArtefactID, VersionID: "1.4.2"}}; !reflect.DeepEqual(cfg.Version.Components, want) {
		t.Errorf("components = %+v, want %+v", cfg.Version.Components, want)
	}
	if want := []string{testEnvID}; !reflect.DeepEqual(cfg.Version.DeployedEnvs, want) {
		t.Errorf("deployed-envs = %v, want %v", cfg.Version.DeployedEnvs, want)
	}
}

func TestClientIDMustBeAUUID(t *testing.T) {
	cases := map[string]string{"name": "ci-publisher"}
	for name, id := range rejectedIDs {
		cases[name] = id
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			vars := validEnv()
			vars["INPUT_CLIENT-ID"] = id
			_, err := load(vars)
			if err == nil || !strings.Contains(err.Error(), "must be the service account's id, a UUID") {
				t.Fatalf("client-id %q: err = %v, want it rejected as not a UUID", id, err)
			}
		})
	}
}

func TestComponentArtefactIDMustBeAUUID(t *testing.T) {
	for name, id := range rejectedIDs {
		t.Run("inline "+name, func(t *testing.T) {
			vars := validEnv()
			vars["INPUT_COMPONENTS"] = id + "=1.4.2"
			_, err := load(vars)
			if err == nil || !strings.Contains(err.Error(), "artefact id must be a UUID") {
				t.Fatalf("component %q: err = %v, want it rejected as not a UUID", id, err)
			}
		})
		t.Run("file "+name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "components.json")
			body := `{"components":[{"artefact_id":"` + id + `","version_id":"1.4.2"}]}`
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			vars := validEnv()
			vars["INPUT_COMPONENTS-FILE"] = path
			_, err := load(vars)
			if err == nil || !strings.Contains(err.Error(), "artefact id must be a UUID") {
				t.Fatalf("component file with %q: err = %v, want it rejected as not a UUID", id, err)
			}
		})
	}
}

func TestDeployedEnvsMustBeUUIDs(t *testing.T) {
	for name, id := range rejectedIDs {
		t.Run(name, func(t *testing.T) {
			vars := validEnv()
			vars["INPUT_DEPLOYED-ENVS"] = testEnvID + "," + id
			_, err := load(vars)
			if err == nil || !strings.Contains(err.Error(), "input `deployed-envs`: each id must be a UUID") {
				t.Fatalf("deployed-envs %q: err = %v, want it rejected as not a UUID", id, err)
			}
		})
	}
}

// An uppercase UUID is accepted and lowercased, so what is checked is also what is sent: the API takes only the lowercase spelling.
func TestUppercaseResourceIDsAreLowercased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "components.json")
	body := `{"components":[{"artefact_id":"` + strings.ToUpper(testArtefactID) + `","version_id":"1.4.2"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []afclient.Component{{ArtefactID: testArtefactID, VersionID: "1.4.2"}}

	for name, set := range map[string]func(map[string]string){
		"inline components": func(v map[string]string) { v["INPUT_COMPONENTS"] = strings.ToUpper(testArtefactID) + "=1.4.2" },
		"components file":   func(v map[string]string) { v["INPUT_COMPONENTS-FILE"] = path },
	} {
		t.Run(name, func(t *testing.T) {
			vars := validEnv()
			vars["INPUT_CLIENT-ID"] = strings.ToUpper(testClientID)
			vars["INPUT_DEPLOYED-ENVS"] = strings.ToUpper(testEnvID)
			set(vars)
			cfg, err := load(vars)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.ClientID != testClientID {
				t.Errorf("client-id = %q, want %q", cfg.ClientID, testClientID)
			}
			if !reflect.DeepEqual(cfg.Version.Components, want) {
				t.Errorf("components = %+v, want %+v", cfg.Version.Components, want)
			}
			if w := []string{testEnvID}; !reflect.DeepEqual(cfg.Version.DeployedEnvs, w) {
				t.Errorf("deployed-envs = %v, want %v", cfg.Version.DeployedEnvs, w)
			}
		})
	}
}

// The examples in the repository are what users copy, so they must pass the action's own validation.
func TestExampleComponentsFileIsValid(t *testing.T) {
	vars := validEnv()
	vars["INPUT_COMPONENTS-FILE"] = filepath.Join("..", "..", "examples", "components.json")
	if _, err := load(vars); err != nil {
		t.Fatalf("examples/components.json: %v", err)
	}
}
