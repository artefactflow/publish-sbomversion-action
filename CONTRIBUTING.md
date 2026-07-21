# Contributing

Thanks for taking the time. Bug reports, documentation fixes, and pull requests are all welcome.

## Getting started

The action is a small Go program shipped as a container action. You need Go (the version in [go.mod](go.mod)) and, to build the image, Docker.

```sh
go build ./...
go test ./...
```

## Running it locally

The binary reads the same environment the runner gives it, so you can exercise it without a workflow. With `GITHUB_OUTPUT` unset it prints the outputs to stdout instead of writing them to a file. The `ARTEFACTFLOW_` variables are the convenient way in. Unlike the `INPUT_` ones they contain no hyphens, so a shell accepts them as an assignment prefix:

```sh
ARTEFACTFLOW_API_URL=https://api.artefactflow.app \
ARTEFACTFLOW_CLIENT_ID=... \
ARTEFACTFLOW_CLIENT_SECRET=... \
ARTEFACTFLOW_SBOM_NAME=acme-platform \
ARTEFACTFLOW_VERSION=2.0.0 \
go run ./cmd/publish-sbomversion
```

Set `ARTEFACTFLOW_API_URL` deliberately. Left unset it defaults to the hosted API, and this action writes. Running it by accident against production creates a real SBOM version, and a released one cannot be reverted.

To exercise the `with:` path instead, set the `INPUT_` variables the runner would set. Those do contain hyphens, so they have to go through `env`:

```sh
env 'INPUT_SBOM-NAME=acme-platform' 'INPUT_VERSION=2.0.0' 'INPUT_CLIENT-ID=...' 'INPUT_CLIENT-SECRET=...' go run ./cmd/publish-sbomversion
```

Against the stub, with no ArtefactFlow instance and no credentials at all. [`testdata/stub-api.py`](testdata/stub-api.py) implements the two endpoints the action calls, and it is the same stub CI uses:

```sh
python3 testdata/stub-api.py 8099 &
until curl -sf -o /dev/null -X POST -H 'Content-Type: application/json' \
  -d '{"client_id":"0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0","client_secret":"afsa_stub-client-secret"}' \
  http://localhost:8099/v1/auth/token; do sleep 0.2; done

ARTEFACTFLOW_API_URL=http://localhost:8099 \
ARTEFACTFLOW_CLIENT_ID=0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0 \
ARTEFACTFLOW_CLIENT_SECRET=afsa_stub-client-secret \
ARTEFACTFLOW_SBOM_NAME=acme-platform \
ARTEFACTFLOW_VERSION=2.0.0 \
go run ./cmd/publish-sbomversion
```

The stub rejects any request that does not present the token it minted, so a change that breaks the authentication wiring fails there rather than passing quietly. It mirrors the behaviours this action is built around: components the request does not pin come back auto-resolved, an artefact that is not part of the SBOM is rejected, the same version cannot be created twice, and a second `draft` is refused with a *different* `409` from a duplicate version. Run the command again to see the `if-exists` behaviour, and add `ARTEFACTFLOW_IF_EXISTS=skip` to watch a re-run succeed.

## Before opening a pull request

CI runs these, so running them first saves a round trip:

```sh
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
docker build .    # the action is a container action; the image has to build
```

CI additionally runs a smoke test that executes the action end to end against the stub API, which covers the wiring the unit tests cannot reach.

## Conventions

- Keep the input mapping covered by tests. The runner exposes an input named `sbom-name` as `INPUT_SBOM-NAME`: it uppercases the name and replaces spaces with underscores, but it does not touch hyphens. Reading the underscored spelling would make every `with:` value invisible while every unit test still passed.
- The absent-versus-empty distinction on `components` is load-bearing. Omitting the field means "resolve every artefact in the SBOM to its latest stable version"; it is not the same as sending an empty list. Anything that could turn one into the other is a wrong-bill-of-materials bug, not a formatting one, which is also why an input that parses to no pins is an error rather than a silent fallback to auto-resolution.
- A partial component list is a set of overrides, not a replacement of the component set. Wherever this is described (docs, log lines, error messages), say so, because the intuitive reading is the wrong one.
- `409` is overloaded on this endpoint: it means either that the version exists or that the SBOM's single draft slot is taken. The remedies differ, so the two are always reported separately, and `if-exists: skip` covers only the first.
- Everything knowable before a request is made is checked before it is made, including a `components-file` that cannot be read or parsed. A release must never be created only for the run to discover its inputs were unusable all along.
- The `components` output is the action's most valuable one, because auto-resolution means the caller has no other way to learn what a release captured. An unknown component set is reported as empty rather than as `[]`: the second is a claim, the first is an admission.
- The client secret and the minted token must never reach a log line, an error message, or an output.
- Every default is applied in `LoadConfig`, never as a `default:` in `action.yml`. The runner substitutes a declared default before the action runs, which would make the `ARTEFACTFLOW_` fallback dead code. CI fails a pull request that adds one. `release-status` is the notable one: the API defaults to `draft`, this action to `released`.
- Failures surface as `::error::` annotations with a non-zero exit, so they land on the run summary rather than only in the step log.
- Prose in Markdown is written as one unwrapped line per paragraph: do not hard-wrap at a column.
- `action.yml` stays at the repository root; that is a Marketplace requirement.
- Do not edit `CHANGELOG.md`.

## Releasing

Releases are cut by maintainers from the `Release` workflow. It re-runs the tests from the tag, builds and pushes the multi-architecture image to GHCR, creates the GitHub release, and repoints the moving major tag (`v1`) at it, skipping that last step for pre-releases.

`action.yml` references **one exact image version**, for example `docker://ghcr.io/artefactflow/publish-sbomversion-action:1.2.3`, and that reference is part of the release commit. A floating `:1` would be less work, but it would mean someone who pins `uses: ...@v1.2.0` or a commit SHA silently gets a newer image on your next release. Pinning has to actually pin. The release workflow refuses to publish when the reference and the tag disagree.

So each release is:

1. Update `runs.image` in `action.yml` to the version being released, and commit.
2. Tag that commit (`git tag v1.2.3`) and push the tag.
3. Run the `Release` workflow against the tag, with **dry-run off**.

Between steps 2 and 3 the tag exists but its image does not, so the action is briefly unusable at that ref. Nothing consumes a tag before its release exists, so this is safe, but do not leave the gap open longer than necessary.

### The first release

The first release is the exception: no image exists yet, so `action.yml` stays on `image: 'Dockerfile'` and the workflow emits a notice rather than failing. That release builds on the runner for anyone who uses it. Immediately afterwards:

1. Confirm the package is **public**: GHCR packages are not reliably public just because the repository is, and a private image fails for every consumer with an unauthorized pull. Check under the organisation's Packages settings.
2. Switch `action.yml` to `docker://ghcr.io/artefactflow/publish-sbomversion-action:<that version>` and cut the next release normally.

Listing on the Marketplace is a manual step on the first release only: open the release, choose **Edit**, and tick **Publish this Action to the GitHub Marketplace**.

### Why CI stages a copy of the action

Because `action.yml` points at a published image, `uses: ./` in the smoke job would pull that image and test the last release rather than the pull request. The job therefore copies the action into `ci-local-action/` with the image reference rewritten to `Dockerfile`, and runs that. If you add a file the container build needs, add it to that copy step too.

Note that the copy covers only what the **image build** needs (`go.mod`, `cmd`, `internal`, and the Dockerfile). A container action still runs with the repository root as its working directory, so a path passed to `components-file` resolves against the real checkout rather than the staged copy.
