# Publish SBOM Version

[![CI](https://github.com/artefactflow/publish-sbomversion-action/actions/workflows/ci.yml/badge.svg)](https://github.com/artefactflow/publish-sbomversion-action/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## What is ArtefactFlow?

[ArtefactFlow](https://www.artefactflow.com) is a hosted platform for managing software artefacts and their Software Bills of Materials. It gives your team one source of truth for every application, library and image you ship: each artefact and its versions, the licenses and vulnerabilities they carry, the immutable CycloneDX SBOMs that describe them, and a record of which SBOM version is running in which environment. So when someone asks what is inside a release, whether it is vulnerable, or what exactly is in production right now, there is one answer rather than four.

Everything is available over a REST API, which is what makes integrations like this one possible. [Create an account](https://www.artefactflow.com) to get started, or read the [documentation](https://docs.artefactflow.com) for the full picture.

## What this action does

An SBOM in ArtefactFlow names a set of artefacts that ship together. A *version* of that SBOM is one release of the set: which artefact version of each belongs to it.

The point of this action is that you usually do not have to say. Give it an SBOM name and a SemVer, and every artefact in the SBOM resolves to its latest stable version:

```yaml
- uses: artefactflow/publish-sbomversion-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    sbom-name: acme-platform
    version: 2.0.0
```

A release pipeline that has kept its artefact versions up to date — with [publish-version-action](https://github.com/artefactflow/publish-version-action), for instance — needs nothing more than that to record a complete bill of materials.

When one artefact does need pinning, pin it. Everything else still auto-resolves:

```yaml
- uses: artefactflow/publish-sbomversion-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    sbom-name: acme-platform
    version: 2.0.0
    components: |
      0123456789abcdef01234567=1.4.2
```

**A partial list is a set of overrides, not a subset.** The artefacts it does not mention are still part of the version — they auto-resolve. There is no way to use this action to produce an SBOM version covering only some of the SBOM's artefacts, and no way to add an artefact to an SBOM: pinning an `artefact_id` that is not already a component of the SBOM is rejected.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `client-id` | yes | | A service account's client id — its 24-character hex id |
| `client-secret` | yes | | The service account's client secret. Pass it from a secret |
| `sbom-name` | yes | | The SBOM name. Exact and case-sensitive |
| `version` | yes | | The SemVer version to create, unique within the SBOM |
| `api-url` | no | `https://api.artefactflow.app` | Base URL of the API. Self-hosted operators override it |
| `release-status` | no | `released` | `released` or `draft` — see below |
| `components` | no | | Pins, one `artefact-id[=version]` per line |
| `components-file` | no | | The same pins from a JSON file. Mutually exclusive with `components` |
| `base-version` | no | | SemVer of an existing version to fork from |
| `bom-ref` | no | generated | CycloneDX bom-ref. Immutable once the version exists |
| `note` | no | | Free-text note, at most 4096 characters |
| `hotfix-flag` | no | `false` | Mark this version as a temporary hotfix |
| `compliance-status` | no | | `compliant`, `pending`, `review`, or `non_compliant` |
| `lifecycles` | no | | `design`, `build`, `operations`, `discovery`, `decommission`, `end-of-life` |
| `deployed-envs` | no | | Environment ids this release is deployed to, as 24-hex ids |
| `external-references` | no | the workflow run | Typed links, one `type url [comment]` per line |
| `if-exists` | no | `fail` | `fail` or `skip` when the version already exists |

### Pinning components

`components` takes one pin per line. The version is optional — a line with only an artefact id auto-resolves, exactly as leaving it out would, so a pipeline generating this list does not have to filter its own output:

```yaml
components: |
  0123456789abcdef01234567=1.4.2
  89abcdef0123456789abcdef=0.9.0-rc.1
  fedcba9876543210fedcba98
```

For a generated list, write it to a file and use `components-file` instead. The format is in [examples/components.json](examples/components.json). Unknown keys are rejected: a file using a key this action does not read would otherwise pin nothing while looking like it pinned everything.

### Drafts and released versions

`release-status` defaults to `released`, which is not the API's own default. A released version is frozen the moment it is created, and creating one is a single call with no follow-up — the right shape for a pipeline.

The alternative, `draft`, has one property worth knowing before you choose it: **an SBOM permits only one draft at a time.** A second concurrent draft fails, so two pipelines racing to draft the same SBOM will have one of them fall over. Creating as `released` avoids the contention entirely.

Released is also one-way. A released version cannot be modified, and cannot be reverted to a draft.

### Recording provenance

The SBOM version body has no commit, build, or pipeline fields of its own — those live on the *artefact* versions it captures. External references are where a release records where it came from, so a link back to the workflow run is added automatically:

```yaml
external-references: |
  release-notes https://example.com/releases/2.0.0 Release notes
  vcs https://github.com/acme/platform Source
```

Supply a `build-system` reference of your own and the automatic one is left off, rather than the version carrying two contradictory answers to "which build made this?".

### Configuring through the environment

Every input can also come from an `ARTEFACTFLOW_`-prefixed environment variable — `sbom-name` from `ARTEFACTFLOW_SBOM_NAME`, and so on. A `with:` value always wins. This is what lets one job-level `env:` block configure several steps:

```yaml
jobs:
  release:
    env:
      ARTEFACTFLOW_CLIENT_ID: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
      ARTEFACTFLOW_CLIENT_SECRET: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
      ARTEFACTFLOW_SBOM_NAME: acme-platform
    steps:
      - uses: artefactflow/publish-sbomversion-action@v1
        with:
          version: 2.0.0
```

## Outputs

| Output | Description |
|---|---|
| `version` | The SemVer version that was published |
| `version-url` | API URL of the version |
| `sbom-name` | The SBOM the version was created on |
| `release-status` | `released` or `draft`, as created |
| `created` | `true` when this run created the version; `false` when it already existed and `if-exists` was `skip` |
| `components` | The resolved component set, as JSON |

`components` is the one to pay attention to. Because artefacts auto-resolve, the workflow that asked for the release does not otherwise know which artefact versions it captured:

```yaml
- id: publish
  uses: artefactflow/publish-sbomversion-action@v1
  with:
    sbom-name: acme-platform
    version: 2.0.0

- name: Show what shipped
  run: echo '${{ steps.publish.outputs.components }}' | jq -r '.[] | "\(.artefact_name) \(.version)"'
```

It is empty rather than `[]` when the run resolved nothing — after an `if-exists: skip`, for instance. An empty array would be a claim that the release captured nothing; an empty value says this run does not know.

## Re-runs, and versions that already exist

By default a version that already exists fails the step, because a pipeline releasing the same version twice is usually a mistake worth seeing. `if-exists: skip` treats it as success and changes nothing on the existing version, which makes a re-run of a whole release workflow safe.

`skip` covers only that one conflict. An SBOM that already holds its one permitted draft is a different failure with a different remedy — release or delete the outstanding draft, or create as `released` — and the requested version does not exist either way, so it always fails the step.

## Composing with the other actions

The natural release chain is one artefact at a time, then the SBOM at the end:

1. [suggest-version-action](https://github.com/artefactflow/suggest-version-action) — work out the next version of an artefact.
2. [publish-version-action](https://github.com/artefactflow/publish-version-action) — record what each build produced.
3. This action — snapshot the whole set as one release of the SBOM.

Because step 2 keeps every artefact's latest version current, step 3 needs no component list at all.

## Authentication

The action takes a service account's client id and secret and exchanges them for a short-lived token. It deliberately does not accept an already-minted bearer token: that would make it easy to hand it a person's token, which carries far more scopes than this needs and attributes releases to a human rather than a machine identity.

### Scopes and team access

The service account needs the `sbom:write` scope **and** membership of a team with write access to the SBOM's group. Both are checked, and both fail with `403` — a fresh service account with the right scope but no team grant is still denied.

## Retries, timeouts, and what the action does on its own

Connection failures, `429`, and `5xx` responses are retried up to three times with exponential backoff and jitter, honouring `Retry-After`. Permanent failures are not retried. The whole run is bounded by a five-minute timeout, and the runner cancelling the job stops an in-flight retry.

## Permissions

The action needs no `permissions:` grant of its own — it talks to ArtefactFlow, not to the GitHub API.

## Requirements

A Linux runner (this is a container action) and an ArtefactFlow service account.

## Troubleshooting

| What you see | What it usually means |
|---|---|
| `HTTP 401: the client credentials were rejected` | Wrong or rotated `client-secret`, or an unknown `client-id`. The API does not distinguish the two |
| `HTTP 402` | The organisation is over its plan limit. No retry or input change resolves it |
| `HTTP 403` | Missing `sbom:write`, or the service account is in no team with write access to the SBOM's group |
| `HTTP 404` | No SBOM with that name on this instance. The name is exact and case-sensitive |
| `already has an outstanding draft version` | The SBOM's single draft slot is taken. Release or delete it, or use `release-status: released` |
| `version … already exists` | Pick another version, or set `if-exists: skip` if a re-run should tolerate it |
| An artefact was rejected as `not a component of this SBOM` | This action pins versions of what the SBOM already holds; add the artefact to the SBOM first |

Errors quote the API's own message and its log id, which is what to include when asking for help with a `403` or a `500`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

[Apache-2.0](LICENSE)
