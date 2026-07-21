# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it through GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. That opens a private channel visible only to maintainers.

Include what you did, what happened, and what you expected — a minimal reproduction is worth more than anything else. You will get an acknowledgement, and we will keep you updated as the report is triaged and fixed. Please give us a chance to ship a fix before disclosing publicly.

## Supported versions

Fixes go onto the newest major release, and the moving major tag (for example `v1`) is repointed at it. Pin to the major tag to pick fixes up automatically, or to a full release tag if you would rather review each change.

## Handling of credentials

This action takes a service account's client id and client secret as inputs, and exchanges them for a short-lived access token. The secret is used for exactly one thing — that exchange — and it is never written to a log line, an error message, or an action output; the error path for the exchange is explicitly scrubbed of it, because that is the one request that carries a credential. The minted token is masked in the workflow log as soon as it is issued, is never emitted as an output, and is discarded when the action exits. It is also scrubbed from any API response the action turns into an error, so a service or proxy that echoes the request back cannot turn that into a leak.

The action deliberately does not accept an already-minted bearer token. That would make it easy to hand it a person's token, which carries far more scopes than the one this needs and attributes releases to a human rather than a machine identity.

Pass the client secret from an encrypted secret rather than inlining it, so the runner masks it in the log if anything ever does print it.

## Scope of what the action writes

This action writes to ArtefactFlow: it creates a version of one SBOM. It does not modify existing versions, and it cannot change which artefacts an SBOM contains — an `artefact_id` that is not already a component of the SBOM is rejected rather than added. A version created as `released` is immutable and cannot be reverted to a draft, so a wrong release cannot be quietly rewritten afterwards.

The `components` output records which artefact versions a release captured. It is not sensitive in itself, but it does describe your internal release composition — bear that in mind before echoing it into a public log or forwarding it outside the workflow.

Give the service account write access only to the groups whose SBOMs the workflow is meant to release.
