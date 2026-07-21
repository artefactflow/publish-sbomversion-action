#!/usr/bin/env python3
"""A stub of the ArtefactFlow endpoints this action calls.

It exists so the action can be exercised end to end — the container, the input
plumbing, and $GITHUB_OUTPUT — without an ArtefactFlow instance and without any
secret, which is what lets the smoke test run on pull requests from forks too.

It is deliberately strict about the things the action could get wrong silently:
the token endpoint checks the credentials, the create endpoint rejects a request
that does not present the minted token, creating the same version twice returns
409, and creating a second draft returns a *different* 409 — the two conflicts
have different remedies and the action has to tell them apart. It also mirrors
the auto-resolution behaviour the action is built around: components the request
does not pin come back resolved in the response.

    python3 testdata/stub-api.py [port]
"""

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENT_ID = "507f191e810c19729de860ed"
CLIENT_SECRET = "afsa_stub-client-secret"
MINTED_TOKEN = "stub-minted-jwt"

SBOM_NAME = "acme-platform"

CREATE_PATH = re.compile(r"^/v1/sboms/([^/]+)/versions$")

# The artefacts that are components of the stub SBOM, with the version each one auto-resolves to when the request does not pin it. An artefact_id outside this set is rejected: this action pins versions of what the SBOM already holds, it cannot add artefacts to it.
SBOM_COMPONENTS = {
    "0123456789abcdef01234567": {"name": "acme-payment-service", "latest": "1.4.2"},
    "89abcdef0123456789abcdef": {"name": "acme-web", "latest": "3.0.1"},
    "fedcba9876543210fedcba98": {"name": "acme-scheduler", "latest": "0.8.7"},
}

created_versions = set()
draft_exists = False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_one_request(self):
        # Each request re-arms the drain guard; the body of one request must never be mistaken for the body of the next.
        self._drained = False
        self._raw = b""
        super().handle_one_request()

    def log_message(self, fmt, *args):
        # One line per request, on stderr, without the noisy default prefix.
        sys.stderr.write("stub-api: " + fmt % args + "\n")

    def _send(self, status, payload, headers=None):
        # Drain the request body first. With keep-alive on, replying to a request whose body is still unread leaves those bytes in the stream, where they are parsed as the next request line — turning every early-return error path into a confusing 501 on the *following* call.
        self._drain()
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, code, message):
        self._send(status, {"code": code, "message": message, "logid": "stub-log-id"})

    def _drain(self):
        """Read and discard any unread request body. Safe to call more than once."""
        if getattr(self, "_drained", False):
            return
        self._drained = True
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self._raw = self.rfile.read(length)

    def _body(self):
        self._drain()
        try:
            return json.loads(getattr(self, "_raw", b"") or b"{}")
        except json.JSONDecodeError:
            self._error(400, "GEN00001", "Malformed JSON body")
            return None

    def _authorised(self):
        # Only the token this stub minted is accepted. The action has no other way to
        # authenticate, so anything else means the credentials flow is broken.
        header = self.headers.get("Authorization", "")
        if header == f"Bearer {MINTED_TOKEN}":
            return True
        self._error(401, "AUTH00002", f"Unexpected Authorization header: {header!r}")
        return False

    def do_POST(self):
        global draft_exists
        path = self.path.split("?", 1)[0]

        if path == "/v1/auth/token":
            body = self._body()
            if body is None:
                return
            if body.get("client_id") != CLIENT_ID or body.get("client_secret") != CLIENT_SECRET:
                # The real API does not distinguish an unknown id from a wrong secret.
                self._error(401, "AUTH00001", "Invalid credentials")
                return
            self._send(200, {"access_token": MINTED_TOKEN, "expire_in": 300, "token_type": "Bearer"})
            return

        match = CREATE_PATH.match(path)
        if not match:
            self._error(404, "GEN00404", "No such endpoint")
            return
        if not self._authorised():
            return

        if match.group(1) != SBOM_NAME:
            self._error(404, "SBOM00404", "No SBOM with that name")
            return

        body = self._body()
        if body is None:
            return

        version = body.get("version")
        if not version:
            self._error(422, "SBOMVERSION00422", "Create body is missing version")
            return

        release_status = body.get("release_status", "draft")
        if release_status not in ("draft", "released"):
            self._error(422, "SBOMVERSION00422", f"Unexpected release_status {release_status!r}")
            return

        # Pins are overrides on top of auto-resolution, so an unknown artefact is a mistake worth catching rather than a component to add.
        pins = {}
        for component in body.get("components") or []:
            artefact_id = component.get("artefact_id")
            if artefact_id not in SBOM_COMPONENTS:
                self._error(422, "SBOMVERSION00422", f"Artefact {artefact_id} is not a component of this SBOM")
                return
            if component.get("version_id"):
                pins[artefact_id] = component["version_id"]

        if version in created_versions:
            self._error(409, "SBOMVERSION00409", "A version with that value already exists")
            return
        # The other meaning of 409, and the one whose remedy differs: an SBOM holds at most one draft.
        if release_status == "draft" and draft_exists:
            self._error(409, "SBOMVERSION00410", "This SBOM already has a draft version; release or delete it first")
            return

        created_versions.add(version)
        if release_status == "draft":
            draft_exists = True

        # Every artefact in the SBOM comes back, pinned or auto-resolved. This is the response the action turns into its `components` output, and the only way a caller learns what a partly-pinned release actually captured.
        resolved = [
            {
                "artefact_id": artefact_id,
                "artefact_name": meta["name"],
                "version": pins.get(artefact_id, meta["latest"]),
            }
            for artefact_id, meta in SBOM_COMPONENTS.items()
        ]
        self._send(
            201,
            {
                "version": version,
                "bom_ref": body.get("bom_ref") or "urn:uuid:11111111-2222-3333-4444-555555555555",
                "release_status": release_status,
                "components": resolved,
            },
            {"Location": f"/v1/sboms/{SBOM_NAME}/versions/{version}"},
        )


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    # Threaded on purpose. With keep-alive connections a single-threaded server accepts no new connection while an idle one is open, so a client that opens a second connection — a retry, or a client built with its own transport — would hang until it timed out.
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
