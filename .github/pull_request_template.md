## What this changes

<!-- What the change does, and why. If it fixes an open issue, link it here. -->

## How it was verified

<!-- Which tests cover it, and anything you checked by hand. -->

## Checklist

- [ ] `gofmt -l .` prints nothing, and `go vet ./...` and `go test -race ./...` pass
- [ ] The Dockerfile still builds
- [ ] Tests cover the change
- [ ] Inputs, outputs, and behaviour changes are reflected in `action.yml` and the README
- [ ] An absent `components` list still means "auto-resolve everything", and a partial list is still a set of overrides rather than a subset
- [ ] The two meanings of a `409` are still reported separately, with their own remedies
- [ ] No client secret, token, URL, or other credential appears in code, tests, logs, or this description
- [ ] `CHANGELOG.md` is untouched
