# Release security and verification

MRMA's release control plane is part of its trusted computing base. Provenance identifies the
source and workflow that produced an artifact; it does not establish that the source is benign or
that an experiment result is correct.

## Maintainer release policy

Publishing workflows accept only a signed annotated `v*` tag. Both workflows verify the tag
against `.github/release-signers` before publishing, and every write-bearing job is gated by the
protected `release` environment. Container publishing cannot be invoked with an arbitrary version
through manual workflow dispatch.

The `main` branch and `v*` tags are governed by repository rulesets. Security-sensitive source,
schemas, dependencies, container configuration, signer policy, and workflows have explicit
CODEOWNERS coverage. A second trusted maintainer should be added before enabling mandatory
code-owner approval; a sole maintainer cannot provide independent review.

## Verify a release

Install a current GitHub CLI, authenticate it, and verify the release before installation:

```bash
gh release verify v0.4.0 -R 0xmrma/mrma
gh release download v0.4.0 -R 0xmrma/mrma --pattern 'mrma-0.4.0-py3-none-any.whl'
gh release verify-asset v0.4.0 ./mrma-0.4.0-py3-none-any.whl -R 0xmrma/mrma
```

Verify the container's GitHub-signed provenance and require the publishing workflow and tag ref:

```bash
gh attestation verify oci://ghcr.io/0xmrma/mrma:0.4.0 \
  -R 0xmrma/mrma \
  --signer-workflow 0xmrma/mrma/.github/workflows/package.yml \
  --source-ref refs/tags/v0.4.0
```

The image also carries BuildKit provenance and SBOM manifests. Resolve the immutable OCI index
digest and pin deployments to `ghcr.io/0xmrma/mrma@sha256:...` rather than relying only on a
mutable semantic-version tag:

```bash
docker buildx imagetools inspect ghcr.io/0xmrma/mrma:0.4.0
```

Verification establishes artifact identity and build origin. It does not replace source review,
authorization policy, or evidence validation.
