# Stars — Code-Signing Status and Plan

### Current status

The Stars installer is **not code-signed**. On first launch Windows SmartScreen shows "Windows protected your PC — unrecognized publisher". Users have to click "More info → Run anyway".

**What we ship instead** (see the README, "Verify integrity" section): every release build publishes a `.sha256` file. Users can check that their downloaded file is bit-for-bit identical to the build produced by GitHub Actions. That protects against tampered downloads but does not replace code-signing.

### Why no code-signing (yet)

Stars is an open-source project without commercial budget. The three realistic options all involve ongoing cost:

| Option | Cost | SmartScreen reputation | HSM required | CI/CD integration |
|---|---|---|---|---|
| **Azure Trusted Signing** | ~10 USD/month | builds up slowly | no (cloud) | very good (OIDC) |
| **EV Code Signing** (DigiCert, Sectigo, SSL.com) | ~400–700 USD/year | immediate from first signature | yes (USB token) | hard without workarounds |
| **OV Code Signing** (Standard) | ~200–400 USD/year | weeks to months | yes (USB token) | hard without workarounds |

### When code-signing gets added

The existing release workflow (`.github/workflows/release.yml`) is structured so that a future signature is added as **one new GitHub Actions step** between "Build NSIS installer" and "Stage release artifact". The hash computation stays unchanged — it then runs in addition to the signature.

Concretely, a sponsor / the maintainer then needs:

1. **Obtain a certificate or service account** (see table above).
2. **Add two GitHub secrets:** `CODESIGN_CERT_PFX` (base64-encoded PFX) and `CODESIGN_CERT_PASSWORD` — or, for Azure Trusted Signing, configure federated identity.
3. **New workflow step** calls `signtool.exe sign /fd SHA256 /tr <timestamp-server> /td SHA256 ...` on the NSIS installer before the hash is computed (so the hash covers the signed installer).
4. **Remove the "no code-signing" note** from the README.

### What we don't do

Self-signed certificates are **not used** — they give users no additional security and are not registered with SmartScreen. Installing a self-signed certificate on a machine that Stars analyzes increases the attack surface rather than reducing it.
