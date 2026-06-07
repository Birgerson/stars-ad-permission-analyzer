# Stars — Code-Signing-Status und Plan

[**Deutsch**](#deutsch) · [**English**](#english)

---

## <a name="deutsch"></a>Deutsch

### Aktueller Stand

Der Stars-Installer ist **nicht codesigned**. Beim ersten Start zeigt Windows SmartScreen die Warnung „Computer durch Windows geschützt — unbekannter Herausgeber". Anwender müssen dann auf „Weitere Informationen → Trotzdem ausführen" klicken.

**Was es stattdessen gibt** (siehe README, Abschnitt „Integrität verifizieren"): jeder Release-Build veröffentlicht eine `.sha256`-Datei. Anwender können damit prüfen, dass ihre heruntergeladene Datei bit-genau dem Build aus GitHub Actions entspricht. Das schützt gegen verfälschte Downloads, ersetzt aber kein Code-Signing.

### Warum (noch) kein Code-Signing

Stars wird als Open-Source-Projekt ohne kommerzielles Budget betrieben. Die drei realistischen Optionen erfordern alle laufende Kosten:

| Option | Kosten | SmartScreen-Reputation | HSM-Pflicht | CI/CD-Integration |
|---|---|---|---|---|
| **Azure Trusted Signing** | ~10 USD/Monat | langsam aufbauend | nein (Cloud) | sehr gut (OIDC) |
| **EV Code Signing** (DigiCert, Sectigo, SSL.com) | ~400–700 USD/Jahr | sofort ab erster Signatur | ja (USB-Token) | schwierig ohne Tricks |
| **OV Code Signing** (Standard) | ~200–400 USD/Jahr | Wochen bis Monate | ja (USB-Token) | schwierig ohne Tricks |

### Wenn Code-Signing dazukommen soll

Der bestehende Release-Workflow (`.github/workflows/release.yml`) ist so strukturiert, dass eine zukünftige Signatur als **eine neue GitHub-Actions-Step** zwischen „Build NSIS installer" und „Stage release artifact" eingefügt werden kann. Die Hash-Berechnung bleibt unverändert — sie wird dann zusätzlich zur Signatur ausgeführt.

Konkret braucht ein Sponsor / der Maintainer dann:

1. **Zertifikat oder Service-Account beschaffen** (siehe Tabelle oben).
2. **Zwei GitHub-Secrets anlegen:** `CODESIGN_CERT_PFX` (Base64-kodiertes PFX) und `CODESIGN_CERT_PASSWORD` — oder bei Azure Trusted Signing eine Federated-Identity-Konfiguration.
3. **Neuer Workflow-Step** ruft `signtool.exe sign /fd SHA256 /tr <timestamp-server> /td SHA256 ...` auf den NSIS-Installer auf, bevor der Hash berechnet wird (damit der Hash über den signierten Installer geht).
4. **README-Hinweis** zum fehlenden Code-Signing entfernen.

### Was wir nicht tun

Selbstsignierte Zertifikate werden **nicht** verwendet — sie geben Anwendern keine zusätzliche Sicherheit und sind nicht in SmartScreen registriert. Wer auf einer von Stars analysierten Maschine ein selbstsigniertes Zertifikat installiert, vergrößert eher die Angriffsfläche als sie zu verkleinern.

---

## <a name="english"></a>English

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
