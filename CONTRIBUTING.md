# Contributing

- Keep scanning and parsing defensive. Never execute or install a file being inspected.
- Add tests for every detection rule, including benign cases that must not be flagged.
- Include provenance, rationale, test coverage, and expiry/version metadata for future threat indicators.
- Never commit API keys, signing keys, private certificates, user files, or malware samples.
- Preserve the distinction between confirmed hash indicators, heuristic warnings, and unknown results.
- Do not add broad Android permissions without a documented requirement and policy review.

## Integration and regression policy

- The canonical integration candidate is `integration/release-candidate-stable`. New product work should target this branch through a pull request, not an older parallel feature branch.
- Do not merge unrelated or diverged feature histories wholesale. Review the exact file-level delta and port compatible components into the canonical branch.
- Treat `app/src/main/AndroidManifest.xml`, `app/src/main/res/**`, `app/src/main/java/com/antivirusalai/AntivirusApp.kt`, the scan engines, quarantine, and threat-feed verification as protected product surfaces.
- A launcher-icon change is incomplete unless the manifest references both `@mipmap/ic_launcher` and `@mipmap/ic_launcher` as the round icon, adaptive and legacy resources resolve, the artwork is present, and the built APK reports an application icon.
- Every change to launcher resources or core product wiring must pass `tools/test_android_release_invariants.py` through the normal Python unit-test discovery step.
- Keep local scan verdicts independent from optional cloud reputation. Cloud lookups must require explicit user consent and send only the SHA-256 digest.
- Do not claim Play readiness from a debug APK or unsigned AAB. Production signing, permission-policy declarations, privacy disclosures, and live threat-data operations require separate release approval.
- Do not commit secrets, private signing material, private malware samples, or user files. Do not deploy Workers or change production secrets from a code-only integration PR.
