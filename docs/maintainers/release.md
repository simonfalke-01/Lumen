# Release Lumen

`version.txt` is the single source of truth for Lumen's user-visible version. It must contain a stable SemVer version such
as `0.1.0`, or an `alpha.N`, `beta.N`, or `rc.N` prerelease such as `0.1.0-alpha.1`. CMake uses the numeric core for
platform package metadata while the application, build artifacts, and GitHub release use the complete SemVer value.
Because Windows is the published target, major and minor components must not exceed 255 and patch must not exceed
65535.

The release tag must exactly equal `v` followed by the contents of `version.txt`. For example, the initial release is
`v0.1.0-alpha.1`. Untagged builds include a `.dev.N+gCOMMIT` suffix and cannot be mistaken for a release build.

## Create a release

1. Update `version.txt` to the intended version in a normal reviewed commit.
2. Run the normal Windows CI and confirm it passes on that commit.
3. Create and push the matching annotated tag. Do not create the GitHub Release manually.

   ```text
   git tag -a v0.1.0-alpha.1 -m "Lumen 0.1.0-alpha.1"
   git push origin v0.1.0-alpha.1
   ```

   Release tags are protected against update and deletion. If a tag is wrong, fix the release commit, increment
   `version.txt`, and create a new tag instead of moving the old one.

4. The `Release` workflow validates that the tag exactly matches `version.txt`, builds that tag through the reusable
   Windows workflow, reruns the non-driver installer validation scenarios, and downloads the versioned Lumen artifacts.
   The optional Virtual HID install/uninstall scenario remains a required check in the normal Windows CI before the tag
   is created; it is not repeated during release publication because hosted driver installation is nondeterministic.
5. Approve the deployment in the protected GitHub `release` environment when the validation evidence is complete.
6. After approval, the workflow revalidates the remote tag target, generates `SHA256SUMS` and `update-manifest.json`, records GitHub artifact
   provenance attestations, and publishes the GitHub Release with generated notes.

The update manifest is release metadata for current and future clients. Each binary entry includes its file name,
size, SHA-256 digest, and immutable tag download URL. The repository enforces GitHub immutable releases, and the
workflow verifies that the published release is immutable. Consumers should still verify the digest after downloading;
release publication also records GitHub provenance for the uploaded bytes.

The current application implements release discovery and a trusted repository-scoped download link. It does not
download, verify, or execute installers automatically. Prerelease installations follow newer prereleases by default;
stable installations only consider prereleases when the existing opt-in setting is enabled.

## Stable-release gate

Stable `vX.Y.Z` publication is hard-disabled until the production release requirements are implemented and reviewed.
Until then, publish only prerelease versions.

## Verify downloaded artifacts

Download the release assets, then verify their checksums from the same directory:

```text
sha256sum --check SHA256SUMS
```

GitHub provenance can also be checked with the GitHub CLI:

```text
gh attestation verify Lumen-0.1.0-alpha.1-Windows-AMD64-installer.msi \
  --repo simonfalke-01/Lumen
```
