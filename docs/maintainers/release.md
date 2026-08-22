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
   Windows workflow, runs the installer validation scenarios, and downloads the versioned Lumen artifacts.
5. Approve the deployment in the protected GitHub `release` environment when the validation evidence is complete.
6. After approval, the workflow revalidates the remote tag target, generates `SHA256SUMS` and `update-manifest.json`, records GitHub artifact
   provenance attestations, and publishes the GitHub Release with generated notes.

The update manifest is release metadata for current and future clients. Each binary entry includes its file name,
size, SHA-256 digest, and immutable tag download URL. The repository enforces GitHub immutable releases, and the
workflow refuses to publish if that protection is disabled. Consumers should still verify the digest after
downloading; release publication also records GitHub provenance for the uploaded bytes.

The current application implements release discovery and a trusted repository-scoped download link. It does not
download, verify, or execute installers automatically. Prerelease installations follow newer prereleases by default;
stable installations only consider prereleases when the existing opt-in setting is enabled.

## Signing and stable-release gate

Prerelease applications and MSI packages are currently unsigned. They may bundle a per-run self-signed Virtual HID
driver certificate; the release notes and update manifest call this out explicitly, and Virtual HID installation
remains opt-in.

Stable `vX.Y.Z` publication is hard-disabled. Enabling stable releases requires implementation steps that sign and
verify the application, MSI, catalog, and Virtual HID driver inside the release workflow. An operator variable is not
accepted as proof of signing. Until those steps exist and are reviewed, publish only prerelease versions.

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
