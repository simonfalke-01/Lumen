/** GitHub repository used for Lumen release checks. */
export const LUMEN_REPOSITORY = 'simonfalke-01/Lumen';

/** GitHub API endpoint used to retrieve published Lumen releases. */
export const LUMEN_RELEASES_API_URL =
  `https://api.github.com/repos/${LUMEN_REPOSITORY}/releases?per_page=100`;

/** Public Lumen release page used for safe URL fallbacks. */
export const LUMEN_RELEASES_URL =
  `https://github.com/${LUMEN_REPOSITORY}/releases`;

const SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

/**
 * Parse a strict Semantic Versioning 2.0.0 value.
 *
 * A leading lowercase `v` is accepted for compatibility with Git tags. The
 * version itself must otherwise follow the SemVer grammar exactly.
 *
 * @param {string} version Version or Git tag to parse.
 * @returns {object|null} Parsed version fields, or `null` when invalid.
 */
export function parseSemVer(version) {
  if (typeof version !== 'string' || version.length === 0) {
    return null;
  }

  const normalized = version.startsWith('v') ? version.slice(1) : version;
  const match = SEMVER_PATTERN.exec(normalized);
  if (!match) {
    return null;
  }

  return {
    raw: version,
    normalized,
    major: match[1],
    minor: match[2],
    patch: match[3],
    prerelease: match[4] ? match[4].split('.') : [],
    build: match[5] ? match[5].split('.') : [],
  };
}

/**
 * Compare unsigned decimal identifiers without losing integer precision.
 *
 * @param {string} left Left numeric identifier.
 * @param {string} right Right numeric identifier.
 * @returns {-1|0|1} Ordering of the identifiers.
 */
function compareNumericIdentifiers(left, right) {
  if (left.length !== right.length) {
    return left.length < right.length ? -1 : 1;
  }
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

/**
 * Compare two parsed Semantic Versioning values.
 *
 * Build metadata is intentionally excluded from precedence as required by
 * SemVer 2.0.0.
 *
 * @param {object} left Parsed left-hand version.
 * @param {object} right Parsed right-hand version.
 * @returns {-1|0|1} SemVer precedence ordering.
 */
function compareParsedVersions(left, right) {
  for (const field of ['major', 'minor', 'patch']) {
    const result = compareNumericIdentifiers(left[field], right[field]);
    if (result !== 0) {
      return result;
    }
  }

  if (left.prerelease.length === 0 || right.prerelease.length === 0) {
    if (left.prerelease.length === right.prerelease.length) {
      return 0;
    }
    return left.prerelease.length === 0 ? 1 : -1;
  }

  const identifierCount = Math.max(
    left.prerelease.length,
    right.prerelease.length,
  );
  for (let index = 0; index < identifierCount; index += 1) {
    const leftIdentifier = left.prerelease[index];
    const rightIdentifier = right.prerelease[index];
    if (leftIdentifier === undefined || rightIdentifier === undefined) {
      return leftIdentifier === undefined ? -1 : 1;
    }
    if (leftIdentifier === rightIdentifier) {
      continue;
    }

    const leftNumeric = /^\d+$/.test(leftIdentifier);
    const rightNumeric = /^\d+$/.test(rightIdentifier);
    if (leftNumeric && rightNumeric) {
      return compareNumericIdentifiers(leftIdentifier, rightIdentifier);
    }
    if (leftNumeric !== rightNumeric) {
      return leftNumeric ? -1 : 1;
    }
    return leftIdentifier < rightIdentifier ? -1 : 1;
  }

  return 0;
}

/**
 * Convert a version object or string to parsed SemVer.
 *
 * @param {LumenVersion|string} version Version value to parse.
 * @returns {object} Parsed Semantic Versioning fields.
 */
function requireParsedVersion(version) {
  if (version instanceof LumenVersion) {
    return version.parsedVersion;
  }
  const parsed = parseSemVer(version);
  if (!parsed) {
    throw new TypeError(`Invalid Semantic Version: ${String(version)}`);
  }
  return parsed;
}

/**
 * Compare two strict Semantic Versioning values.
 *
 * @param {LumenVersion|string} left Left version.
 * @param {LumenVersion|string} right Right version.
 * @returns {-1|0|1} SemVer precedence ordering.
 */
export function compareSemVer(left, right) {
  return compareParsedVersions(
    requireParsedVersion(left),
    requireParsedVersion(right),
  );
}

/**
 * Compare deterministic release metadata after equal SemVer precedence.
 *
 * @param {object} left Left release.
 * @param {object} right Right release.
 * @returns {-1|0|1} Release ordering.
 */
function compareReleaseMetadata(left, right) {
  const fields = ['published_at', 'created_at', 'tag_name', 'name', 'html_url'];
  for (const field of fields) {
    const leftValue = String(left[field] ?? '');
    const rightValue = String(right[field] ?? '');
    if (leftValue !== rightValue) {
      return leftValue < rightValue ? -1 : 1;
    }
  }

  const leftId = String(left.id ?? '');
  const rightId = String(right.id ?? '');
  if (leftId === rightId) {
    return 0;
  }
  return leftId < rightId ? -1 : 1;
}

/**
 * Select the highest valid stable or prerelease from GitHub release records.
 *
 * Draft releases and releases whose GitHub prerelease flag disagrees with the
 * SemVer tag are ignored. Equal-precedence releases use release metadata as a
 * deterministic tie-breaker.
 *
 * @param {object[]} releases GitHub release records.
 * @param {object} options Selection options.
 * @param {boolean} options.prerelease Select prereleases when `true`.
 * @returns {object|null} Selected release, or `null` when none match.
 */
export function selectLatestRelease(releases, { prerelease = false } = {}) {
  if (!Array.isArray(releases)) {
    return null;
  }

  const candidates = releases
    .map((release) => ({
      release,
      parsed: parseSemVer(release?.tag_name),
    }))
    .filter(({ release, parsed }) => {
      if (!release || release.draft || !parsed) {
        return false;
      }
      const semVerIsPrerelease = parsed.prerelease.length > 0;
      return Boolean(release.prerelease) === prerelease &&
        semVerIsPrerelease === prerelease;
    });

  candidates.sort((left, right) => {
    const versionResult = compareParsedVersions(left.parsed, right.parsed);
    return versionResult || compareReleaseMetadata(left.release, right.release);
  });

  return candidates.length > 0
    ? candidates[candidates.length - 1].release
    : null;
}

/**
 * Select the latest stable and prerelease Lumen releases.
 *
 * @param {object[]} releases GitHub release records.
 * @returns {{stable: object|null, prerelease: object|null}} Selected releases.
 */
export function selectLatestReleases(releases) {
  return {
    stable: selectLatestRelease(releases),
    prerelease: selectLatestRelease(releases, { prerelease: true }),
  };
}

/**
 * Retrieve Lumen releases from GitHub.
 *
 * @param {typeof fetch} fetchImplementation Fetch implementation to use.
 * @returns {Promise<object[]>} GitHub release records.
 */
export async function fetchLumenReleases(fetchImplementation = fetch) {
  const response = await fetchImplementation(LUMEN_RELEASES_API_URL, {
    headers: {
      Accept: 'application/vnd.github+json',
    },
  });
  if (!response.ok) {
    throw new Error(`GitHub releases request failed with HTTP ${response.status}`);
  }

  const releases = await response.json();
  if (!Array.isArray(releases)) {
    throw new TypeError('GitHub releases response was not an array');
  }
  return releases;
}

/**
 * Determine whether a URL belongs to the Lumen release area on GitHub.
 *
 * @param {string} value URL to validate.
 * @param {object} options Validation options.
 * @param {boolean} options.download Require a release asset download URL.
 * @returns {boolean} `true` only for an allowed repository-scoped HTTPS URL.
 */
export function isTrustedLumenReleaseUrl(value, { download = false } = {}) {
  if (typeof value !== 'string') {
    return false;
  }

  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.hostname !== 'github.com' ||
        url.port !== '' || url.username !== '' || url.password !== '') {
      return false;
    }

    const releasePath = `/${LUMEN_REPOSITORY}/releases`;
    return download
      ? url.pathname.startsWith(`${releasePath}/download/`)
      : url.pathname === releasePath ||
          url.pathname.startsWith(`${releasePath}/`);
  } catch {
    return false;
  }
}

/**
 * Convert untrusted release notes to escaped, line-preserving plain text.
 *
 * @param {unknown} releaseNotes GitHub release body.
 * @returns {string} HTML-safe plain text with line breaks.
 */
export function formatReleaseNotesAsHtml(releaseNotes) {
  if (typeof releaseNotes !== 'string' || releaseNotes.length === 0) {
    return '';
  }

  return releaseNotes
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
    .replaceAll('\r\n', '\n')
    .replaceAll('\r', '\n')
    .replaceAll('\n', '<br>');
}

/**
 * Resolve a trusted release page URL, falling back to a local construction.
 *
 * @param {object} release GitHub release record.
 * @returns {string} Trusted Lumen release URL.
 */
function getReleasePageUrl(release) {
  if (isTrustedLumenReleaseUrl(release?.html_url)) {
    return release.html_url;
  }
  const parsedVersion = parseSemVer(release?.tag_name);
  return parsedVersion
    ? `${LUMEN_RELEASES_URL}/tag/${encodeURIComponent(release.tag_name)}`
    : LUMEN_RELEASES_URL;
}

/**
 * Select a version-matched Windows installer from a release.
 *
 * @param {object} release GitHub release record.
 * @returns {object|null} Matching release asset.
 */
export function selectWindowsInstallerAsset(release) {
  const parsedVersion = parseSemVer(release?.tag_name);
  if (!parsedVersion || !Array.isArray(release.assets)) {
    return null;
  }

  const expectedName = `Lumen-${parsedVersion.normalized}-Windows-AMD64-installer.msi`;
  return release.assets.find((asset) => {
    return asset?.name === expectedName &&
      isTrustedLumenReleaseUrl(asset.browser_download_url, {
        download: true,
      });
  }) ?? null;
}

/**
 * Resolve the user-facing download URL for a release.
 *
 * Windows uses a matching versioned installer asset when one exists. Every
 * other case safely falls back to the GitHub release page. This function only
 * returns a URL and never downloads or executes an installer.
 *
 * @param {object} release GitHub release record.
 * @param {string} platform Lumen platform identifier.
 * @returns {string} Installer or release page URL.
 */
export function getReleaseDownloadUrl(release, platform) {
  if (platform === 'windows') {
    const installer = selectWindowsInstallerAsset(release);
    if (installer) {
      return installer.browser_download_url;
    }
  }
  return getReleasePageUrl(release);
}

/** A strict Semantic Versioning wrapper for installed and GitHub versions. */
class LumenVersion {
  /**
   * Create a version wrapper.
   *
   * @param {object|null} release GitHub release record.
   * @param {string|null} version Installed version when no release is supplied.
   */
  constructor(release = null, version = null) {
    if (!release && !version) {
      throw new Error('Either release or version must be provided');
    }

    this.release = release;
    this.version = release ? release.tag_name : version;
    this.versionName = release ? release.name : null;
    this.versionTag = release ? release.tag_name : null;
    this.parsedVersion = requireParsedVersion(this.version);
    this.versionParts = [
      this.parsedVersion.major,
      this.parsedVersion.minor,
      this.parsedVersion.patch,
    ];
    this.versionMajor = this.parsedVersion.major;
    this.versionMinor = this.parsedVersion.minor;
    this.versionPatch = this.parsedVersion.patch;
  }

  /**
   * Parse a strict Semantic Versioning value.
   *
   * @param {string} version Version to parse.
   * @returns {object|null} Parsed version fields.
   */
  parseVersion(version) {
    return parseSemVer(version);
  }

  /**
   * Determine whether this version has higher SemVer precedence.
   *
   * @param {LumenVersion|string} otherVersion Version to compare against.
   * @returns {boolean} `true` when this version is newer.
   */
  isGreater(otherVersion) {
    return compareSemVer(this, otherVersion) > 0;
  }

  /**
   * Resolve the download link for this release.
   *
   * @param {string} platform Lumen platform identifier.
   * @returns {string|null} Installer or release page URL.
   */
  downloadUrl(platform) {
    return this.release ? getReleaseDownloadUrl(this.release, platform) : null;
  }
}

export default LumenVersion;
