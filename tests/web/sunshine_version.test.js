import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import LumenVersion, {
  LUMEN_RELEASES_API_URL,
  LUMEN_RELEASES_URL,
  compareSemVer,
  fetchLumenReleases,
  formatReleaseNotesAsHtml,
  getReleaseDownloadUrl,
  isTrustedLumenReleaseUrl,
  parseSemVer,
  selectLatestRelease,
  selectLatestReleases,
  selectWindowsInstallerAsset,
} from '../../src_assets/common/assets/web/sunshine_version.js';

function release(tagName, options = {}) {
  return {
    id: options.id ?? 1,
    tag_name: tagName,
    name: options.name ?? tagName,
    html_url: options.html_url ?? `${LUMEN_RELEASES_URL}/tag/${tagName}`,
    published_at: options.published_at ?? '2026-01-01T00:00:00Z',
    created_at: options.created_at ?? '2026-01-01T00:00:00Z',
    draft: options.draft ?? false,
    prerelease: options.prerelease ?? tagName.includes('-'),
    assets: options.assets ?? [],
  };
}

const indexSource = readFileSync(
  new URL('../../src_assets/common/assets/web/index.html', import.meta.url),
  'utf8',
);

test('parses strict SemVer tags with prerelease and build metadata', () => {
  assert.deepEqual(parseSemVer('v12.34.56-rc.2+windows.1'), {
    raw: 'v12.34.56-rc.2+windows.1',
    normalized: '12.34.56-rc.2+windows.1',
    major: '12',
    minor: '34',
    patch: '56',
    prerelease: ['rc', '2'],
    build: ['windows', '1'],
  });
});

test('rejects values outside strict SemVer', () => {
  const invalidVersions = [
    '',
    '1',
    '1.2',
    '01.2.3',
    '1.02.3',
    '1.2.03',
    '1.2.3-01',
    '1.2.3-',
    '1.2.3+',
    '1.2.3.4',
    'V1.2.3',
    'release-1.2.3',
  ];
  for (const version of invalidVersions) {
    assert.equal(parseSemVer(version), null, version);
  }
  assert.throws(() => new LumenVersion(null, '1.2'), /Invalid Semantic Version/);
});

test('implements the full SemVer prerelease precedence chain', () => {
  const orderedVersions = [
    '1.0.0-alpha',
    '1.0.0-alpha.1',
    '1.0.0-alpha.beta',
    '1.0.0-beta',
    '1.0.0-beta.2',
    '1.0.0-beta.11',
    '1.0.0-rc.1',
    '1.0.0',
  ];
  for (let index = 1; index < orderedVersions.length; index += 1) {
    assert.equal(
      compareSemVer(orderedVersions[index - 1], orderedVersions[index]),
      -1,
    );
  }
  assert.equal(compareSemVer('1.0.0-rc.1', '1.0.0-rc.1'), 0);
  assert.equal(compareSemVer('1.0.0', '1.0.0-rc.1'), 1);
  assert.equal(compareSemVer('1.0.0-alpha.1', '1.0.0-alpha'), 1);
  assert.equal(compareSemVer('1.0.0-alpha.beta', '1.0.0-alpha.1'), 1);
  assert.equal(compareSemVer('1.0.0-beta', '1.0.0-alpha'), 1);
  assert.equal(compareSemVer('1.1.0', '1.0.9'), 1);
  assert.equal(compareSemVer('1.0.2', '1.0.1'), 1);
});

test('ignores build metadata for precedence and handles large numbers exactly', () => {
  assert.equal(compareSemVer('1.2.3+linux', '1.2.3+windows'), 0);
  assert.equal(
    compareSemVer(
      '999999999999999999999999.0.0',
      '1000000000000000000000000.0.0',
    ),
    -1,
  );
});

test('uses tag_name for both release version fields', () => {
  const version = new LumenVersion(release('v2.3.4'), null);
  assert.equal(version.version, 'v2.3.4');
  assert.equal(version.versionTag, 'v2.3.4');
  assert.equal(version.isGreater('2.3.3'), true);
  assert.equal(version.parseVersion('2.3.4').patch, '4');
  assert.equal(version.downloadUrl('linux'), version.release.html_url);

  const installedVersion = new LumenVersion(null, '2.3.4');
  assert.equal(installedVersion.downloadUrl('windows'), null);
  assert.throws(() => new LumenVersion(), /must be provided/);
});

test('selects stable and prerelease releases by SemVer rather than API order', () => {
  const releases = [
    release('v2.0.0-rc.1', { prerelease: true }),
    release('v1.8.0'),
    release('v1.10.0'),
    release('v9.0.0', { draft: true }),
    release('v2.0.0-rc.3', { prerelease: true }),
    release('v2.0.0-rc.2', { prerelease: true }),
  ];

  const selected = selectLatestReleases(releases);
  assert.equal(selected.stable.tag_name, 'v1.10.0');
  assert.equal(selected.prerelease.tag_name, 'v2.0.0-rc.3');
});

test('ignores invalid tags and mismatched GitHub prerelease flags', () => {
  const releases = [
    null,
    release('not-semver'),
    release('v4.0.0-rc.1', { prerelease: false }),
    release('v4.0.0', { prerelease: true }),
    release('v3.0.0'),
  ];
  assert.equal(selectLatestRelease(releases).tag_name, 'v3.0.0');
  assert.equal(selectLatestRelease(releases, { prerelease: true }), null);
});

test('breaks equal-precedence release ties deterministically', () => {
  const earlier = release('v1.0.0+build.2', {
    published_at: '2026-01-01T00:00:00Z',
  });
  const later = release('v1.0.0+build.1', {
    published_at: '2026-02-01T00:00:00Z',
  });
  assert.equal(selectLatestRelease([later, earlier]), later);
  assert.equal(selectLatestRelease([earlier, later]), later);

  const idOne = release('v1.0.0+same', { id: 1 });
  const idTwo = release('v1.0.0+same', { id: 2 });
  assert.equal(selectLatestRelease([idTwo, idOne]), idTwo);
  assert.equal(selectLatestRelease([idOne, idTwo]), idTwo);
  assert.deepEqual(selectLatestRelease([idOne, { ...idOne }]), idOne);

  const bareRelease = {
    tag_name: 'v1.0.0+bare',
    draft: false,
    prerelease: false,
  };
  assert.deepEqual(
    selectLatestRelease([bareRelease, { ...bareRelease }]),
    bareRelease,
  );
});

test('returns null when no stable or prerelease release exists', () => {
  assert.deepEqual(selectLatestReleases([]), {
    stable: null,
    prerelease: null,
  });
  assert.equal(selectLatestRelease(null), null);
});

test('fetches releases from the Lumen repository with the GitHub media type', async () => {
  const expected = [release('v1.0.0')];
  const calls = [];
  const actual = await fetchLumenReleases(async (...args) => {
    calls.push(args);
    return {
      ok: true,
      async json() {
        return expected;
      },
    };
  });

  assert.equal(actual, expected);
  assert.equal(calls[0][0], LUMEN_RELEASES_API_URL);
  assert.equal(calls[0][1].headers.Accept, 'application/vnd.github+json');
});

test('uses the global fetch implementation by default', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    async json() {
      return [];
    },
  });
  try {
    assert.deepEqual(await fetchLumenReleases(), []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('reports HTTP and malformed API responses', async () => {
  await assert.rejects(
    fetchLumenReleases(async () => ({ ok: false, status: 503 })),
    /HTTP 503/,
  );
  await assert.rejects(
    fetchLumenReleases(async () => ({
      ok: true,
      async json() {
        return { message: 'rate limited' };
      },
    })),
    /not an array/,
  );
});

test('escapes remote release notes as plain text', () => {
  assert.equal(
    formatReleaseNotesAsHtml(
      '<img src=x onerror="alert(1)">\r\n[click](javascript:alert(1)) & \'quoted\'',
    ),
    '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;<br>' +
      '[click](javascript:alert(1)) &amp; &#39;quoted&#39;',
  );
  assert.equal(formatReleaseNotesAsHtml('one\rtwo'), 'one<br>two');
  assert.equal(formatReleaseNotesAsHtml(''), '');
  assert.equal(formatReleaseNotesAsHtml(null), '');
  assert.doesNotMatch(indexSource, /marked\.parse|convertMarkdownToHtml/);
  assert.match(indexSource, /formatReleaseNotesAsHtml\(githubVersion\.release\.body\)/);
});

test('keeps update-check failure distinct from the latest-version state', () => {
  assert.match(indexSource, /updateCheckFailed: false/);
  assert.match(indexSource, /this\.updateCheckFailed = true/);
  assert.match(indexSource, /v-if="updateCheckFailed && !loading"/);
  assert.match(indexSource, /v-else-if="githubVersion &&/);
});

test('only trusts repository-scoped HTTPS release URLs', () => {
  assert.equal(
    isTrustedLumenReleaseUrl(`${LUMEN_RELEASES_URL}/tag/v1.2.3`),
    true,
  );
  assert.equal(
    isTrustedLumenReleaseUrl(
      `${LUMEN_RELEASES_URL}/download/v1.2.3/Lumen-1.2.3-Windows-installer.msi`,
      { download: true },
    ),
    true,
  );

  const rejectedUrls = [
    'http://github.com/simonfalke-01/Lumen/releases/tag/v1.2.3',
    'https://github.com.evil.test/simonfalke-01/Lumen/releases/tag/v1.2.3',
    'https://github.com/LizardByte/Sunshine/releases/tag/v1.2.3',
    'https://user@github.com/simonfalke-01/Lumen/releases/tag/v1.2.3',
    'https://github.com:444/simonfalke-01/Lumen/releases/tag/v1.2.3',
    'not a URL',
    null,
  ];
  for (const url of rejectedUrls) {
    assert.equal(isTrustedLumenReleaseUrl(url), false, String(url));
  }
  assert.equal(
    isTrustedLumenReleaseUrl(`${LUMEN_RELEASES_URL}/tag/v1.2.3`, {
      download: true,
    }),
    false,
  );
});

test('chooses the matching versioned Windows MSI deterministically', () => {
  const currentRelease = release('v2.4.0-rc.1', {
    prerelease: true,
    assets: [
      {
        name: 'Lumen-2.4.0-rc.1-Windows-AMD64-installer.exe',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/installer.exe`,
      },
      {
        name: 'Lumen-2.3.0-Windows-AMD64-installer.msi',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.3.0/old.msi`,
      },
      {
        name: 'Lumen-2.4.0-rc.1-Windows-AMD64-installer.msi',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/installer.msi`,
      },
      {
        name: 'Lumen-Windows-AMD64-installer.msi',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/unversioned.msi`,
      },
      {
        name: 'Lumen-2.4.0-rc.1-Windows-ARM64-installer.msi',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/arm64.msi`,
      },
      {
        name: 'Lumen-2.4.0-rc.1-Windows-x86-installer.msi',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/x86.msi`,
      },
      {
        name: 'Lumen-2.4.0-rc.1-Linux-AMD64-installer.msi',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/linux.msi`,
      },
      {
        name: 'Lumen-2.4.0-rc.1-Windows-AMD64-lite.zip',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/lite.zip`,
      },
      {
        name: 'Lumen-v2.4.0-rc.1-Windows-AMD64-installer.msi',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/v-prefixed.msi`,
      },
      {
        name: 'Lumen-2.4.0-rc.1-Windows-AMD64-portable.exe',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/portable.exe`,
      },
      {
        name: 'Lumen-2.4.0-rc.1-Windows-AMD64-installer.msi',
      },
      null,
    ],
  });

  assert.equal(
    selectWindowsInstallerAsset(currentRelease).browser_download_url,
    `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/installer.msi`,
  );
  assert.equal(
    getReleaseDownloadUrl(currentRelease, 'windows'),
    `${LUMEN_RELEASES_URL}/download/v2.4.0-rc.1/installer.msi`,
  );

  const executableRelease = release('v2.4.0', {
    assets: [
      {
        name: 'Lumen-2.4.0-Windows-AMD64-installer.exe',
        browser_download_url: `${LUMEN_RELEASES_URL}/download/v2.4.0/installer.exe`,
      },
    ],
  });
  assert.equal(selectWindowsInstallerAsset(executableRelease), null);
});

test('falls back to a trusted release page instead of guessing installers', () => {
  const currentRelease = release('v1.2.3', {
    html_url: `${LUMEN_RELEASES_URL}/tag/v1.2.3`,
    assets: [{
      name: 'Lumen-Windows-AMD64-installer.msi',
      browser_download_url: `${LUMEN_RELEASES_URL}/download/v1.2.3/unversioned.msi`,
    }],
  });

  assert.equal(
    getReleaseDownloadUrl(currentRelease, 'windows'),
    `${LUMEN_RELEASES_URL}/tag/v1.2.3`,
  );
  assert.equal(
    getReleaseDownloadUrl(currentRelease, 'linux'),
    `${LUMEN_RELEASES_URL}/tag/v1.2.3`,
  );
  assert.equal(selectWindowsInstallerAsset(null), null);
  assert.equal(selectWindowsInstallerAsset(release('v1.2.3')), null);
  assert.equal(
    getReleaseDownloadUrl(null, 'linux'),
    LUMEN_RELEASES_URL,
  );
});

test('rejects foreign release pages and download assets', () => {
  const foreignRelease = release('v3.2.1', {
    html_url: 'https://evil.test/releases/v3.2.1',
    assets: [{
      name: 'Lumen-v3.2.1-Windows-AMD64-installer.msi',
      browser_download_url: 'https://evil.test/Lumen-v3.2.1-installer.msi',
    }],
  });

  assert.equal(selectWindowsInstallerAsset(foreignRelease), null);
  assert.equal(
    getReleaseDownloadUrl(foreignRelease, 'windows'),
    `${LUMEN_RELEASES_URL}/tag/v3.2.1`,
  );
});
