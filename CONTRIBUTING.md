# Development and validation

This is a static, browser-only Vite application. Use Node.js 24 LTS and install the locked dependency tree:

```sh
npm ci
npm run dev
```

## Required checks

```sh
npm run typecheck
npm test
npm run build
```

Install Playwright's three browser engines once, then run the browser suite:

```sh
npx playwright install --with-deps chromium firefox webkit
npm run test:e2e
```

The E2E command builds and serves the production assets with the production security headers. It includes private-input network-egress checks, pack-free challenge flows, runtime-pack caching and offline execution checks. The seven WebKit offline-pack execution checks are currently skipped because of the documented Playwright offline reload issue; a passing suite does not establish WebKit offline support.

GitHub Actions runs install, typecheck, unit tests and build on Windows and Linux using Node 24. A separate Linux job runs all three browser projects and uploads the HTML report and test results. Hosted CI results must be checked on the pull request; a local run does not verify the hosted environment.

## Fixture integrity

`src/formats/testing/` and `corpus/` contain byte-sensitive fixtures protected by `.gitattributes`. Do not normalize their line endings, reformat their contents or change expected hashes merely to make a test pass. Preserve original bytes and retain provenance and licensing records.

For a checkout created before these attributes were added, existing files may still have been converted by `core.autocrlf`. Use a fresh clone when possible. Investigate differences against the committed bytes before replacing any existing file; do not overwrite local work.

New regression fixtures should include an independently verifiable source and licence, expected intermediate results and explicit format or compute limits. Generated conformance vectors are useful but do not replace real challenge acceptance evidence.

## Acceptance status

See `design.md` for the architecture and milestone gates, and `M6-status.md` for the current baseline and remaining gaps. Passing tests are not a declaration that every format variant or milestone is complete.
