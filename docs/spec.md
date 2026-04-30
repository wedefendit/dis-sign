# dis-sign manifest spec

## Manifest format

```json
{
  "version": 1,
  "tool": "dis-sign/0.1.0",
  "app": "<APP_NAME>",
  "generated_at": "2026-04-23T12:34:56Z",
  "signing_key_fingerprint": "<full GPG fingerprint, no spaces>",
  "artifacts": {
    "<category>": {
      "<repo-relative path>": "sha256:<hex>",
      ...
    },
    ...
  },
  "artifact_count": <int>,
  "manifest_hash": "sha256:<hex>"
}
```

## Rules

- Keys are sorted (`jq -S`) before write so output is byte-stable.
- `manifest_hash` is computed over the manifest with `manifest_hash` set
  to `""` (empty string), then written into the field.
- All paths are repo-relative, forward-slash, no leading `./`.
- One file may appear in only one category.
- A category with no matching files is omitted.

## Categories

Categories are optional.

`dis-sign.conf` is parsed as a constrained config file, not sourced as
shell. Supported top-level keys are `APP_NAME`, `SIGNING_KEY`,
`CATEGORIES`, and `IGNORE`; any other syntax is rejected.

When `CATEGORIES` is defined in `dis-sign.conf`, files are grouped by
the categories you specify. Each category is a name and one or more
shell globs. Only files matching the globs are included.

When `CATEGORIES` is unset or empty, `dis-sign` falls back to
`git ls-files` and includes every tracked file under a single `"all"`
category. This is zero-maintenance — any file added to git is
automatically in the manifest.

Use explicit categories when you want to verify subsets independently
(e.g. "just the install scripts" or "just the configs"). Use git
auto-tracking when you just want everything covered.

## Ignore globs

`IGNORE` in `dis-sign.conf` is an optional array of bash globs applied
*after* file selection in both modes. Any file matching any `IGNORE`
glob is dropped before hashing.

```bash
IGNORE=(
  "test/playwright/**"
  "**/*.snapshot"
  "vendor/**"
)
```

Globs are native bash path globs with `globstar` on — `**` matches
across directories, `*` does not. Matches are against repo-relative paths
(no leading `./`) and must not point outside the repo. A category whose
files are all ignored is omitted from the manifest. If no files remain,
signing fails instead of producing an empty manifest.

## Signing

A detached, ASCII-armored GPG signature is written next to the manifest
as `<manifest>.asc`. Verification recomputes `manifest_hash` and every
artifact hash before reporting OK.

Verification also checks that the actual signature signer fingerprint
matches `signing_key_fingerprint`. When a deployment needs a pinned trust
root, callers should pass `--trusted-fingerprint` or set
`DIS_VERIFY_TRUSTED_FINGERPRINT`; this makes verification reject any
manifest signed by a different key.

## Why this shape

- **Self-hashing** — prevents tampering with the artifact index without
  re-signing.
- **Categories** — let consumers verify subsets without parsing globs.
- **Stable JSON** — sorted keys + UTC timestamp makes diffs meaningful.
- **Detached signature** — verifier doesn't have to mutate the manifest.

## What this is not

- Not a transport format. It describes what's in a repo at a point in
  time. Distribution is up to you.
- Not a substitute for `cosign`/`sigstore` if you need transparency-log
  backed signatures.
- Not a build system. It hashes what exists; it does not build.

## Copyright (c) 2026 Defend I.T. Solutions. MIT License.
