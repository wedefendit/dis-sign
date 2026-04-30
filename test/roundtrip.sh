#!/usr/bin/env bash
# Copyright (c) 2026 Defend I.T. Solutions
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Round-trip test: sign a fixture repo, verify it, mutate a file,
# verify again and expect failure. Tests both explicit categories
# and git auto-tracking modes.

set -Eeuo pipefail

cd "$(dirname "$0")"
SCRIPT_DIR=$(pwd)
DIS_SIGN="${SCRIPT_DIR}/../bin/dis-sign"
DIS_VERIFY="${SCRIPT_DIR}/../bin/dis-verify"

for bin in "$DIS_SIGN" "$DIS_VERIFY"; do
  [[ -x "$bin" ]] || { echo "missing or non-executable: $bin" >&2; exit 1; }
done

for bin in jq sha256sum gpg git; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
echo "test: workdir=$WORK"

GPG_HOME="${WORK}/gnupg"
mkdir -p "$GPG_HOME"
chmod 700 "$GPG_HOME"

cat > "${WORK}/keygen.batch" <<EOF
%no-protection
Key-Type: EDDSA
Key-Curve: ed25519
Name-Real: dis-sign test key
Name-Email: test@dis-sign.invalid
Expire-Date: 0
%commit
EOF

gpg --homedir "$GPG_HOME" --batch --gen-key "${WORK}/keygen.batch" 2>/dev/null
KEY_FPR=$(gpg --homedir "$GPG_HOME" --list-secret-keys --with-colons \
  | awk -F: '/^fpr:/ {print $10; exit}')
echo "test: generated key $KEY_FPR"

cat > "${WORK}/other-keygen.batch" <<EOF
%no-protection
Key-Type: EDDSA
Key-Curve: ed25519
Name-Real: dis-sign other test key
Name-Email: other@dis-sign.invalid
Expire-Date: 0
%commit
EOF

gpg --homedir "$GPG_HOME" --batch --gen-key "${WORK}/other-keygen.batch" 2>/dev/null
OTHER_FPR=$(gpg --homedir "$GPG_HOME" --list-secret-keys --with-colons other@dis-sign.invalid \
  | awk -F: '/^fpr:/ {print $10; exit}')
echo "test: generated other key $OTHER_FPR"

rewrite_manifest_fingerprint() {
  local manifest="$1"
  local fpr="$2"
  local body
  local hash

  body=$(jq --arg f "$fpr" '.signing_key_fingerprint = $f | .manifest_hash = ""' "$manifest")
  hash=$(jq -S . <<<"$body" | sha256sum | awk '{print $1}')
  jq --arg h "sha256:$hash" '.manifest_hash = $h' <<<"$body" > "${manifest}.tmp"
  mv "${manifest}.tmp" "$manifest"
}

# ── Test 1: explicit categories ──
echo ""
echo "=== Test 1: explicit categories ==="

REPO1="${WORK}/repo-categories"
mkdir -p "${REPO1}/src/bin" "${REPO1}/conf" "${REPO1}/signing"
echo '#!/bin/sh' > "${REPO1}/src/bin/hello"
echo 'echo hello' >> "${REPO1}/src/bin/hello"
chmod +x "${REPO1}/src/bin/hello"
echo 'foo=bar' > "${REPO1}/conf/app.conf"

gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > "${REPO1}/signing/test-public.gpg.asc"

cat > "${REPO1}/dis-sign.conf" <<EOF
APP_NAME=testapp
SIGNING_KEY=${KEY_FPR}
CATEGORIES=(
  "bin:src/bin/*"
  "conf:conf/*"
  "signing:signing/*.gpg.asc"
)
EOF

echo "test1: signing"
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO1}/dis-sign.conf"

echo "test1: verifying (expect OK)"
( cd "$REPO1" && "$DIS_VERIFY" ) || { echo "FAIL: clean verify failed"; exit 1; }

echo "test1: verifying with trusted fingerprint (expect OK)"
( cd "$REPO1" && "$DIS_VERIFY" --trusted-fingerprint "$KEY_FPR" ) || {
  echo "FAIL: trusted fingerprint verify failed"
  exit 1
}

echo "test1: verifying with trusted fingerprint env (expect OK)"
( cd "$REPO1" && DIS_VERIFY_TRUSTED_FINGERPRINT="$KEY_FPR" "$DIS_VERIFY" ) || {
  echo "FAIL: trusted fingerprint env verify failed"
  exit 1
}

echo "test1: verifying with different trusted fingerprint (expect FAIL with exit 1)"
set +e
( cd "$REPO1" && "$DIS_VERIFY" --trusted-fingerprint "$OTHER_FPR" )
rc=$?
set -e
if [[ $rc -ne 1 ]]; then
  echo "FAIL: expected exit 1 (trusted fingerprint mismatch), got $rc"
  exit 1
fi

echo "test1: signer must match manifest fingerprint (expect FAIL with exit 1)"
cp "${REPO1}/signing/testapp-manifest.json" "${REPO1}/signing/testapp-manifest.json.good"
cp "${REPO1}/signing/testapp-manifest.json.asc" "${REPO1}/signing/testapp-manifest.json.asc.good"
rewrite_manifest_fingerprint "${REPO1}/signing/testapp-manifest.json" "$OTHER_FPR"
gpg --homedir "$GPG_HOME" \
  --local-user "$KEY_FPR" \
  --detach-sign --armor --yes \
  --output "${REPO1}/signing/testapp-manifest.json.asc" \
  "${REPO1}/signing/testapp-manifest.json" 2>/dev/null
set +e
( cd "$REPO1" && "$DIS_VERIFY" )
rc=$?
set -e
if [[ $rc -ne 1 ]]; then
  echo "FAIL: expected exit 1 (signer fingerprint mismatch), got $rc"
  exit 1
fi
mv "${REPO1}/signing/testapp-manifest.json.good" "${REPO1}/signing/testapp-manifest.json"
mv "${REPO1}/signing/testapp-manifest.json.asc.good" "${REPO1}/signing/testapp-manifest.json.asc"

echo "test1: broad category excludes generated manifest/signature"
cat > "${REPO1}/dis-sign.conf" <<EOF
APP_NAME=testapp
SIGNING_KEY=${KEY_FPR}
CATEGORIES=(
  "all:**"
)
EOF
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO1}/dis-sign.conf"
if jq -e '.artifacts.all["signing/testapp-manifest.json"] or .artifacts.all["signing/testapp-manifest.json.asc"]' \
  "${REPO1}/signing/testapp-manifest.json" >/dev/null; then
  echo "FAIL: generated manifest/signature should be excluded"
  exit 1
fi
( cd "$REPO1" && "$DIS_VERIFY" ) || { echo "FAIL: broad category verify failed"; exit 1; }

echo "test1: relative manifest from outside repo (expect OK)"
( cd "$WORK" && "$DIS_VERIFY" --manifest "repo-categories/signing/testapp-manifest.json" ) || {
  echo "FAIL: relative manifest verify failed"
  exit 1
}

echo "test1: tampering with src/bin/hello"
echo 'rm -rf /' >> "${REPO1}/src/bin/hello"

echo "test1: verifying (expect FAIL with exit 2)"
set +e
( cd "$REPO1" && "$DIS_VERIFY" )
rc=$?
set -e
if [[ $rc -ne 2 ]]; then
  echo "FAIL: expected exit 2 (artifact mismatch), got $rc"
  exit 1
fi

echo "test1: PASS"

echo ""
echo "=== Test 1b: duplicate explicit category entries ==="

REPO_DUP="${WORK}/repo-duplicate"
mkdir -p "${REPO_DUP}/src" "${REPO_DUP}/signing"
echo 'duplicate me' > "${REPO_DUP}/src/shared.txt"
gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > "${REPO_DUP}/signing/test-public.gpg.asc"

cat > "${REPO_DUP}/dis-sign.conf" <<EOF
APP_NAME=testapp-duplicate
SIGNING_KEY=${KEY_FPR}
CATEGORIES=(
  "one:src/shared.txt"
  "two:src/*.txt"
)
EOF

echo "test1b: signing duplicate category config (expect FAIL)"
set +e
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO_DUP}/dis-sign.conf"
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "FAIL: expected duplicate category signing to fail"
  exit 1
fi
echo "test1b: PASS"

# ── Test 2: git auto-tracking (no categories) ──
echo ""
echo "=== Test 2: git auto-tracking ==="

REPO2="${WORK}/repo-git"
mkdir -p "${REPO2}/src" "${REPO2}/signing"

cd "$REPO2"
git init -q
git config user.email "test@dis-sign.invalid"
git config user.name "test"

echo '#!/bin/sh' > src/app.sh
echo 'key=val' > src/config.txt

gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > signing/test-public.gpg.asc

cat > dis-sign.conf <<EOF
APP_NAME=testapp-git
SIGNING_KEY=${KEY_FPR}
EOF

git add -A
git commit -q -m "init"

echo "test2: signing (no categories, git ls-files mode)"
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO2}/dis-sign.conf"

echo "test2: checking manifest uses 'all' category"
category=$(jq -r '.artifacts | keys[]' signing/testapp-git-manifest.json)
if [[ "$category" != "all" ]]; then
  echo "FAIL: expected 'all' category, got '$category'"
  exit 1
fi

file_count=$(jq -r '.artifact_count' signing/testapp-git-manifest.json)
echo "test2: manifest has $file_count files"

echo "test2: verifying (expect OK)"
"$DIS_VERIFY" || { echo "FAIL: clean verify failed"; exit 1; }

echo "test2: tampering with src/app.sh"
echo 'echo pwned' >> src/app.sh

echo "test2: verifying (expect FAIL with exit 2)"
set +e
"$DIS_VERIFY"
rc=$?
set -e
if [[ $rc -ne 2 ]]; then
  echo "FAIL: expected exit 2, got $rc"
  exit 1
fi

echo "test2: PASS"

# ── Test 3: IGNORE globs ──
echo ""
echo "=== Test 3: IGNORE globs ==="

REPO3="${WORK}/repo-ignore"
mkdir -p "${REPO3}/src" "${REPO3}/test/playwright" "${REPO3}/vendor" "${REPO3}/signing"

echo 'keep' > "${REPO3}/src/app.sh"
echo 'also keep' > "${REPO3}/src/config.txt"
echo 'playwright fixture' > "${REPO3}/test/playwright/e2e.spec.ts"
echo 'vendored' > "${REPO3}/vendor/lib.js"
echo 'snapshot' > "${REPO3}/src/app.snapshot"

gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > "${REPO3}/signing/test-public.gpg.asc"

cat > "${REPO3}/dis-sign.conf" <<EOF
APP_NAME=testapp-ignore
SIGNING_KEY=${KEY_FPR}
CATEGORIES=(
  "src:src/**"
  "test:test/**"
  "vendor:vendor/**"
  "signing:signing/*.gpg.asc"
)
IGNORE=(
  "test/playwright/**"
  "**/*.snapshot"
  "vendor/**"
)
EOF

echo "test3: signing"
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO3}/dis-sign.conf"

MANIFEST3="${REPO3}/signing/testapp-ignore-manifest.json"

echo "test3: checking ignored paths are absent"
for bad in "test/playwright/e2e.spec.ts" "src/app.snapshot" "vendor/lib.js"; do
  if jq -e --arg p "$bad" '[.. | objects | keys[]?] | any(. == $p)' "$MANIFEST3" >/dev/null; then
    echo "FAIL: ignored path leaked into manifest: $bad"
    exit 1
  fi
done

echo "test3: checking kept paths are present"
for good in "src/app.sh" "src/config.txt"; do
  if ! jq -e --arg p "$good" '[.. | objects | keys[]?] | any(. == $p)' "$MANIFEST3" >/dev/null; then
    echo "FAIL: expected path missing from manifest: $good"
    exit 1
  fi
done

echo "test3: checking wholly-ignored categories are omitted"
for cat in "test" "vendor"; do
  if jq -e --arg c "$cat" '.artifacts | has($c)' "$MANIFEST3" >/dev/null; then
    echo "FAIL: category '$cat' should be omitted (all files ignored)"
    exit 1
  fi
done

echo "test3: verifying (expect OK)"
( cd "$REPO3" && "$DIS_VERIFY" ) || { echo "FAIL: clean verify failed"; exit 1; }

echo "test3: PASS"

# ── Test 4: IGNORE in git ls-files mode ──
echo ""
echo "=== Test 4: IGNORE in git ls-files mode ==="

REPO4="${WORK}/repo-ignore-git"
mkdir -p "${REPO4}/src" "${REPO4}/test/playwright" "${REPO4}/signing"

cd "$REPO4"
git init -q
git config user.email "test@dis-sign.invalid"
git config user.name "test"

echo 'keep' > src/app.sh
echo 'playwright fixture' > test/playwright/e2e.spec.ts

gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > signing/test-public.gpg.asc

cat > dis-sign.conf <<EOF
APP_NAME=testapp-ignore-git
SIGNING_KEY=${KEY_FPR}
IGNORE=(
  "test/playwright/**"
)
EOF

git add -A
git commit -q -m "init"

echo "test4: signing"
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO4}/dis-sign.conf"

echo "test4: checking ignored path is absent"
if jq -e '.artifacts.all["test/playwright/e2e.spec.ts"]' signing/testapp-ignore-git-manifest.json >/dev/null; then
  echo "FAIL: ignored path leaked into git ls-files manifest"
  exit 1
fi

echo "test4: checking kept path is present"
if ! jq -e '.artifacts.all["src/app.sh"]' signing/testapp-ignore-git-manifest.json >/dev/null; then
  echo "FAIL: expected path missing from git ls-files manifest"
  exit 1
fi

echo "test4: verifying (expect OK)"
"$DIS_VERIFY" || { echo "FAIL: clean verify failed"; exit 1; }

echo "test4: PASS"

# -- Test 5: IGNORE uses pathname glob semantics --
echo ""
echo "=== Test 5: IGNORE pathname glob semantics ==="

REPO5="${WORK}/repo-ignore-path-globs"
mkdir -p "${REPO5}/src" "${REPO5}/test/nested" "${REPO5}/signing"

echo 'nested test should stay' > "${REPO5}/test/nested/keep.txt"
echo 'direct test should go' > "${REPO5}/test/direct.txt"
echo 'nested snapshot should stay' > "${REPO5}/src/app.snapshot"
echo 'root snapshot should go' > "${REPO5}/root.snapshot"

gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > "${REPO5}/signing/test-public.gpg.asc"

cat > "${REPO5}/dis-sign.conf" <<EOF
APP_NAME=testapp-path-globs
SIGNING_KEY=${KEY_FPR}
CATEGORIES=(
  "all:**"
)
IGNORE=(
  "test/*"
  "*.snapshot"
)
EOF

echo "test5: signing"
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO5}/dis-sign.conf"

MANIFEST5="${REPO5}/signing/testapp-path-globs-manifest.json"

echo "test5: checking direct path glob matches are absent"
for bad in "test/direct.txt" "root.snapshot"; do
  if jq -e --arg p "$bad" '[.. | objects | keys[]?] | any(. == $p)' "$MANIFEST5" >/dev/null; then
    echo "FAIL: ignored path leaked into manifest: $bad"
    exit 1
  fi
done

echo "test5: checking star does not cross directories"
for good in "test/nested/keep.txt" "src/app.snapshot"; do
  if ! jq -e --arg p "$good" '[.. | objects | keys[]?] | any(. == $p)' "$MANIFEST5" >/dev/null; then
    echo "FAIL: pathname glob overmatched and removed: $good"
    exit 1
  fi
done

echo "test5: verifying (expect OK)"
( cd "$REPO5" && "$DIS_VERIFY" ) || { echo "FAIL: clean verify failed"; exit 1; }

echo "test5: PASS"

# -- Test 6: all ignored files must not produce an empty signed manifest --
echo ""
echo "=== Test 6: empty manifest rejected ==="

REPO6="${WORK}/repo-empty-manifest"
mkdir -p "${REPO6}/src" "${REPO6}/signing"
echo 'ignore me' > "${REPO6}/src/app.sh"
gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > "${REPO6}/signing/test-public.gpg.asc"

cat > "${REPO6}/dis-sign.conf" <<EOF
APP_NAME=testapp-empty
SIGNING_KEY=${KEY_FPR}
CATEGORIES=(
  "all:src/**"
)
IGNORE=(
  "src/**"
)
EOF

echo "test6: signing empty manifest config (expect FAIL)"
set +e
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO6}/dis-sign.conf"
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "FAIL: expected empty manifest signing to fail"
  exit 1
fi
if [[ -e "${REPO6}/signing/testapp-empty-manifest.json" ]]; then
  echo "FAIL: empty manifest should not be written"
  exit 1
fi

echo "test6: PASS"

# -- Test 7: config parser must not execute shell --
echo ""
echo "=== Test 7: config parser rejects shell syntax ==="

REPO7="${WORK}/repo-config-safe"
PWNED="${WORK}/config-pwned"
mkdir -p "${REPO7}/src" "${REPO7}/signing"
echo 'keep' > "${REPO7}/src/app.sh"
gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > "${REPO7}/signing/test-public.gpg.asc"

cat > "${REPO7}/dis-sign.conf" <<EOF
APP_NAME=testapp-config-safe
SIGNING_KEY=${KEY_FPR}
touch "${PWNED}"
CATEGORIES=(
  "all:src/**"
)
EOF

echo "test7: signing config with shell command (expect FAIL, no execution)"
set +e
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO7}/dis-sign.conf"
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "FAIL: expected unsupported config syntax to fail"
  exit 1
fi
if [[ -e "$PWNED" ]]; then
  echo "FAIL: config shell command was executed"
  exit 1
fi

echo "test7: PASS"

# -- Test 8: git mode excludes generated manifest/signature by normalized path --
echo ""
echo "=== Test 8: git mode normalized output exclusion ==="

REPO8="${WORK}/repo-git-out"
mkdir -p "${REPO8}/src" "${REPO8}/signing"

cd "$REPO8"
git init -q
git config user.email "test@dis-sign.invalid"
git config user.name "test"

echo 'keep' > src/app.sh
echo '{"old":true}' > signing/testapp-out-manifest.json
echo 'old signature placeholder' > signing/testapp-out-manifest.json.asc
gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > signing/test-public.gpg.asc

cat > dis-sign.conf <<EOF
APP_NAME=testapp-out
SIGNING_KEY=${KEY_FPR}
EOF

git add -A
git commit -q -m "init"

echo "test8: signing with ./ --out path"
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" \
  --config "${REPO8}/dis-sign.conf" \
  --out "./signing/testapp-out-manifest.json"

if jq -e '.artifacts.all["signing/testapp-out-manifest.json"] or .artifacts.all["signing/testapp-out-manifest.json.asc"]' \
  signing/testapp-out-manifest.json >/dev/null; then
  echo "FAIL: generated manifest/signature should be excluded in git mode"
  exit 1
fi

echo "test8: verifying (expect OK)"
"$DIS_VERIFY" --manifest signing/testapp-out-manifest.json || { echo "FAIL: clean verify failed"; exit 1; }

echo "test8: PASS"

# -- Test 9: globs must not escape the repo --
echo ""
echo "=== Test 9: repo escape glob rejected ==="

REPO9="${WORK}/repo-escape"
mkdir -p "${REPO9}/src" "${REPO9}/signing"
echo 'keep' > "${REPO9}/src/app.sh"
gpg --homedir "$GPG_HOME" --armor --export "$KEY_FPR" \
  > "${REPO9}/signing/test-public.gpg.asc"

cat > "${REPO9}/dis-sign.conf" <<EOF
APP_NAME=testapp-escape
SIGNING_KEY=${KEY_FPR}
CATEGORIES=(
  "leak:../*"
)
EOF

echo "test9: signing repo escape config (expect FAIL)"
set +e
DIS_SIGN_GPG_HOME="$GPG_HOME" "$DIS_SIGN" --config "${REPO9}/dis-sign.conf"
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "FAIL: expected repo escape glob to fail"
  exit 1
fi

echo "test9: PASS"

# ── Test 10: GPG_HOME from config with tilde expansion ──
echo ""
echo "=== Test 10: GPG_HOME from config (tilde expanded) ==="

FAKE_HOME="${WORK}/fake-home"
mkdir -p "${FAKE_HOME}/.gnupg-test"
chmod 700 "${FAKE_HOME}/.gnupg-test"
cp -a "${GPG_HOME}/." "${FAKE_HOME}/.gnupg-test/"
chmod 700 "${FAKE_HOME}/.gnupg-test"

REPO10="${WORK}/repo-gpghome"
mkdir -p "${REPO10}/src" "${REPO10}/signing"

echo 'keep' > "${REPO10}/src/app.sh"
gpg --homedir "${FAKE_HOME}/.gnupg-test" --armor --export "$KEY_FPR" \
  > "${REPO10}/signing/test-public.gpg.asc"

cat > "${REPO10}/dis-sign.conf" <<EOF
APP_NAME=testapp-gpghome
SIGNING_KEY=${KEY_FPR}
GPG_HOME=~/.gnupg-test
CATEGORIES=(
  "src:src/**"
  "signing:signing/*.gpg.asc"
)
EOF

echo "test10: signing with HOME=$FAKE_HOME, no DIS_SIGN_GPG_HOME env"
unset DIS_SIGN_GPG_HOME
HOME="$FAKE_HOME" "$DIS_SIGN" --config "${REPO10}/dis-sign.conf"

echo "test10: verifying (expect OK)"
( cd "$REPO10" && HOME="$FAKE_HOME" "$DIS_VERIFY" ) || {
  echo "FAIL: verify failed after signing via config GPG_HOME"
  exit 1
}

echo "test10: env DIS_SIGN_GPG_HOME must override config"
sed -i 's|^GPG_HOME=.*|GPG_HOME=~/.does-not-exist|' "${REPO10}/dis-sign.conf"
HOME="$FAKE_HOME" DIS_SIGN_GPG_HOME="${FAKE_HOME}/.gnupg-test" \
  "$DIS_SIGN" --config "${REPO10}/dis-sign.conf" \
  || { echo "FAIL: env override didn't take"; exit 1; }

echo "test10: PASS"

echo ""
echo "=== All tests passed ==="
