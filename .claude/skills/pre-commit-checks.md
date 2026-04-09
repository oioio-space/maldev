---
name: pre-commit-checks
description: >
  Trigger: before git commit, before git push, when user says "commit" or "push".
  Purpose: verify build passes, tests pass, doc.go exists for new technique
  packages, no credentials leaked (gho_*, ghp_*, sk-*, AKIA*), ignore/ not
  staged, naming conventions followed, README links valid.
  Keywords: commit, push, pre-commit, credential scan, ignore folder, go build.
---

# Pre-Commit & Pre-Push Checks

Run this checklist BEFORE every `git commit` and `git push`. Block the operation and fix issues if any check fails.

## 1. Build Verification

```bash
go build $(go list ./... | grep -v ignore)
```

If this fails, DO NOT commit. Fix compilation errors first.

## 2. Test Verification

```bash
go test $(go list ./... | grep -v ignore) -count=1 -timeout 120s
```

- All packages must PASS (0 FAIL)
- SKIP is acceptable (intrusive/manual tests)
- If any test fails, DO NOT commit. Fix the test first.

## 3. Documentation Checks

### 3a. New technique packages MUST have doc.go with:
- [ ] Technique name
- [ ] MITRE ATT&CK ID (or N/A for utility packages)
- [ ] Detection level (Low / Medium / High)
- [ ] Platform (Windows / Linux / Cross-platform)
- [ ] "How it works" explanation (3-5 sentences minimum)
- [ ] At least one usage example in the doc comment

### 3b. Every exported function MUST have a doc comment explaining:
- What it does
- What each parameter means
- What it returns

### 3c. If a NEW package was created:
- [ ] Added to the Packages table in README.md with link to docs page
- [ ] Added to the relevant docs/ page (evasion.md, injection.md, etc.)
- [ ] Added to docs/mitre.md if it implements a MITRE technique
- [ ] MITRE ID is consistent across README table, docs page, and doc.go

### 3d. If an EXISTING function signature changed:
- [ ] Updated all docs/ pages that reference this function
- [ ] Updated README.md examples if affected

## 4. Credential & Secret Scan

Scan ALL staged files for potential credential leaks:

```bash
git diff --cached --name-only | xargs grep -l -i \
  -e "password" -e "secret" -e "token" -e "api.key" -e "private.key" \
  -e "gho_" -e "ghp_" -e "sk-" -e "AKIA" -e "BEGIN RSA" -e "BEGIN PRIVATE" \
  2>/dev/null
```

### Rules:
- `gho_*`, `ghp_*` — GitHub tokens. NEVER commit.
- `sk-*` — API keys. NEVER commit.
- `AKIA*` — AWS access keys. NEVER commit.
- `BEGIN RSA PRIVATE KEY` / `BEGIN PRIVATE KEY` — Private keys. NEVER commit.
- `password` in Go source — check if it's a variable name (OK) or a hardcoded value (BLOCK).
- `.env` files — NEVER commit.
- `credentials.json`, `token.json` — NEVER commit.

If any real credential is found, BLOCK the commit and alert the user.

**Exceptions** (not actual credentials):
- Test files with dummy values (`"P@ssw0rd123!"` in test helpers)
- Documentation examples with placeholder values
- Variable names containing "password" or "token" as identifiers

## 5. Naming Convention Check

Spot-check staged Go files for violations:

- [ ] No stuttering (package name repeated in symbol: `token.NewToken` → `token.New`)
- [ ] No `Get` prefix on getters (`GetVersion` → `Current`)
- [ ] No `SCREAMING_CASE` for project-invented constants (Windows SDK constants are exempt)
- [ ] Acronyms consistently cased: `ID` not `Id`, `HTTP` not `Http`

## 6. ignore/ Safety Check

```bash
git diff --cached --name-only | grep "^ignore/"
```

If ANY file in `ignore/` is staged: **BLOCK the commit**. The `ignore/` folder must NEVER be committed. Verify with:
```bash
git check-ignore -v ignore/
```

## 7. Version & Tag Check (pre-push only)

When pushing, verify:

### 7a. go.mod version
- `go.mod` declares `go 1.21` or higher
- No `replace` directives (single module, no workspace)

### 7b. If this is a release push (tag push):
- Tag follows SEMVER: `v{MAJOR}.{MINOR}.{PATCH}`
- Tag message describes changes
- CHANGELOG or tag annotation is present

### 7c. GitHub repo metadata
After pushing, verify (if credentials available):
- Description is set and accurate
- Topics/tags are present
- Homepage points to pkg.go.dev

## 8. README Consistency

- [ ] Documentation table links all work (no broken relative paths)
- [ ] Package table has MITRE column filled for all technique packages
- [ ] Every package in the table links to its docs/ page
- [ ] Acknowledgments section is present
- [ ] License section is present

## Execution Order

1. Build → 2. Tests → 3. Docs → 4. Credentials → 5. Naming → 6. ignore/ → 7. Version → 8. README

If ANY check fails: stop, report the issue, fix it, then re-run.

## Severity Levels

- **BLOCK** (must fix before commit): build failure, test failure, credential leak, ignore/ staged
- **WARN** (should fix, can commit with acknowledgment): missing doc comment, naming violation, broken doc link
- **INFO** (nice to have): version not tagged, GitHub metadata outdated
