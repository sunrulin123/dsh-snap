# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.7.4] - 2026-11-10

### Fixed — second independent audit (26 findings: 3 P0, 10 P1, 13 P2; all fixed)

- **P0** Snapshot manifest `taken` lists are now allowlist-validated on read — a
  tampered manifest cannot write files outside the profile/home via `../` traversal.
- **P0** Restore refuses (and reports) junction/reparse-point **ancestors** inside the
  target path — lexical containment alone cannot stop reparse redirection; ancestors
  are re-checked after every `mkdir` to close the TOCTOU window.
- **P0** Incremental snapshots no longer trust the previous snapshot's recorded hash —
  bytes are re-hashed before reuse, so pollution in a previous snapshot is detected and
  excluded (`pollutedPrev` reported) instead of silently propagating into new
  "complete" snapshots.
- Restore now runs under an advisory **mutex** (`restore.lock`, `wx` open): a second
  concurrent restore is refused with `restore-busy` while the holder is alive; a dead
  holder's lock is taken over.
- Restore result is **fail-closed** on hard issues (missing snapshot file, restore
  failure, missing index, refused reparse ancestor, …): `ok:false` + `partial:true` +
  guard snapshot retained — the CLI exits non-zero instead of reporting success.
- `restore last` selects the latest **pre-install trigger** snapshot (agent/web/cli
  install family) rather than any snapshot; falls back with `lastFallback` reported.
- Pre-install triggers are whitelist-matched (`agent:install*`, `cli-install`,
  `web-install`, …) so synthetic trigger strings cannot hijack `last`.
- `repair-profile` and `repair-gui` backups are **fail-closed**: if the guard backup
  cannot be created, the operation aborts before touching live files.
- Content identity is verified in three tiers (inode → sha256 → byte compare) before
  declaring a node_modules entry up-to-date; `size+mtime` alone is only ever a
  "needs verification" hint.
- Prune no longer extrapolates shared-byte accounting from O(live) rows in memory —
  two-pass streaming scan with shared tables rebuilt from the surviving pool only.
- `benign .modules.yaml drift` is only accepted when live and snapshot sides share the
  same inode (verify accepts an optional `liveNmDir`).
- Credential scanning covers single- and double-quoted keys; profile-layer hits are
  recorded (`layers.profile.credHits` + journal) instead of skipped silently.
- Host side: kernel is loaded only from the plugin directory (no store fallback);
  fatal-error rethrow gate actually works (listener-count semantics fixed); tool
  outputs declare the host-required `{schema, render}` contract; `/snap` reads
  `invocation.rawInput`.
- New negative-control regressions for the audit findings (selftest 49 → 55).

## [0.7.3] - 2026-11-10

### Fixed — first independent review (11 findings: 7 P1, 4 P2; all fixed)

- Panel projection no longer parses the (multi-MB) manifest twice per list.
- Process-busy probe (`tasklist`) failure is now fail-closed: busy is reported as
  `null` and the operation refuses, instead of silently proceeding.
- `repair-gui` backup/delete failures no longer report success — guard and live state
  are preserved and the CLI exits non-zero.
- `repair-profile` aborts before writing when the guard backup fails (manifest
  pre-serialized; patch written via temp-file + rename).
- Host consumes the synchronous `takeSnapshot` return value correctly (pending-baseline
  chain: snapshot → clear pending → journal shows `harness-change` snapshot).
- Ghost-bundle candidates no longer pass when `node_modules` is missing; official
  namespace scope exemption no longer swallows stale bundles.
- Store rescue-copy version marker self-heals when code matches but the marker lags.
- Six review findings pinned as regression tests (selftest 43 → 49).

## [0.7.2] - 2026-11-10

### Added

- `crash`: shell-handshake classification — a broken desktop shell handshake (e.g.
  web-auth failure) is no longer misattributed to plugins and no longer produces a
  useless "restore" suggestion; mixed crash scenes keep the restore hint.
- `repair-profile` / `repair-gui`: surgical repair after the official "recover
  plugins" button shrinks bundles / renames the Cordis patch — guard-backed, dry-run
  first, desktop-running gate.
- `doctor` detects recovery artifacts (`.bak-*` patch, shrunken bundles).

## [0.7.0] - 2026-11-09

### Added

- External rescue web server (`serve`): loopback-only + random token; snapshot list,
  manual snapshot, preflight, verify, crash attribution, two-step restore
  (preview → confirm) — usable in a browser when DSH cannot boot.
- Rescue batch files in the store (`restore-last.bat`, `repair-gui.bat`, …) prefer the
  DSH-bundled Node runtime, so they work without `node` on `PATH`.
- `preflight <pkg>` pre-install check: registry existence, deprecation flags,
  `engines.dsh` vs local harness version (zero-dependency semver subset; warn-only).

## [0.6.0] - 2026-11-09

### Added

- Crash attribution: crash-log parsing × journal time-window correlation → suspect
  plugins with direct/circumstantial grading, crash-loop detection, and a restore
  command pointing at the pre-crash snapshot. Reports only — never acts.

## [0.5.1] - 2026-11-09

### Fixed

- `node_modules/.modules.yaml` (pnpm's in-place rewrite) excluded from the hardlink
  pool — it previously polluted every historical snapshot.
- dsh-snap's own directory uses private copies, never hardlinks — self-upgrade chain
  pollution fixed.

## [0.3.5] - 2026-11-08

### Added

- First public-shaped release: pre-install auto-snapshots on all three install paths
  (agent tool interception / Web install-state / CLI run.json watcher, best-effort) +
  manual; external zero-dependency restore CLI living inside the snapshot store;
  guard snapshot before every restore (undoable); doctor / verify / prune / open;
  Web panel tab; `/snap` session command; read-only agent tools
  (`snap_list` / `snap_snapshot` / `snap_doctor` — restore deliberately not exposed
  to the agent).
