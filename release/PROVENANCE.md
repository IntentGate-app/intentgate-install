# Release-input provenance: the nested `intentgate-install/` copy

**Disposition:** removed from release input permanently. The build refuses it: `guard-release-input` and `verify-bundle` fail on any nested repository, ignored file, untracked file or archive in a release input tree.

## What it is (recovered from this repository's own history)

| Fact | Value | Source |
|---|---|---|
| First appearance | Gitlink (mode 160000) `intentgate-install` → `ead14679763a30f16b2c2036a3be1285ff51ecb2` | `git ls-tree fc4913b intentgate-install` |
| What the gitlink points at | `ead1467` *is this repository's root commit* ("IntentGate one-click installer: compose, env template, install scripts", 2026-07-09 00:00:26 +0200 = 2026-07-08T22:00:26Z) | `git log -1 ead1467` |
| Tracked in | `ead1467` … `fc4913b` (2026-07-09) | `git log -- intentgate-install` |
| Removed from tracking | `c99ddef` "Remove embedded clone; restore executable bit on install.sh" (2026-07-09 08:01 +0200), which also added `intentgate-install/` to `.gitignore` | `git show --stat c99ddef` |
| Present on the owner's working copy | Yes, as an ignored nested git clone dated 2026-07-08 | claude/LKG-CLEAN-ROOM-RELEASE-ACCEPTANCE-2026-09-30.md §1; claude/LKG-PRODUCT-EVIDENCE-FINDINGS-2026-09-30.md §1 (DUPLICATE/OBSOLETE) |

The copy is a self-clone of this repository at its first commit. Its content at the recorded gitlink is fully preserved in this repository's history: `git show ead1467:<path>` reproduces every file. Nothing about it is lost by excluding it.

## Not verifiable from the cloud build host

The nested clone exists only on the owner's machine; it is not in this repository and was never pushed. Whether its *current* HEAD is still `ead1467`, or whether it carries local edits, was **not measured**. See the owner action below.

## Owner action (one command, read-only)

On the owner's machine, in the install working copy:

```sh
git -C intentgate-install log -1 --format='%H %ci' ; git -C intentgate-install status --porcelain | wc -l
```

- If it prints `ead14679763a30f16b2c2036a3be1285ff51ecb2 …` and `0`, the copy is exactly `ead1467`. Delete the folder.
- Otherwise, preserve it first with `git -C intentgate-install bundle create ../intentgate-install-nested-$(date +%Y%m%d).bundle --all`, record the bundle's sha256 in this file, then delete the folder.

## Why it must never ship

A folder zip of the working copy would ship a months-old installer. Its compose pinned mutable tags and omitted the control plane. `release/assemble-bundle.sh` copies only the tracked, clean files listed in `release/bundle-files.json`. CI runs `guard-release-input`, which fails on any nested `.git`, ignored file, untracked file or archive, so the copy cannot re-enter a release by any path.
