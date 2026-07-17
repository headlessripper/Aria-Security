# Phase 1 Restore

To restore any quarantined file to its original location:
    git mv cleanup/<tag>/<original/path> <original/path>

To restore an entire bucket (example: qt-ui):
    cd cleanup/qt-ui && git ls-files | while read f; do
      dest="${f#cleanup/qt-ui/}"; mkdir -p "$(dirname "../../$dest")"; git mv "$f" "../../$dest"; done

To restore everything Phase 1 moved, revert the Phase 1 commits:
    git revert --no-commit <first-phase1-sha>..<last-phase1-sha> && git commit

Baseline (pre-Phase-1) snapshot: commit 871bbf3 (run `git rev-parse HEAD` before Task 1
to capture the exact current tip if it has advanced).
