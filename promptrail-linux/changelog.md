# Changelog

## Unreleased / Current Session

### Fixed

- Resolved the daemon build error caused by using `std::error::Error::source` with `anyhow::Error` in [promptrail-daemon/src/main.rs](promptrail-daemon/src/main.rs).
- Updated the fatal-error logging path in [promptrail-daemon/src/main.rs](promptrail-daemon/src/main.rs) to iterate over the `anyhow` error chain safely using `e.chain().skip(1)`.

### Improved

- Added libssl target resolution in [promptrail-daemon/src/proc_watch.rs](promptrail-daemon/src/proc_watch.rs) so the daemon can discover a concrete libssl path from `/proc/<pid>/maps` or common system library directories before attaching uprobes.
- Updated the uprobe attachment flow in [promptrail-daemon/src/main.rs](promptrail-daemon/src/main.rs) to use the resolved libssl target dynamically instead of relying only on the bare `ssl` name.
- Added lightweight regression-style tests in [promptrail-daemon/src/proc_watch.rs](promptrail-daemon/src/proc_watch.rs) for the new libssl target resolution helper.

### Build status

- The latest build output reported successful completion of both the `release` and `dev` targets for the workspace.
