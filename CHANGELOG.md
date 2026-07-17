# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0]

### Breaking Changes
- **Renamed binary**: `ringbuf-reserve-submit` → `arp-monitor` (reflects purpose, not implementation)
- **CLI interface changed**: Now requires `-i <interface>` flag instead of positional argument
- **Removed**: Raw file-per-day logging (replaced by structured logging system)
- **Restructured**: Source moved to `src/` and `src/bpf/` directories

### Added
- **ARP Spoofing Detection**: Full IP→MAC tracking with configurable flip threshold
  - Kernel-side: `BPF_MAP_TYPE_HASH` map for zero-copy MAC change tracking
  - Userspace: Hash table mirror for logging and alerting
  - Configurable threshold (`-t N`) to reduce false positives
- **CLI with getopt_long**: Full option parsing
  - `-i/--interface`: Network interface (required)
  - `-v/--verbose`: Debug-level output
  - `-j/--json`: Structured JSON output (one object per line, pipe-friendly)
  - `-d/--daemon`: Daemonize with syslog
  - `-t/--threshold`: Spoof detection sensitivity
  - `-l/--log-file`: Log to file
  - `-w/--whitelist`: IP-MAC whitelist (not yet implemented, reserved)
  - `-V/--version`: Version info
- **Structured Logging**: Levels (DEBUG/INFO/WARN/ERROR), timestamps, file:line in debug, syslog support
- **JSON Output Mode**: Machine-parseable NDJSON for integration with SIEM/log aggregators
- **Graceful Shutdown**: `SIGINT`/`SIGTERM` handlers with proper cleanup (TC hook detach, BPF destroy, buffer flush)
- **CO-RE / vmlinux.h**: Uses BTF-based CO-RE for cross-kernel portability (5.15+)
- **Unit Tests**: 10 test cases covering spoof detection logic (no external framework dependencies)
- **Integration Tests**: Bash script using veth pairs + network namespaces for end-to-end validation
- **GitHub Actions CI**: Multi-kernel build matrix, cppcheck, clang-format enforcement, ASan/UBSan
- **`.clang-format`**: Consistent code style enforcement

### Changed
- **Build system**: Updated Makefile with `-Wall -Wextra -Werror -std=gnu11` (note: `-pedantic` omitted — incompatible with libbpf's `LIBBPF_OPTS` macro which uses GCC statement expressions)
- **BPF program**: Complete rewrite
  - Uses `vmlinux.h` + CO-RE instead of raw kernel headers
  - Proper bounds checks on all packet accesses
  - `BPF_MAP_TYPE_HASH` for kernel-side IP→MAC tracking
  - Uses `__builtin_memcpy` (verifier-friendly) instead of libc `memcpy`
  - Does NOT drop malformed packets (returns `TC_ACT_OK` — monitoring only, not enforcement)
  - Defines `TC_ACT_OK`/`TC_ACT_SHOT` locally (vmlinux.h provides types only, not macros)
  - BPF config map renamed to `arp_config` to avoid `config_s` typedef collision in vmlinux.h
- **Shared header** (`arp_monitor.h`): Uses `linux/types.h` for userspace and vmlinux.h types for BPF — avoids glibc include failures under `-target bpf` and typedef redefinition errors
- **Event structure**: Added `flags` field (new host, spoof detected), `timestamp_ns`
- **Dockerfile**: Multi-stage, minimal runtime image, proper ENTRYPOINT, `gcc-multilib` for BPF cross-compilation

### Removed
- `bump_memlock_rlimit()` — unnecessary on kernel ≥5.11 (memcg-based BPF memory accounting)
- Per-event `fopen()`/`fclose()` pattern (was a performance bug)
- BSD-type usage (`u_int16_t` etc.) in shared headers

### Fixed
- **Buffer overflow**: `strcat(filename, ".txt")` without bounds check in old event handler
- **File descriptor leak**: Old code opened file on every event, potential fd exhaustion under ARP storm
- **Missing cleanup on error paths**: All error paths now go through `cleanup()` label/function
- **TC hook cleanup**: Hooks are now always destroyed on exit (even on crash signals)

### Security
- **Input validation**: Full `strtol` with `endptr` + `errno` check (rejects trailing chars, overflow, empty input)
- **`freopen` return checked**: Daemon mode fails cleanly if `/dev/null` redirect fails
- **Stale filter recovery**: `BPF_TC_F_REPLACE` on `EEXIST` — handles unclean previous exit gracefully instead of failing
- No user-controlled data written to format strings
- BPF verifier compliance verified on kernel 5.15+ (Docker build tested)
- Documented required capabilities (`CAP_BPF`, `CAP_NET_ADMIN`)
- No unsafe string functions (`sprintf`, `strcpy`, `strcat`, `gets`) anywhere in codebase

## [1.0.0]

Initial implementation: TC-hooked BPF program logging ARP packets to date-named files.
