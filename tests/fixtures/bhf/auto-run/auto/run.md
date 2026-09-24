# BHF auto run — 2026-09-24T18:54:54.147404121+00:00
Source: /work/src
Mode: reporting

## Findings
**6 finding observation(s). Start with [`FINDINGS.md`](../FINDINGS.md).**
Machine-readable root-cause index: [`findings.csv`](../findings.csv). Complete evidence bundles: [`findings/`](../findings/).

## Campaign summary
Discovered: 4
Built:      4
Failed:     0
Skipped (could not auto-harness): 0
Unrecoverable link: 0
Unrecoverable runtime: 0
Findings:   6

## Targets
  - H-C0005-3B81D475 parse_record built+fuzzed empty=6execs/3exec_s/1f rng=10execs/3exec_s/0f fuzz_driven=28execs/3exec_s/1f cov=6edges
  - H-C000D-EC9148C8 sum_table built+fuzzed empty=5execs/2exec_s/1f rng=9execs/3exec_s/0f fuzz_driven=25execs/3exec_s/0f cov=6edges
  - H-C0004-8B1AE7C6 run_cmd built+fuzzed empty=1001execs/500exec_s/2f rng=284execs/9exec_s/0f cov=12edges
  - H-C0009-B9A35386 copy_name built+fuzzed empty=29883execs/14940exec_s/0f rng=55294execs/17028exec_s/0f fuzz_driven=170165execs/17490exec_s/0f cov=11edges

## Upstream delta

### Runtime resources observed during fuzzing

### Environment variables (auto-injected)
  - BLOCKSIZE    used by 1 target(s)
  - BLOCK_SIZE    used by 1 target(s)
  - LS_BLOCK_SIZE    used by 1 target(s)
  - POSIXLY_CORRECT    used by 1 target(s)
  - QUOTING_STYLE    used by 1 target(s)
  - TZ    used by 1 target(s)

### Missing files
  - /etc/selinux/config    used by 1 target(s)
