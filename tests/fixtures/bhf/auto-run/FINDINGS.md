# BHF findings

**6 root-cause issue(s)** from 6 finding observation(s), ordered by impact.

The CSV index is [`findings.csv`](findings.csv); complete evidence bundles are under [`findings/`](findings/). The full campaign and coverage caveats are in [`auto/run.md`](auto/run.md).

## 1. [CRITICAL] ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000039 at pc 0x5886692362b6 bp 0x7fff2922beb0 sp 0x7fff2922b670 (READ of size 65)

- Finding: `F-0000-c0dca483`
- Rule: `BHF-201`
- Evidence: fuzz · confidence medium · verdict likely_reachable
- CWE: CWE-122, CWE-125
- Location: `/work/src/parse.c`:9 in `parse_record`
- Suggested fix: Check the requested index and offset and copy length against the actual buffer bounds before every read or write; use size-aware APIs where available.
- Evidence bundle: [`findings/F-0000-c0dca483/`](findings/F-0000-c0dca483/)
- Reproduce: `bhf replay --finding /work/bhf/findings/F-0000-c0dca483`

## 2. [CRITICAL] ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7c68a3b00030 at pc 0x6280af918348 bp 0x7fff8d17ce50 sp 0x7fff8d17c610 (WRITE of size 45)

- Finding: `F-0002-1d8ca3de`
- Rule: `BHF-203`
- Evidence: fuzz · confidence medium · verdict likely_reachable
- CWE: CWE-121
- Location: `/work/src/parse.c`:9 in `parse_record`
- Suggested fix: Check the requested index and offset and copy length against the actual buffer bounds before every read or write; use size-aware APIs where available.
- Evidence bundle: [`findings/F-0002-1d8ca3de/`](findings/F-0002-1d8ca3de/)
- Reproduce: `bhf replay --finding /work/bhf/findings/F-0002-1d8ca3de`

## 3. [CRITICAL] ERROR: AddressSanitizer: heap-buffer-overflow on address 0x503000000144 at pc 0x5e4a57ee2b24 bp 0x7ffd0a9de160 sp 0x7ffd0a9de158 (WRITE of size 4)

- Finding: `F-0001-bb0ed262`
- Rule: `BHF-201`
- Evidence: fuzz · confidence medium · verdict likely_reachable
- CWE: CWE-122, CWE-787
- Location: `/work/src/parse.c`:17 in `sum_table`
- Suggested fix: Check the requested index and offset and copy length against the actual buffer bounds before every read or write; use size-aware APIs where available.
- Evidence bundle: [`findings/F-0001-bb0ed262/`](findings/F-0001-bb0ed262/)
- Reproduce: `bhf replay --finding /work/bhf/findings/F-0001-bb0ed262`

## 4. [CRITICAL] shell metacharacters observed in a runtime command string

- Finding: `F-0003-77f37013`
- Rule: `BHF-304`
- Evidence: runtime · confidence low · verdict likely_reachable
- CWE: CWE-78
- Location: `/work/src/cmd.c`:4 in `run_cmd`
- Suggested fix: Pass arguments as a list to a fixed program (execve-style), or validate against an allowlist — never build a shell string from input.
- Evidence bundle: [`findings/F-0003-77f37013/`](findings/F-0003-77f37013/)
- Reproduce: `bhf replay --finding /work/bhf/findings/F-0003-77f37013`

## 5. [CRITICAL] fuzz-controlled command reached a shell-execution API during fuzz execution

- Finding: `F-0004-8fb10837`
- Rule: `BHF-431`
- Evidence: runtime · confidence low · verdict likely_reachable
- CWE: CWE-78
- Location: `/work/src/cmd.c`:4 in `run_cmd`
- Suggested fix: During fuzz execution a contiguous run of the command or program argument passed to a process-execution API (system/popen, the execve family, or posix_spawn) was derived from the fuzz input (byte-origin taint), and the exact command was never executed without that taint. system()/popen() hand their whole argument to /bin/sh -c so a controlled span is shell-interpreted; exec*/posix_spawn with a controlled program run an attacker-chosen binary directly — both are OS command injection / arbitrary command execution confirmed by dynamic taint, not a shell-metacharacter heuristic. Build argument vectors from a fixed allow-list and never let untrusted bytes select the program or shell string.
- Evidence bundle: [`findings/F-0004-8fb10837/`](findings/F-0004-8fb10837/)
- Reproduce: `bhf replay --finding /work/bhf/findings/F-0004-8fb10837`

## 6. [MEDIUM] Attacker input can make run_cmd execute a process — this capability is exercised by the fuzz corpus but by no baseline input, so it is input-triggered attack surface.

- Finding: `F-CAP-0000`
- Rule: `BHF-668`
- Evidence: fuzz · confidence medium · verdict likely_reachable
- CWE: CWE-668
- Location: `/work/src/cmd.c`:4 in `run_cmd`
- Suggested fix: Confirm the input should reach this OS capability, then allowlist and constrain its command, path, address, library, or format operand to the minimum required scope.
- Evidence bundle: [`findings/F-CAP-0000/`](findings/F-CAP-0000/)
- Reproduce: `bhf replay --finding /work/bhf/findings/F-CAP-0000`

