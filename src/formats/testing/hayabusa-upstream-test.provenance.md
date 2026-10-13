# Hayabusa JSONL sample

- Original: <https://github.com/Yamato-Security/hayabusa/blob/main/test_files/evtx/test.jsonl>.
- Local file: `src/formats/testing/hayabusa-upstream-test.jsonl`, byte-identical to upstream Git blob `a2a894ca991fa3253c367527cc66acfea65b8f4c` (3,693 bytes).
- Repository license: AGPL-3.0, <https://github.com/Yamato-Security/hayabusa/blob/main/LICENSE.txt>.
- Regression: `src/formats/windowsTimeline.test.ts` imports the two published Sysmon JSONL events with their explicit UTC timestamps, host identifiers and paths; `src/formats/entityCorrelation.test.ts` checks explicit file-path and account/SID observations and a five-second cross-host association. The association is not evidence of causation or the same host.

This published tool-format sample is not a sourced CTF challenge fixture.
