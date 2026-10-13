# 7-Zip 26.04 encrypted-header vector

- Produced with local 7-Zip 26.04 (`7zz a -t7z -pM6fixtureOnly2026 -mhe=on -mtm=off -mta=off -mtc=off`) using the Apache-2.0 Google CTF 2023 LCG dump fixture as input.
- Archive: `src/formats/testing/7zip-26-encrypted-header.7z`, Git blob `d2435498e84b55d454baabc48787096daba0f537` (769 bytes).
- Password: `M6fixtureOnly2026` (fixture-only; no secret material).
- Independently inspected by 7-Zip: one 930-byte plaintext member, LZMA2:12 + 7zAES:19, encrypted header. `src/operations/archive.test.ts` checks real-archive hash export, start/next header CRCs, and damaged-header rejection.

This is an independently generated format vector, not a sourced CTF challenge or password recovery proof.
