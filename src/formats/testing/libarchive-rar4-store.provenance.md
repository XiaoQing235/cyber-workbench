# libarchive RAR4 stored-member fixture

- Original encoded fixture: <https://github.com/libarchive/libarchive/blob/master/libarchive/test/test_read_format_rar.rar.uu>.
- Local archive `src/formats/testing/libarchive-rar4-store.rar` was decoded from the upstream uuencoded test file without modifying archive bytes; Git blob `a0e135fcf1d896265481f60ecef58776775ff300` (336 bytes).
- Repository license: BSD-style libarchive license, <https://github.com/libarchive/libarchive/blob/master/COPYING>.
- Independently inspected with 7-Zip 26.04: five RAR4 entries (stored text files, a symlink, two directories). `src/operations/archive.test.ts` checks stored regular-file extraction against the original plaintext, and rejects symlink/directory selection and tampered CRC bytes.

This is an independently published format fixture, not a sourced CTF challenge. Compressed, split and encrypted RAR members remain unsupported.
