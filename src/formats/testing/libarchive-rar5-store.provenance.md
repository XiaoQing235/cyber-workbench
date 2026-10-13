# libarchive RAR5 stored-member fixture

- Original encoded fixture: <https://github.com/libarchive/libarchive/blob/master/libarchive/test/test_read_format_rar5_stored.rar.uu>.
- Local archive `src/formats/testing/libarchive-rar5-store.rar` was decoded from the upstream uuencoded fixture without modifying archive bytes; Git blob `a9a34301f571216a294baa590b6b092309f46dc3` (109 bytes).
- Repository license: BSD-style libarchive license, <https://github.com/libarchive/libarchive/blob/master/COPYING>.
- Independently inspected with 7-Zip 26.04: one unencrypted stored 29-byte `helloworld.txt` file (CRC-32 `95A043B4`). `src/operations/archive.test.ts` verifies exact extracted plaintext and CRC rejection through the registered operation.

This is a published format fixture, not a sourced CTF challenge. Other RAR5 extra fields, compressed and encrypted entries remain unsupported.
