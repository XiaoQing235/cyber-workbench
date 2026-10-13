# libarchive compressed RAR5 negative fixture

- Original encoded fixture: <https://github.com/libarchive/libarchive/blob/master/libarchive/test/test_read_format_rar5_multiple_files.rar.uu>.
- Local `src/formats/testing/libarchive-rar5-compressed.rar` is the uu-decoded upstream test archive (1,656 bytes).
- Repository license: BSD-style libarchive license, <https://github.com/libarchive/libarchive/blob/master/COPYING>.
- 7-Zip 26.04 reports four independent m5 compressed RAR5 members. The bounded m0 extractor must reject it rather than return compressed bytes as plaintext. Regression: `src/operations/archive.test.ts`.

This is a format rejection vector, not a CTF challenge or compressed RAR recovery proof.
