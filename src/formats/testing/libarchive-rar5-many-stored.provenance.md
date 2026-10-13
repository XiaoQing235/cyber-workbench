# libarchive multi-member stored RAR5 fixture

- Original encoded fixture: <https://github.com/libarchive/libarchive/blob/master/libarchive/test/test_read_format_rar5_stored_manyfiles.rar.uu>.
- Local `src/formats/testing/libarchive-rar5-many-stored.rar` is the uu-decoded upstream archive, Git blob `5de3ea99946bcb46a65f9a3d5639d23c4329b1bf` (2,586 bytes).
- Repository license: BSD-style libarchive license, <https://github.com/libarchive/libarchive/blob/master/COPYING>.
- Independently inspected/extracted with 7-Zip 26.04: three unencrypted m0 members. `src/operations/archive.test.ts` checks the three indexed extraction SHA-256 digests against 7-Zip output and confirms names/sizes.

This is a published format fixture, not a sourced CTF challenge.
