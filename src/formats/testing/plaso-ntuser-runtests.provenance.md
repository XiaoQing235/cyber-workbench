# Plaso NTUSER-RunTests.DAT fixture

- Original: <https://github.com/log2timeline/plaso/blob/1e2fa282efa2f839e1f179a3e98dbf922b5dbbc7/test_data/NTUSER-RunTests.DAT>.
- Local file: `src/formats/testing/plaso-ntuser-runtests.dat`, byte-identical to upstream Git blob `a7e65e13b7dd760d98472182685a12b26ad9cfa7` (262,144 bytes).
- Repository license: Apache-2.0, <https://github.com/log2timeline/plaso/blob/1e2fa282efa2f839e1f179a3e98dbf922b5dbbc7/LICENSE>.
- Regression: `src/formats/registryHive.test.ts` checks the original hive's header, root and child key traversal through the registered inspector. Transaction-log replay and big-data values are not covered.

This is a published format fixture, not a sourced CTF challenge.
