# Plaso Catalog1.edb fixture

- Original: <https://github.com/log2timeline/plaso/blob/1e2fa282efa2f839e1f179a3e98dbf922b5dbbc7/test_data/Catalog1.edb>.
- Local file: `src/formats/testing/plaso-catalog1.edb`, byte-identical to upstream Git blob `22c61563ad84a869ce65dc2004075c8032223882` (3,153,920 bytes).
- Repository license: Apache-2.0, <https://github.com/log2timeline/plaso/blob/1e2fa282efa2f839e1f179a3e98dbf922b5dbbc7/LICENSE>.
- Regression: `src/formats/eseHeader.test.ts` checks original ESE database-header metadata and its primary checksum through the registered operation. It does not decode ESE pages or SRUM tables.

This is a published format fixture, not a sourced CTF challenge.
