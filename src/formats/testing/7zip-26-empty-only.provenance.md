# 7-Zip 26.04 archives with no packed streams

- Created with 7-Zip 26.04 (`7zz a -t7z -m0=Copy -ms=off -mhc=off -mtm=off -mta=off -mtc=off`) from an empty `m6-empty.txt` and, separately, an empty `m6-directory/`.
- `7zip-26-empty-only.7z` contains one zero-byte regular file; `7zip-26-folder-only.7z` contains one directory. `7zz l -slt` reports zero packed blocks in both.
- `src/formats/sevenZipCopy.test.ts` checks that the bounded parser lists both and extracts only the empty regular file.

These are independently generated format vectors, not CTF challenge fixtures.
