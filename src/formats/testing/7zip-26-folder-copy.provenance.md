# 7-Zip 26.04 Copy archive with a directory

- Produced with 7-Zip 26.04 (`7zz a -t7z -m0=Copy -ms=off -mhc=off -mtm=off -mta=off -mtc=off`) using an empty `m6-directory/` and the licensed Google CTF LCG text fixture.
- Archive: `src/formats/testing/7zip-26-folder-copy.7z`, containing one directory and one 930-byte regular Copy stream. 7-Zip independently lists both.
- Regression: `src/formats/sevenZipCopy.test.ts` checks the directory is listed but not extracted, while the regular stream still has its original CRC-verified contents.

This is an independently generated format vector, not a sourced CTF challenge.
