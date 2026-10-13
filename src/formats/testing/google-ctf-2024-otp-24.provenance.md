# Google CTF 2024 OTP 24-image package

- Original attachments: `2nd00.png`–`2nd23.png` from <https://github.com/google/google-ctf/tree/main/2024/quals/crypto-otp/attachments/encrypted>.
- Local stored ZIP: `src/formats/testing/google-ctf-2024-otp-24.zip`, assembled from those original image bytes in numerical order, Git blob `f29367fb85fb4dc7917525a8c8ebd1ace89aeed2` (323,714 bytes). Archive timestamps are local packaging metadata; original PNG bytes are not altered. The first PNG matches published Git blob `fa833e5853e39d403d3aa50c340b63f6e7f9e3d5`.
- License: Apache-2.0, `corpus/LICENSE.google-ctf.apache-2.0.txt`; copyright 2024 Google LLC.
- Regression: `src/formats/pixelPermutation.test.ts` feeds all 24 original images to the bounded shared-swap operation and checks score improvement and deterministic report output.

The seeded 2,000-swap run does not reproduce the official ten-million-swap result or recover the released flag.
