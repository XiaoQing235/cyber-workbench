# Google CTF 2024 OTP complete second-round package

- Original attachments: `2nd00.png`–`2nd63.png` from <https://github.com/google/google-ctf/tree/main/2024/quals/crypto-otp/attachments/encrypted>.
- Local stored ZIP: `src/formats/testing/google-ctf-2024-otp-64.zip`, assembled from the original PNG bytes in numerical order; Git blob `5d3db2b1f7c6c8c366c2ee74fc8024519dc92b38` (872,804 bytes). ZIP timestamps are packaging metadata; the PNG bytes are unchanged.
- License: Apache-2.0, `corpus/LICENSE.google-ctf.apache-2.0.txt`; copyright 2024 Google LLC.
- Regression: `src/formats/pixelPermutation.test.ts` runs seeded bounded swaps over all 64 original images, verifies improvement, and confirms a resumed batch for image 63 equals a continuous run.

This covers the complete second-round image set, not the full official ten-million-swap recovery or released flag.
