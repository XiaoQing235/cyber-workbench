# postal-mime nested MIME fixture

- Original: <https://github.com/postalsys/postal-mime/blob/master/test/fixtures/mixed.eml>
- Local file: `src/formats/testing/postal-mime-mixed.eml` (byte-identical to upstream Git blob `3718c9b1cd67b57896d83dd08fc838fee8642562`)
- Author: Andris Reinman / postal-mime contributors; copyright (c) 2021–2025 Andris Reinman.
- License: MIT, <https://github.com/postalsys/postal-mime/blob/master/LICENSE.txt>.
- Regression: `src/formats/mimeMail.test.ts` checks the nested text/HTML output through `forensics.mail.inspect` and verifies no routing or attachment facts are invented.

This is a format conformance vector, not a CTF challenge or an end-to-end flag fixture.
