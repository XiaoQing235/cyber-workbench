# postal-mime multi-hop bounce fixture

- Original: <https://github.com/postalsys/postal-mime/blob/master/test/fixtures/bounce.eml>.
- Local file: `src/formats/testing/postal-mime-bounce.eml`, byte-identical to upstream Git blob `ab82052f236146b037143af73ab734d11ec89d83` (12,200 bytes).
- Author: Andris Reinman / postal-mime contributors. Repository license: MIT, <https://github.com/postalsys/postal-mime/blob/master/LICENSE.txt>.
- Regression: `src/formats/mimeMail.test.ts` checks top-level Received hop chronology and attributed SPF/DKIM/DMARC claims through `forensics.mail.inspect` on the original message.

This is a published format fixture, not a sourced CTF challenge. Received and Authentication-Results fields are message claims, not independently verified routing/authentication facts.
