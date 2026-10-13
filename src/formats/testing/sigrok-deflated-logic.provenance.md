# Deflated sigrok-compatible session vector

- Created independently with Python 3.13 `zipfile.ZIP_DEFLATED` from explicit version-2 sigrok-style metadata and 32 digital sample bytes (`00 01 03 02` repeated eight times).
- Archive: `src/formats/testing/sigrok-deflated-logic.sr`; contains `version`, `metadata`, and ZIP-deflated `logic-1` entries. No analog devices or multiple sessions.
- Regression: `src/formats/sigrokSession.test.ts` imports the archive through the registered operation, checks the decoded 1 MHz sample period, two named probes, 32 samples and VCD signal inventory.

This is a compatible format vector, not an original sigrok capture or a sourced CTF challenge.
