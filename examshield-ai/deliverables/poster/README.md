# ExamShield AI A1 poster

Files
- `ExamShield_AI_A1_Poster.pdf`: print file, exactly **594 x 841 mm** (A1 portrait), one page, vector text and shapes, fonts embedded. The background runs to the page edge.
- `ExamShield_AI_A1_Poster_with_3mm_bleed.pdf`: same artwork, **600 x 847 mm** (3 mm bleed on every side). Send this to a printer that asks for bleed and have them trim to A1. Crop marks are not included.
- `ExamShield_AI_A1_Poster.svg`: editable source (units are millimetres, viewBox 0 0 594 841). Open in Inkscape or Illustrator. Fonts: Carlito (a free Calibri-metric font); install it if text looks different.
- `build_poster.py`: regenerates all of the above. Run `python deliverables/poster/build_poster.py` (needs Pillow, Playwright with Chromium, pypdf). All numbers are computed by running the real benchmark, so the poster always matches the project.

Editing
- Team details: search the SVG for `[Student names]`, `[Team name]`, `[Institution]`, `[Department]`, `[Faculty guide]` (also in `build_poster.py`).
- QR code: a dashed placeholder box. Replace it only after the demo URL is real and you have scanned the code. Keep at least 35 x 35 mm.
- Safe area: all content sits at least 24 mm inside the trim edge.

Printing
Choose "actual size / 100%" (no fit-to-page). Ask for a proof if possible; dark navy backgrounds can print differently from screens. Smallest caption text is about 5.8 mm tall (roughly 16 pt); body text is 6.7 to 9.4 mm; headings 14 mm and up.

Accuracy
The poster states only what the project does: Python standard library, SQLite, a JSON API, JavaScript front end, unittest. The benchmark figures are from the synthetic dataset and are labelled as such.
