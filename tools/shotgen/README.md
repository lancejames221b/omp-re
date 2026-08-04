# omp-re shotgen

Renders real `omp-re` TUI captures to PNG for `README.md` and the GitHub
release body. Standalone dev tool, isolated from the plugin's own
`package.json`/`bun.lock` — never referenced from the root manifest.

## Regenerating the screenshots

```bash
bun install --ignore-scripts
FIXTURE=/bin/ls DECOMPILE_FN=main DECOMPILE_DOWN=2 REPORT_ADDR=0x1000 bash capture.sh
bun render.ts
```

The committed `docs/img/*.png` are real captures of `/bin/ls`, not the
WannaCry sample `capture.sh` defaults to — `/bin/ls` exists on every Linux
box, so anyone can reproduce them without a malware fixture.
`DECOMPILE_DOWN=2` is required for this fixture because the functions panel
filters on the function **name** substring only, so `main` also matches
`sym.imp.textdomain` and `sym.imp.bindtextdomain`, both of which sort ahead
of the real `main` by address; without the two Down presses, Enter opens an
import thunk instead.

Then, with an agent that has the `browser` tool, open each
`out/<scene>.html` and screenshot the `#shot` element. Measured fact: the
capture path emits **1024px-wide** PNGs regardless of the requested
viewport/scale (1040px viewport / `scale: 2` requested, 1024px delivered) —
target roughly that width for a visual match with any headless-Chrome
equivalent. Save the result to `../../docs/img/<scene>.png`.

`capture.sh` requires tmux, a real `radare2`, and a fixture binary. Unset,
`FIXTURE` defaults to the WannaCry sample used by `test/tui-qa.sh`
(`/tmp/rzx-dogfood/wannacry.bin`), which is **deliberately not distributed**
with this repo — set `FIXTURE=/path/to/your/binary` to point it elsewhere.
Some scenes assume that specific fixture's disassembly (the `main` filter in
the decompile/xrefs scenes) and may skip on a substitute rather than fail;
the invocation above is the one that actually produced the committed
images.

`out/` is intermediate output — ANSI captures and rendered HTML — and is
git-ignored. Only the final PNGs under `docs/img/` are committed.

Any headless-Chrome equivalent (Puppeteer, Playwright, `chrome
--headless=new --screenshot`) works in place of the `browser` tool for the
last step; this repo does not add one as a dependency since screenshotting
is a one-off dev task, not something the plugin itself needs at runtime.
