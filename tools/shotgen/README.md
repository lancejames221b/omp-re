# omp-re shotgen

Renders real `omp-re` TUI captures to PNG for `README.md` and the GitHub
release body. Standalone dev tool, isolated from the plugin's own
`package.json`/`bun.lock` — never referenced from the root manifest.

## Regenerating the screenshots

```bash
bun install --ignore-scripts
bash capture.sh
bun render.ts
```

Then, with an agent that has the `browser` tool, open each
`out/<scene>.html` and screenshot the `#shot` element (see the commit that
added `docs/img/*.png` for the exact viewport/scale used). Save the result
to `../../docs/img/<scene>.png`.

`capture.sh` requires tmux, a real `radare2`, and a fixture binary. It
defaults to the real WannaCry sample used by `test/tui-qa.sh`
(`/tmp/rzx-dogfood/wannacry.bin`), which is **deliberately not distributed**
with this repo — set `FIXTURE=/path/to/your/binary` to point it elsewhere.
Some scenes assume that specific fixture's disassembly (the `main` filter in
the decompile/xrefs scenes) and may skip on a substitute rather than fail.

`out/` is intermediate output — ANSI captures and rendered HTML — and is
git-ignored. Only the final PNGs under `docs/img/` are committed.

Any headless-Chrome equivalent (Puppeteer, Playwright, `chrome
--headless=new --screenshot`) works in place of the `browser` tool for the
last step; this repo does not add one as a dependency since screenshotting
is a one-off dev task, not something the plugin itself needs at runtime.
