# Website

The page at <https://enclos.dev/>: what enclos does, how to install it and what to know about its limits. Keep it short: one page, leading with letting agents work while your computer stays yours, and details left to the two guides beside it, `getting-started.html` and `policy-compilation.html`. They are shorter versions of [getting started](../docs/getting-started.md) and [policy compilation](../docs/policy-compilation.md), written by hand: when a command or a behavior changes in those docs, change the guide too. It is plain HTML, CSS and JavaScript, with no build step, external font or analytics. The only request it makes is to the GitHub API, to name the latest release.

[`pages.yml`](../.github/workflows/pages.yml) publishes this folder and [`install.sh`](../install.sh) on every change to them on `main` ([releases](../docs/releases.md#the-website)). To preview it:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory site
```

then open <http://127.0.0.1:8765>.

Keep it to what enclos does today, with what enclos is built for marked beside what runs today, and check each claim against the [README](../README.md), [getting started](../docs/getting-started.md), the [design](../docs/design.md) and the [threat model](../docs/adr/0014-threat-model-accidental-damage.md). It says plainly that host reads are broad, that agents in one sandbox share it, that the default `assistant` policy reaches the public web, and that the proxy sees where HTTPS connections go, not their content. enclos is meant to run on more than one operating system, so the page says "your computer", not "your Mac"; it names macOS and Linux only where it states what runs today, and says where a step differs between them. In the same way, it speaks of agent runtimes, names Hermes where it says what runs today, and names other runtimes only as planned. The commands it shows must run as written: paste them into a real sandbox after changing them. The `status` sample is labelled as an example and follows `enclos status`'s own layout. The policy sample must pass `enclos policy edit`, and the compiled sample beside it follows what Seatbelt's compiler (`src/backend/seatbelt/compile.rs`) or bubblewrap's (`src/backend/bubblewrap/compile.rs`) writes, shortened and labelled with the backend it shows.

The brand icon and wordmark are in [`assets/`](../assets/).
