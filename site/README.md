# Website

The page at <https://victorbonnet.github.io/enclos/>: what enclos does, a few illustrated boundaries, how to install it and common questions. It is plain HTML, CSS and JavaScript, with no build step, external font or analytics. The only request it makes is to the GitHub API, to name the latest release.

[`pages.yml`](../.github/workflows/pages.yml) publishes this folder and [`install.sh`](../install.sh) on every change to them on `main` ([releases](../docs/releases.md#the-website)). To preview it:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory site
```

then open <http://127.0.0.1:8765>.

Keep it to what enclos does today, and check each claim against the [README](../README.md), [getting started](../docs/getting-started.md), the [design](../docs/design.md) and the [threat model](../docs/adr/0014-threat-model-accidental-damage.md). It says plainly that host reads are broad, that agents in one sandbox share it, that the default `assistant` policy reaches the public web, and that the proxy sees where HTTPS connections go, not their content. enclos is meant to run on more than one operating system, so the page says "your computer", not "your Mac"; it names macOS only where it states what runs today, and names Linux only as planned until its backend ships. In the same way, it speaks of agent runtimes, names Hermes where it says what runs today, and names other runtimes only as planned.

The brand icon and wordmark are in [`assets/`](../assets/).
