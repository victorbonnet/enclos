"use strict";

// These examples explain the default policy. They do not contact a running sandbox.
const scenarios = {
  install: {
    verdict: "Allowed inside its home",
    destination: "sandbox home",
    blocked: false,
    title: ["The tool gets a home.", "Your Mac keeps its boundaries."],
    description: "Tools, dependencies, and skills can live inside the sandbox’s own home and run under the same policy. Downloads still need an allowed destination.",
    commandLabel: "Inspect what this sandbox may do",
    command: "enclos policy show lab",
  },
  keys: {
    verdict: "Blocked by default",
    destination: "host SSH keys",
    blocked: true,
    title: ["A bad instruction stops", "at a sensitive path."],
    description: "Your host’s ~/.ssh is on the default read deny list. The sandbox blocks access even if the agent decides to try. Other host files remain broadly readable unless denied by policy.",
    commandLabel: "Check known ways out from inside the sandbox",
    command: "enclos policy test lab",
  },
  network: {
    verdict: "Refused and logged",
    destination: "your router",
    blocked: true,
    title: ["The public web, yes.", "Your network, no."],
    description: "The agent can browse public websites through the sandbox’s proxy, and every connection is logged. Your Mac’s own services and cloud metadata addresses are never reachable, and a private address needs your explicit grant. See what was refused with enclos net denied lab.",
    commandLabel: "Review what the proxy refused",
    command: "enclos net denied lab",
  },
  agent: {
    verdict: "Reported, then tracked by you",
    destination: "a second agent",
    blocked: false,
    title: ["Another agent.", "The same sandbox boundary."],
    description: "Create an agent with Hermes inside the sandbox and enclos reports it. Add it to track the existing agent without recreating it. It shares this sandbox’s policy, proxy, runtime, and login.",
    commandLabel: "Track an existing agent named scout",
    command: "enclos agent add lab/scout",
  },
};

const scenarioButtons = document.querySelectorAll("[data-scenario]");
const result = document.querySelector(".scenario-result");

for (const button of scenarioButtons) {
  button.disabled = false;
  button.addEventListener("click", () => {
    const scenario = scenarios[button.dataset.scenario];
    if (!scenario) return;

    for (const other of scenarioButtons) {
      other.setAttribute("aria-pressed", String(other === button));
    }
    result.classList.toggle("is-blocked", scenario.blocked);
    document.getElementById("result-verdict").textContent = scenario.verdict;
    document.querySelector(".result-destination").textContent = scenario.destination;
    document.querySelector(".result-track > span").textContent = scenario.blocked ? "×" : "→";
    document.getElementById("result-title").replaceChildren(
      document.createTextNode(scenario.title[0]),
      document.createElement("br"),
      document.createTextNode(scenario.title[1]),
    );
    document.getElementById("result-description").textContent = scenario.description;
    document.getElementById("result-command-label").textContent = scenario.commandLabel;
    document.getElementById("result-command").textContent = scenario.command;
  });
}

// The command stays selectable everywhere; copying is an enhancement.
const copyButton = document.getElementById("copy-install");
if (navigator.clipboard && window.isSecureContext) {
  copyButton.hidden = false;
  copyButton.addEventListener("click", async () => {
    const status = document.getElementById("copy-status");
    try {
      await navigator.clipboard.writeText(document.getElementById("install-code").textContent);
      copyButton.textContent = "Copied ✓";
      status.textContent = "Install command copied. Paste it into Terminal.";
      window.setTimeout(() => { copyButton.textContent = "Copy command"; }, 2500);
    } catch {
      status.textContent = "Copying was unavailable. Select the command and copy it.";
    }
  });
}

// Name the release the installer would take. Without an answer, the page's own text stands.
fetch("https://api.github.com/repos/victorbonnet/enclos/releases/latest", {
  headers: { Accept: "application/vnd.github+json" },
})
  .then(async (response) => {
    const state = document.getElementById("release-state");
    if (response.status === 404) {
      state.textContent = "First release coming soon";
      document.getElementById("release-note").textContent =
        "No release is published yet: the command says so and installs nothing. Until the first one, build from a clone with Rust: cargo install --locked --path .";
      return;
    }
    if (!response.ok) return;
    const { tag_name: tag } = await response.json();
    if (typeof tag === "string" && /^v\d+\.\d+\.\d+$/.test(tag)) {
      state.textContent = "Latest release: " + tag;
    }
  })
  .catch(() => {});
