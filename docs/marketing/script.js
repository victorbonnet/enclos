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
    verdict: "Refused until you allow it",
    destination: "a new API",
    blocked: true,
    title: ["A new destination.", "A decision for you."],
    description: "The proxy refuses an unlisted destination and logs it. Inspect it with enclos net denied lab. If you trust the host, allow it from your Mac; new connections can use it without a restart.",
    commandLabel: "Example: allow a weather API you trust",
    command: "enclos policy allow lab api.open-meteo.com",
  },
  agent: {
    verdict: "Reported, then tracked by you",
    destination: "a second agent",
    blocked: false,
    title: ["Another agent.", "The same sandbox boundary."],
    description: "Create an agent with Hermes inside the sandbox and Enclos reports it. Add it to track the existing agent without recreating it. It shares this sandbox’s policy, proxy, runtime, and login.",
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

// Leave the selectable code visible everywhere; enhance with copying when supported.
const copyButton = document.getElementById("copy-install");
if (navigator.clipboard && window.isSecureContext) {
  copyButton.hidden = false;
  copyButton.addEventListener("click", async () => {
    const status = document.getElementById("copy-status");
    try {
      await navigator.clipboard.writeText(document.getElementById("install-code").textContent);
      copyButton.textContent = "Copied ✓";
      status.textContent = "Installer command copied. Run it from the checkout containing install.sh.";
      window.setTimeout(() => { copyButton.textContent = "Copy command"; }, 2500);
    } catch {
      status.textContent = "Copying was unavailable. Select and copy the installer command.";
      copyButton.textContent = "Select code to copy";
    }
  });
}
