"use strict";

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
      window.setTimeout(() => { copyButton.textContent = "Copy"; }, 2500);
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
    if (!response.ok) return;
    const { tag_name: tag } = await response.json();
    if (typeof tag === "string" && /^v\d+\.\d+\.\d+$/.test(tag)) {
      document.getElementById("release-state").textContent = "Latest release: " + tag + ".";
    }
  })
  .catch(() => {});
