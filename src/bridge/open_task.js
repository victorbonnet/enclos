// Opens a held task's details on Hermes's Kanban page, which opens a task only
// when its card is tapped (task_board_proxy.rs writes the task's id in place
// of the placeholder below, and only an id that cannot leave a string).
(function () {
  var id = TASK, done = false, seen;
  function open() {
    var cards = document.querySelectorAll(".hermes-kanban-card[data-task-id]");
    for (var i = 0; i < cards.length; i++) {
      if (cards[i].getAttribute("data-task-id") === id) {
        done = true;
        cards[i].scrollIntoView({ block: "center", inline: "center" });
        cards[i].click();
        return true;
      }
    }
    return false;
  }
  function watch() {
    if (open()) return;
    seen = new MutationObserver(function () {
      if (!done && open()) seen.disconnect();
    });
    seen.observe(document.body, { childList: true, subtree: true });
    setTimeout(function () { seen.disconnect(); }, 30000);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", watch);
  else watch();
})();
