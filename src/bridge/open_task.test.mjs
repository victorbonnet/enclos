// The script the bridge adds to Hermes's Kanban page (open_task.js), run
// against a stand-in page whose board is drawn later, as Hermes's bundle draws it.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("./open_task.js", import.meta.url), "utf8");

function page({ readyState = "complete" } = {}) {
  const state = { cards: [], clicks: [], observers: [], timers: [], listeners: {} };
  const card = (id) => ({
    getAttribute: (name) => (name === "data-task-id" ? id : null),
    scrollIntoView() {},
    click() { state.clicks.push(id); },
  });
  const context = {
    document: {
      readyState,
      body: {},
      addEventListener(event, listener) { state.listeners[event] = listener; },
      querySelectorAll(selector) {
        assert.equal(selector, ".hermes-kanban-card[data-task-id]");
        return state.cards;
      },
    },
    MutationObserver: class {
      constructor(callback) { this.callback = callback; this.watching = false; state.observers.push(this); }
      observe() { this.watching = true; }
      disconnect() { this.watching = false; }
    },
    setTimeout(callback, ms) { state.timers.push({ callback, ms }); },
  };
  return {
    state,
    run(task) { vm.runInNewContext(source.replace("TASK", JSON.stringify(task)), context); },
    draw(...ids) { state.cards = ids.map(card); },
    mutate() { state.observers.filter((o) => o.watching).forEach((o) => o.callback()); },
    watching() { return state.observers.some((o) => o.watching); },
  };
}

test("the script has one placeholder and nothing that ends its element", () => {
  assert.equal(source.split("TASK").length, 2);
  assert.ok(!source.includes("</"));
});

test("a card drawn later is tapped once, and only the one with the exact id", () => {
  const p = page();
  p.run("t1");
  p.mutate();
  assert.deepEqual(p.state.clicks, []);
  p.draw("t10", "t", "t1", "t2");
  p.mutate();
  p.mutate();
  assert.deepEqual(p.state.clicks, ["t1"]);
  assert.equal(p.watching(), false);
  p.draw("t1");
  p.mutate();
  assert.deepEqual(p.state.clicks, ["t1"], "the board drawn again after the details closed");
});

test("a card already drawn is tapped at once, with nothing left watching", () => {
  const p = page();
  p.draw("t1");
  p.run("t1");
  assert.deepEqual(p.state.clicks, ["t1"]);
  assert.equal(p.state.observers.length, 0);
});

test("a task the board does not show is never tapped, and watching stops", () => {
  const p = page();
  p.run("t1");
  p.draw("t2");
  p.mutate();
  assert.deepEqual(p.state.clicks, []);
  assert.equal(p.state.timers.length, 1);
  assert.equal(p.state.timers[0].ms, 30000);
  p.state.timers[0].callback();
  assert.equal(p.watching(), false);
});

test("a page still loading waits for its document", () => {
  const p = page({ readyState: "loading" });
  p.draw("t1");
  p.run("t1");
  assert.deepEqual(p.state.clicks, []);
  p.state.listeners.DOMContentLoaded();
  assert.deepEqual(p.state.clicks, ["t1"]);
});
