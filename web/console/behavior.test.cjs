const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const bundle = readFileSync(join(__dirname, "app.bundle.js"), "utf8");

function loadConsole(...pages) {
  const context = {
    URLSearchParams, CustomEvent,
    async fetch(path) {
      if (path === "/api/auth/me") return { ok: false };
      assert.ok(path.startsWith("/api/requests?"), path);
      return Response.json(pages.shift());
    },
    dispatchEvent() {}, setInterval() {},
    document: { addEventListener() {}, getElementById() {} },
    // Collect JSX children so assertions see the text emitted by the drawer.
    React: {
      createElement: (_type, _props, ...children) => children,
      useState: (initial) => [initial], useEffect() {},
    },
    ReactDOM: { createRoot: () => ({ render() {} }) },
  };
  context.window = context;
  vm.runInNewContext(bundle, context, { filename: "app.bundle.js" });
  return context;
}

test("paging older history preserves the selected event's CVE details", async () => {
  const id = "CVE-2025-1234";
  const event = { ts: "2026-01-02T00:00:00Z", reason: "cve_found", gate: "cve", blocked_by: ["cve"] };
  const ui = loadConsole(
    { requests: [{ ...event, cves: [{ id, severity: "HIGH", cvss: 8.2, summary: "Updated assessment" }] }], next_cursor: "older" },
    { requests: [{ ...event, ts: "2026-01-01T00:00:00Z", cves: [{ id, severity: "LOW", cvss: 3, summary: "Initial assessment" }] }] },
  );
  const { rows: [selected], nextCursor } = await ui.JOEI.pageRequests({});
  await ui.JOEI.pageRequests({ cursor: nextCursor });

  const text = ui.ThreatDrawer({ r: selected }).flat(Infinity);
  assert.ok(text.includes("Updated assessment"), "drawer lost the selected event's summary");
  assert.ok(text.includes("HIGH"));
  assert.ok(text.includes("8.2"));
  assert.deepEqual(Array.from(ui.jsonLines(selected).cve_ids), [id]);
});

test("blocked events without blocked_by use the recorded reason and gate", () => {
  const ui = loadConsole();
  for (const [reason, label] of [["scan_failed", "Scan failed"], ["future_policy", "future_policy"]]) {
    const r = { ts: new Date(), reason, gate: "cache", blocked_by: [] };
    assert.equal(ui.jsonLines(r).reason, reason);
    const text = ui.ThreatDrawer({ r }).flat(Infinity);
    assert.ok(text.includes(label), label);
    assert.ok(text.includes("Cache"));
  }
});
