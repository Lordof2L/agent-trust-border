const steps = [
  {
    step: "capability-only",
    verdict: "UNKNOWN",
    reason: "MISSING_AUTHORIZATION",
    explanation: "A declared deploy capability is not a receiver-trusted operation grant. The border emits an exact challenge and refuses admission.",
    resources: [], actions: [], maxRuns: null,
    receipt: "br_886de803bb354350420ef1eff04c38c9ae074bd2268af8e9bea30eff99e00392",
    challenge: "ch_b76aff8d4302a828fe07b54f",
    file: "unknown-receipt.dsse.json"
  },
  {
    step: "exact-trusted-grant",
    verdict: "ADMIT",
    reason: "ALL_MANDATORY_CHECKS_PASS",
    explanation: "The exact receiver-issued challenge is bound into a trusted one-use grant. Scope is reduced to the request, grant and local-policy intersection.",
    resources: ["sandbox:demo"], actions: ["deploy"], maxRuns: 1,
    receipt: "br_8ce58bd9ca390aab2afab145d86a1d03d79d0213483a0af43df5f95c2b9730cc",
    challenge: "ch_b76aff8d4302a828fe07b54f",
    file: "admit-receipt.dsse.json"
  },
  {
    step: "production-scope-mutation",
    verdict: "DENY",
    reason: "SCOPE_EXCEEDED",
    explanation: "A valid sandbox grant cannot authorize a production resource. The receiver denies the widened request without executing it.",
    resources: [], actions: [], maxRuns: null,
    receipt: "br_c8dcb446b475a9a19b1f6b90f200316f292b57fea1811e2af630e96d906b59cc",
    challenge: "ch_13e8c522ffafc956ace96d32",
    file: "deny-receipt.dsse.json"
  },
  {
    step: "consumed-grant-replay",
    verdict: "DENY",
    reason: "REPLAY_DETECTED",
    explanation: "The one-use grant has already been consumed. Replay state blocks reuse and returns a signed denial receipt.",
    resources: [], actions: [], maxRuns: null,
    receipt: "br_b8051445ad5162eab32e792cf1e4241c346206a3fcb2cd67382800f614704abb",
    challenge: "ch_b76aff8d4302a828fe07b54f",
    file: "replay-receipt.dsse.json"
  }
];

const short = (value) => `${value.slice(0, 9)}…${value.slice(-4)}`;
const text = (id, value) => { document.getElementById(id).textContent = value; };

function selectStep(index) {
  const item = steps[index];
  document.querySelectorAll(".step-tab").forEach((tab, tabIndex) => {
    const active = tabIndex === index;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  const verdict = document.getElementById("verdict");
  verdict.textContent = item.verdict;
  verdict.className = `verdict ${item.verdict.toLowerCase()}`;
  text("stepLabel", item.step);
  text("reason", item.reason);
  text("explanation", item.explanation);
  text("resource", item.resources.join(", ") || "none");
  text("action", item.actions.join(", ") || "none");
  text("maxRuns", item.maxRuns === null ? "none" : String(item.maxRuns));
  text("receiptId", short(item.receipt));
  text("challengeId", short(item.challenge));
  document.getElementById("receiptLink").href = `evidence/${item.file}`;
}

document.querySelectorAll(".step-tab").forEach((tab) => {
  tab.addEventListener("click", () => selectStep(Number(tab.dataset.step)));
});
