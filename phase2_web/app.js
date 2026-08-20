const form = document.getElementById("requestForm");
const resource = document.getElementById("resource");
const authorityMode = document.getElementById("authorityMode");
const evidenceMode = document.getElementById("evidenceMode");
const evaluateButton = document.getElementById("evaluateButton");
const health = document.getElementById("health");

const setText = (id, value) => {
  document.getElementById(id).textContent = value;
};

function synchronizeConstraints(changed) {
  if (changed === evidenceMode && evidenceMode.value === "unavailable") {
    authorityMode.value = "missing";
  }
  if (changed === authorityMode && authorityMode.value !== "missing") {
    evidenceMode.value = "verified";
  }
  if (authorityMode.value === "consumed_grant_replay") {
    resource.value = "sandbox:demo";
    evidenceMode.value = "verified";
  }
}

function showResult(payload) {
  const verdict = document.getElementById("verdict");
  verdict.textContent = payload.verdict;
  verdict.className = `verdict ${payload.verdict.toLowerCase()}`;
  setText("resultTitle", payload.reason_codes.join(" · "));
  setText(
    "resultStatus",
    payload.verdict === "ADMIT"
      ? "The exact request, trusted grant and receiver policy intersect. Admission is not execution."
      : "The receiver withheld capability. Inspect the reason and signed receipt below."
  );
  setText("effectiveResource", payload.effective_scope.resources.join(", ") || "none");
  setText("effectiveAction", payload.effective_scope.actions.join(", ") || "none");
  setText("maxRuns", payload.effective_scope.constraints.max_runs ?? "none");
  setText("actionExecuted", String(payload.action_executed));
  setText("worldTruth", payload.world_truth);
  setText("receiptId", payload.receipt_id);
  setText(
    "receiptVerified",
    payload.receipt_verified ? "✓ Independently verified" : "Receipt verification failed"
  );
  document.getElementById("receiptVerified").className =
    payload.receipt_verified ? "verification verified" : "verification failed";
  setText("rawResult", JSON.stringify(payload, null, 2));
}

function showError(payload, status) {
  const verdict = document.getElementById("verdict");
  verdict.textContent = "REJECTED";
  verdict.className = "verdict deny";
  setText("resultTitle", payload.error || "request_failed");
  setText("resultStatus", `HTTP ${status}. The invalid command was not evaluated or executed.`);
  setText("receiptVerified", "No authoritative receipt");
  document.getElementById("receiptVerified").className = "verification failed";
  setText("effectiveResource", "none");
  setText("effectiveAction", "none");
  setText("maxRuns", "none");
  setText("actionExecuted", "false");
  setText("worldTruth", "OUT_OF_SCOPE");
  setText("receiptId", "none");
  setText("rawResult", JSON.stringify(payload, null, 2));
}

async function evaluateRequest() {
  evaluateButton.disabled = true;
  evaluateButton.textContent = "Evaluating…";
  setText("resultStatus", "Computing and independently verifying a new signed receipt…");
  try {
    const response = await fetch("/api/v1/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        resource: resource.value,
        authority_mode: authorityMode.value,
        evidence_mode: evidenceMode.value,
      }),
    });
    const payload = await response.json();
    if (!response.ok) {
      showError(payload, response.status);
      return;
    }
    showResult(payload);
  } catch (error) {
    showError({ error: "local_kernel_unreachable", detail: error.name }, 0);
  } finally {
    evaluateButton.disabled = false;
    evaluateButton.textContent = "Evaluate exact request";
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  evaluateRequest();
});

[resource, authorityMode, evidenceMode].forEach((control) => {
  control.addEventListener("change", () => synchronizeConstraints(control));
});

document.querySelectorAll(".preset").forEach((button) => {
  button.addEventListener("click", () => {
    resource.value = button.dataset.resource;
    authorityMode.value = button.dataset.authority;
    evidenceMode.value = button.dataset.evidence;
    evaluateRequest();
  });
});

fetch("/api/v1/health")
  .then((response) => response.json().then((payload) => ({ response, payload })))
  .then(({ response, payload }) => {
    if (!response.ok || payload.status !== "ok" || payload.action_execution !== false) {
      throw new Error("unsafe-health-state");
    }
    health.textContent = "● Local kernel connected · action execution disabled";
    health.classList.add("connected");
  })
  .catch(() => {
    health.textContent = "× Local kernel unavailable";
    health.classList.add("failed");
    evaluateButton.disabled = true;
  });
