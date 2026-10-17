"use strict";

const params = new URLSearchParams(location.search);
const target = params.get("url") || "";
const verdict = params.get("verdict") === "suspicious" ? "suspicious" : "dangerous";
const score = params.get("score");
const reason = params.get("reason");

let domain = "this site";
let safeTarget = "";
try {
  const parsed = new URL(target);
  if (parsed.protocol === "http:" || parsed.protocol === "https:") {
    domain = parsed.hostname.replace(/^www\./i, "");
    safeTarget = parsed.toString();
  }
} catch {
  /* missing or malformed target */
}

document.body.dataset.status = verdict;
document.getElementById("title").textContent =
  verdict === "suspicious" ? "This site looks suspicious" : "This site may be dangerous";
document.getElementById("domain").textContent = domain;
document.getElementById("score").textContent = score && /^\d{1,3}$/.test(score) ? score : "--";
document.getElementById("reason").textContent = reason || "Flagged by TrustLine";
document.getElementById("url").textContent = safeTarget || "Unknown";
document.title = `${domain} blocked · TrustLine`;

document.getElementById("back").addEventListener("click", () => {
  if (history.length > 2) history.go(-2);
  else location.replace("about:blank");
});

const proceed = document.getElementById("proceed");
proceed.disabled = !safeTarget;
proceed.addEventListener("click", async () => {
  if (!safeTarget) return;
  if (typeof chrome !== "undefined" && chrome.runtime?.id) {
    const res = await chrome.runtime.sendMessage({ type: "allowAndProceed", url: safeTarget });
    if (res?.ok) return;
  }
  location.href = safeTarget;
});
