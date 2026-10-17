"use strict";

const COOLDOWN_MS = 5_000;

const params = new URLSearchParams(location.search);
const target = params.get("url") || "";
const verdict = params.get("verdict") === "suspicious" ? "suspicious" : "dangerous";
const rawScore = params.get("score");
const score = rawScore && /^\d{1,3}$/.test(rawScore) ? Math.min(100, Number(rawScore)) : null;
const source = params.get("source");
const scannedAt = Number(params.get("ts")) || Date.now();

let parsed = null;
let domain = "";
let safeTarget = "";
try {
  const u = new URL(target);
  if (u.protocol === "http:" || u.protocol === "https:") {
    parsed = u;
    domain = u.hostname.replace(/^www\./i, "");
    safeTarget = u.toString();
  }
} catch {
  /* missing or malformed target */
}

/* ------------------------------------------------------------------ utils */

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) if (child) node.append(child);
  return node;
}

function parseReasons() {
  const list = [];
  const raw = params.get("reasons");
  if (raw) {
    try {
      const decoded = JSON.parse(raw);
      if (Array.isArray(decoded)) list.push(...decoded);
    } catch {
      list.push(...raw.split("|")); // tolerate pipe-separated input
    }
  }
  const single = params.get("reason");
  if (single) list.push(single);
  const clean = list.filter((r) => typeof r === "string" && r.trim()).map((r) => r.trim().slice(0, 200));
  return [...new Set(clean)].slice(0, 10);
}

/* --------------------------------------------------------- classification */

// Each rule maps a reason (from the scanner or local URL inspection) to a
// severity tag, the real-world risks it feeds, and a plain-language explanation.
const RULES = [
  {
    id: "lookalike",
    re: /punycode|xn--|look-?alike|homograph|typosquat|impersonat/i,
    tag: "high",
    risks: ["credential", "financial"],
    detail: "The address imitates a trusted brand using look-alike characters or spellings, so it can pass a quick glance.",
  },
  {
    id: "userinfo",
    re: /embeds credentials|before the hostname/i,
    tag: "high",
    risks: ["credential"],
    detail: "Text before an @ in a URL is ignored by the browser, a trick used to disguise the real destination.",
  },
  {
    id: "known-bad",
    re: /phish|malware|malicious|blocklist|known threat|exploit|drive-?by/i,
    tag: "high",
    risks: ["credential", "malware"],
    detail: "This destination matches known threat intelligence or exhibits malicious behaviour.",
  },
  {
    id: "payload",
    re: /download|executable|payload|\.(exe|dmg|apk|scr|msi|pkg)\b/i,
    tag: "high",
    risks: ["malware"],
    detail: "The link points at a file that can run code on your device if opened.",
  },
  {
    id: "raw-ip",
    re: /raw ip|ip address/i,
    tag: "network",
    risks: ["malware", "credential"],
    detail: "Legitimate services almost always use a domain name. Bare IPs are common for throwaway attack infrastructure.",
  },
  {
    id: "plaintext",
    re: /not encrypted|unencrypted|\(http\)|certificate|tls|ssl/i,
    tag: "network",
    risks: ["credential", "financial"],
    detail: "Anything you send, including passwords and card numbers, can be read or modified in transit.",
  },
  {
    id: "redirect",
    re: /redirect/i,
    tag: "network",
    risks: ["credential", "malware"],
    detail: "The page bounces through intermediate hosts, a pattern used to evade filters.",
  },
  {
    id: "financial-bait",
    re: /wallet|payment|billing|card|bank|crypto|invoice|refund/i,
    tag: "heuristic",
    risks: ["financial"],
    detail: "The address references payments or wallets, a common lure for card capture and wallet-draining scams.",
  },
  {
    id: "credential-bait",
    re: /credential|bait|login|sign-?in|verify|password|account/i,
    tag: "heuristic",
    risks: ["credential"],
    detail: "Words like \"login\", \"secure\" or \"verify\" in an unfamiliar domain are a hallmark of fake sign-in pages.",
  },
  {
    id: "tld",
    re: /top-level domain|\btld\b|abuse/i,
    tag: "heuristic",
    risks: ["malware", "financial"],
    detail: "This domain ending is cheap to register and disproportionately used for short-lived scam sites.",
  },
  {
    id: "structure",
    re: /hyphen|subdomain|unusually long|hostname is/i,
    tag: "heuristic",
    risks: ["credential"],
    detail: "Long, hyphenated or deeply nested hostnames are used to bury a fake brand name inside a real-looking address.",
  },
  {
    id: "info",
    re: /no known risk|reviewed by|manual test|flagged by trustline/i,
    tag: "info",
    risks: [],
    detail: "",
  },
];

const TAG_LABELS = { high: "HIGH RISK", network: "NETWORK", heuristic: "HEURISTIC", info: "INFO" };
const TAG_ORDER = { high: 0, network: 1, heuristic: 2, info: 3 };

const fallbackRule = {
  id: "other",
  tag: "heuristic",
  risks: ["credential"],
  detail: "TrustLine's scanner flagged this signal as part of its risk assessment.",
};

function classify(text) {
  return RULES.find((r) => r.re.test(text)) ?? fallbackRule;
}

// Lightweight client-side inspection so the breakdown stays useful even when
// the scanner only passed a single reason (or none).
const RISKY_TLDS = new Set(["zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "rest"]);
const BAIT_HOST = /(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|recover)/i;
const MONEY_URL = /(wallet|payment|billing|bank|crypto|invoice|refund)/i;

function inspectUrl(u) {
  if (!u) return [];
  const host = u.hostname.toLowerCase();
  const found = [];
  if (u.protocol === "http:") found.push("Connection is not encrypted (HTTP)");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) found.push("Site is served from a raw IP address");
  if (host.includes("xn--")) found.push("Domain uses punycode, a common look-alike trick");
  if (u.username || u.password) found.push("URL embeds credentials before the hostname");
  const bait = host.match(BAIT_HOST);
  if (bait) found.push(`Domain contains credential-bait keyword "${bait[1]}"`);
  const money = (host + u.pathname).match(MONEY_URL);
  if (money) found.push(`Address references payments ("${money[1]}")`);
  if (/\.(exe|dmg|apk|scr|msi|pkg)$/i.test(u.pathname)) found.push("Link points directly at an executable download");
  if ((host.match(/-/g) || []).length >= 3) found.push("Domain contains many hyphens");
  if (host.split(".").length > 4) found.push("Unusually deep subdomain chain");
  const tld = host.split(".").pop();
  if (RISKY_TLDS.has(tld)) found.push(`Top-level domain ".${tld}" is frequently associated with abuse`);
  if (host.length > 40) found.push("Hostname is unusually long");
  return found;
}

function buildFindings() {
  const findings = [];
  const seen = new Set();
  for (const text of parseReasons()) {
    const rule = classify(text);
    findings.push({ text, rule, origin: source === "daemon" ? "TrustLine daemon" : "TrustLine scanner" });
    seen.add(rule.id);
  }
  for (const text of inspectUrl(parsed)) {
    const rule = classify(text);
    if (seen.has(rule.id)) continue;
    findings.push({ text, rule, origin: "Local URL inspection" });
    seen.add(rule.id);
  }
  const actionable = findings.filter((f) => f.rule.tag !== "info");
  if (actionable.length === 0) {
    findings.push({
      text: verdict === "dangerous" ? "Low trust score from TrustLine's analysis" : "Below-threshold trust score",
      rule: fallbackRule,
      origin: "TrustLine scanner",
    });
  }
  return findings.sort((a, b) => TAG_ORDER[a.rule.tag] - TAG_ORDER[b.rule.tag]);
}

/* ---------------------------------------------------------------- render */

const RISKS = [
  {
    id: "credential",
    title: "Credential & identity theft",
    summary: "Fake sign-in forms can harvest what you type and hijack your accounts.",
    items: ["Passwords and usernames", "Session tokens and cookies", "One-time 2FA codes"],
  },
  {
    id: "financial",
    title: "Financial & payment fraud",
    summary: "Checkout and wallet pages can be cloned to take money directly.",
    items: ["Card capture on fake checkouts", "Crypto wallet draining approvals", "Fake billing or refund scams"],
  },
  {
    id: "malware",
    title: "Malware & payload execution",
    summary: "The page itself can attempt to run code against your browser or device.",
    items: ["Drive-by downloads", "Malicious scripts and extensions", "Browser exploitation"],
  },
];

function renderHeader() {
  document.body.dataset.status = verdict;
  document.title = `${domain || "Site"} blocked · TrustLine`;
  document.getElementById("title").textContent =
    verdict === "suspicious" ? "This site looks suspicious" : "This site may be dangerous";
  document.getElementById("eyebrow").textContent =
    verdict === "suspicious" ? "TrustLine paused this page" : "TrustLine blocked this page";
  document.getElementById("domain").textContent = domain || "unknown host";

  const time = document.getElementById("scan-time");
  const when = new Date(scannedAt);
  time.dateTime = when.toISOString();
  time.textContent = when.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
  document.getElementById("scan-source").textContent =
    source === "daemon" ? "Source: TrustLine daemon" : source === "mock" ? "Source: fallback analyzer" : "Source: unknown";

  document.getElementById("score").textContent = score === null ? "--" : String(score);
  const meter = document.getElementById("meter");
  meter.setAttribute("aria-valuenow", String(score ?? 0));
  requestAnimationFrame(() => {
    document.getElementById("meter-fill").style.width = `${score ?? 0}%`;
  });
}

function renderFindings(findings) {
  const list = document.getElementById("findings");
  list.replaceChildren(
    ...findings.map(({ text, rule, origin }) =>
      el("li", { class: "finding" }, [
        el("span", { class: "tag", dataset: { tag: rule.tag }, text: TAG_LABELS[rule.tag] }),
        el("p", { class: "finding-title", text }),
        rule.detail ? el("p", { class: "finding-detail", text: rule.detail }) : null,
        el("p", { class: "finding-origin", text: origin }),
      ])
    )
  );
  const n = findings.filter((f) => f.rule.tag !== "info").length;
  document.getElementById("finding-count").textContent = `${n} signal${n === 1 ? "" : "s"}`;
}

function renderRisks(findings) {
  const container = document.getElementById("risks");
  container.replaceChildren(
    ...RISKS.map((risk) => {
      const linked = findings.filter((f) => f.rule.risks.includes(risk.id));
      const high = linked.some((f) => f.rule.tag === "high");
      const level = high || linked.length >= 2 ? "high" : linked.length === 1 ? "elevated" : "possible";
      const levelLabel = { high: "HIGH LIKELIHOOD", elevated: "ELEVATED", possible: "POSSIBLE" }[level];
      return el("article", { class: "risk", dataset: { level } }, [
        el("span", { class: "risk-level", text: levelLabel }),
        el("h3", { text: risk.title }),
        el("p", { text: risk.summary }),
        el("ul", {}, risk.items.map((item) => el("li", { text: item }))),
        el("p", {
          class: "risk-links",
          text: linked.length
            ? `Linked to ${linked.length} flagged signal${linked.length === 1 ? "" : "s"}`
            : "No direct signal, still possible",
        }),
      ]);
    })
  );
}

function renderMeta() {
  const rows = [];
  const add = (label, value, flag) => rows.push(el("div", {}, [el("dt", { text: label }), el("dd", { text: value, dataset: flag ? { flag } : {} })]));

  add("Destination", safeTarget || target || "Unknown");
  if (parsed) {
    const https = parsed.protocol === "https:";
    add("Protocol", https ? "HTTPS (encrypted)" : "HTTP (unencrypted)", https ? "ok" : "bad");
    add("Hostname", parsed.hostname);
    add("Port", parsed.port || (https ? "443 (default)" : "80 (default)"));
    add("Path", parsed.pathname + parsed.search || "/");
  }
  add("Verdict", verdict.toUpperCase(), verdict === "dangerous" ? "bad" : "warn");
  add("Trust score", score === null ? "Unavailable" : `${score}/100`);
  add(
    "Scan engine",
    source === "daemon"
      ? "TrustLine daemon (online)"
      : source === "mock"
        ? "Fallback heuristic analyzer (daemon offline)"
        : "Unknown",
    source === "daemon" ? "ok" : "warn"
  );
  document.getElementById("meta").replaceChildren(...rows);
}

/* ------------------------------------------------------------ navigation */

document.getElementById("back").addEventListener("click", () => {
  if (history.length > 2) history.go(-2);
  else location.replace("about:blank");
});

/* ---------------------------------------------------------- friction gate */

const ack = document.getElementById("ack");
const stepAck = document.getElementById("step-ack");
const stepVerify = document.getElementById("step-verify");
const stepProceed = document.getElementById("step-proceed");
const input = document.getElementById("confirm-host");
const hint = document.getElementById("confirm-hint");
const cooldownFill = document.getElementById("cooldown-fill");
const cooldownText = document.getElementById("cooldown-text");
const proceed = document.getElementById("proceed");

let cooldownStart = 0;
let cooldownDone = false;
let cooldownFrame = 0;

function hostMatches() {
  const typed = input.value.trim().toLowerCase();
  return Boolean(parsed) && (typed === domain.toLowerCase() || typed === parsed.hostname.toLowerCase());
}

function updateGate() {
  const acknowledged = ack.checked;
  const typed = input.value.trim();
  const match = hostMatches();

  stepAck.dataset.state = acknowledged ? "done" : "active";
  stepVerify.dataset.state = !acknowledged ? "locked" : cooldownDone && match ? "done" : "active";
  input.disabled = !acknowledged;
  input.dataset.match = !typed ? "" : match ? "yes" : "no";
  if (acknowledged && typed && !match) hint.textContent = "Doesn't match the flagged hostname yet.";
  else hint.textContent = "Pasting is disabled. Type it out by hand.";

  const unlocked = acknowledged && cooldownDone && match && Boolean(safeTarget);
  stepProceed.dataset.state = unlocked ? "active" : "locked";
  proceed.disabled = !unlocked;
}

function tickCooldown() {
  const elapsed = Date.now() - cooldownStart;
  const pct = Math.min(1, elapsed / COOLDOWN_MS);
  cooldownFill.style.width = `${pct * 100}%`;
  if (pct >= 1) {
    cooldownDone = true;
    cooldownText.textContent = "Cooldown complete";
    updateGate();
    return;
  }
  cooldownText.textContent = `Cooldown: ${Math.ceil((COOLDOWN_MS - elapsed) / 1000)}s remaining`;
  cooldownFrame = requestAnimationFrame(tickCooldown);
}

ack.addEventListener("change", () => {
  cancelAnimationFrame(cooldownFrame);
  cooldownDone = false;
  if (ack.checked) {
    cooldownStart = Date.now();
    tickCooldown();
    input.disabled = false;
    input.focus();
  } else {
    // Unchecking resets the whole gate.
    input.value = "";
    cooldownFill.style.width = "0";
    cooldownText.textContent = "Cooldown starts after step 1";
  }
  updateGate();
});

input.addEventListener("input", updateGate);
for (const evt of ["paste", "drop"]) {
  input.addEventListener(evt, (e) => {
    e.preventDefault();
    hint.textContent = "Pasting is disabled. Type the hostname by hand.";
  });
}

proceed.addEventListener("click", async () => {
  if (proceed.disabled || !safeTarget) return;
  if (typeof chrome !== "undefined" && chrome.runtime?.id) {
    const res = await chrome.runtime.sendMessage({ type: "allowAndProceed", url: safeTarget });
    if (res?.ok) return;
  }
  location.href = safeTarget;
});

/* ------------------------------------------------------------------ init */

const findings = buildFindings();
renderHeader();
renderFindings(findings);
renderRisks(findings);
renderMeta();
document.getElementById("expected-host").textContent = domain ? `Flagged: ${domain}` : "No valid destination to verify";
proceed.textContent = domain ? `Allowlist for this session & Proceed to ${domain}` : "No valid destination";
updateGate();
