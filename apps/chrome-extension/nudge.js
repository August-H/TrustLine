"use strict";

/*
 * Deep scan prompt, injected into a page the loading screen let through with a
 * passing but unsure score. background.js runs trustLineNudge() in the page's
 * isolated world with chrome.scripting.executeScript, so this function must not
 * use anything outside itself. It draws in a closed shadow root so the page's
 * styles can't reach it, and ignores clicks the page scripts fake.
 */
function trustLineNudge() {
  const HOST_ID = "trustline-deep-scan-prompt";
  if (document.getElementById(HOST_ID)) return;

  const host = document.createElement("div");
  host.id = HOST_ID;
  host.style.cssText = "all: initial; position: fixed; top: 0; right: 0; z-index: 2147483647;";
  const root = host.attachShadow({ mode: "closed" });

  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    .card {
      position: fixed; top: 12px; right: 16px; width: 300px; box-sizing: border-box;
      display: grid; grid-template-columns: 22px 1fr 20px; gap: 10px; align-items: start;
      padding: 14px 12px 14px 14px; border-radius: 10px;
      background: #1b2430; color: #ffffff;
      font: 15px/1.4 -apple-system, "Segoe UI", system-ui, sans-serif;
      box-shadow: 0 10px 30px rgb(0 0 0 / 0.28), 0 2px 6px rgb(0 0 0 / 0.2);
      animation: drop 180ms ease-out;
    }
    /* Notch pointing up at the toolbar, where the TrustLine icon sits. */
    .card::before {
      content: ""; position: absolute; top: -6px; right: 26px; width: 12px; height: 12px;
      background: #1b2430; transform: rotate(45deg); border-radius: 2px;
    }
    @keyframes drop { from { opacity: 0; transform: translateY(-6px); } }
    @media (prefers-reduced-motion: reduce) { .card { animation: none; } }
    .icon { width: 22px; height: 22px; margin-top: 1px; fill: #f59e0b; }
    .card[data-state="safe"] .icon { fill: #34d399; }
    .card[data-state="blocked"] .icon { fill: #f87171; }
    .title { margin: 0; font-weight: 700; }
    .body { margin: 2px 0 0; color: #d6dce4; }
    .link {
      all: unset; cursor: pointer; color: #ffffff; font-weight: 700;
      text-decoration: underline; text-underline-offset: 2px;
    }
    .link:focus-visible, .close:focus-visible { outline: 2px solid #f59e0b; outline-offset: 2px; border-radius: 2px; }
    .close {
      all: unset; cursor: pointer; width: 20px; height: 20px; display: grid; place-items: center;
      color: #9aa5b4; font-size: 18px; line-height: 1; border-radius: 4px;
    }
    .close:hover { color: #ffffff; background: rgb(255 255 255 / 0.1); }
  `;

  const card = document.createElement("div");
  card.className = "card";
  card.setAttribute("role", "status");
  card.setAttribute("aria-live", "polite");
  card.dataset.state = "offer";

  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("viewBox", "0 0 24 24");
  icon.setAttribute("aria-hidden", "true");
  icon.classList.add("icon");
  const shield = document.createElementNS("http://www.w3.org/2000/svg", "path");
  shield.setAttribute("d", "M12 2 4 5v6c0 5.1 3.4 9.4 8 11 4.6-1.6 8-5.9 8-11V5l-8-3Z");
  icon.append(shield);

  const text = document.createElement("div");
  const title = document.createElement("p");
  title.className = "title";
  title.textContent = "This website may not be safe";
  const body = document.createElement("p");
  body.className = "body";
  const link = document.createElement("button");
  link.type = "button";
  link.className = "link";
  link.textContent = "Click Here";
  body.append(link, " to run a deep scan");
  text.append(title, body);

  const close = document.createElement("button");
  close.type = "button";
  close.className = "close";
  close.setAttribute("aria-label", "Dismiss");
  close.textContent = "×";

  card.append(icon, text, close);
  root.append(style, card);
  (document.body || document.documentElement).append(host);

  let timer = 0;
  const dismiss = () => {
    clearTimeout(timer);
    host.remove();
  };
  const show = (state, heading, message, autoClose) => {
    card.dataset.state = state;
    title.textContent = heading;
    body.textContent = message;
    clearTimeout(timer);
    if (autoClose) timer = setTimeout(dismiss, autoClose);
  };

  close.addEventListener("click", (event) => {
    if (event.isTrusted) dismiss();
  });

  link.addEventListener("click", async (event) => {
    if (!event.isTrusted) return; // the page's own scripts can't start a scan
    show("scanning", "Running a deep scan…",
      "Opening this page in a secure cloud browser. This can take up to a minute.");
    try {
      const res = await chrome.runtime.sendMessage({ type: "nudgeDeepScan" });
      if (!res?.ok) throw new Error(res?.error || "No response from TrustLine");
      const { verdict, reason } = res.data;
      if (verdict === "safe") {
        show("safe", "Deep scan found no scam", reason || "TrustLine checked this page in a cloud browser.", 8000);
      } else if (verdict === "dangerous") {
        show("blocked", "This page was blocked", reason || "TrustLine found signs of a scam.");
      } else {
        show("offer", "The deep scan couldn't decide", reason || "Be careful entering any personal details here.");
      }
    } catch (err) {
      show("offer", "Deep scan unavailable", String(err?.message || err));
    }
  });
}
