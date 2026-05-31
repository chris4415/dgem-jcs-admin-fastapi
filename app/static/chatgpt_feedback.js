// DG-E&M ChatGPT feedback copy v001

function cleanText(value) {
  return (value || "").replace(/\s+/g, " ").trim();
}

function collectList(selector, formatter, limit = 20) {
  const nodes = Array.from(document.querySelectorAll(selector)).slice(0, limit);
  return nodes.map(formatter).filter(Boolean);
}

function getCurrentUserText() {
  const userbar = document.querySelector(".userbar");
  return cleanText(userbar ? userbar.innerText : "");
}

function getActiveTop() {
  const active = document.querySelector(".nav a.active");
  return cleanText(active ? active.innerText : "");
}

function buildChatGPTPacket() {
  const h1 = cleanText(document.querySelector("h1")?.innerText || document.title);
  const subtitle = cleanText(document.querySelector(".hero p")?.innerText || "");
  const route = window.location.pathname;
  const activeTop = getActiveTop();
  const userText = getCurrentUserText();

  const statusLines = collectList(".status-pill", (node) => {
    const label = cleanText(node.querySelector(".label")?.innerText || "");
    const value = cleanText(node.querySelector(".value")?.innerText || "");
    return label ? `- ${label}: ${value}` : "";
  });

  const cardLines = collectList(".card", (node) => {
    const title = cleanText(node.querySelector("h2, h3")?.innerText || "");
    const text = cleanText(node.querySelector("p")?.innerText || "");
    const badge = cleanText(node.querySelector(".badge")?.innerText || "");
    if (!title) return "";
    return `- ${title}${badge ? " [" + badge + "]" : ""}: ${text}`;
  }, 30);

  const timestamp = new Date().toISOString();

  return [
    "DG-E&M JCS-admin Feedback Packet",
    "",
    `Timestamp: ${timestamp}`,
    `Page: ${h1}`,
    `Subtitle: ${subtitle}`,
    `Route: ${route}`,
    `Top Area: ${activeTop}`,
    `User/Role: ${userText}`,
    "",
    "Visible Status:",
    ...(statusLines.length ? statusLines : ["- No status strip detected on this page."]),
    "",
    "Visible Cards / Workflow Items:",
    ...(cardLines.length ? cardLines : ["- No cards detected on this page."]),
    "",
    "Useful Current Links:",
    `- Current page: ${window.location.href}`,
    `- Dashboard: ${window.location.origin}/dashboard`,
    `- API test: ${window.location.origin}/api/chat/test`,
    `- Runner test: ${window.location.origin}/runner/test`,
    `- Audit dashboard: ${window.location.origin}/dashboards/audit`,
    "",
    "Question / instruction for ChatGPT:",
    ""
  ].join("\n");
}

async function copyForChatGPT() {
  const packet = buildChatGPTPacket();
  const assistantBox = document.getElementById("dgem-ai-assistance-box");
  const packetBox = document.getElementById("dgem-feedback-packet-box");
  const status = document.getElementById("dgem-copy-status");

  if (assistantBox) assistantBox.value = packet;
  if (packetBox) packetBox.value = packet;

  let copied = false;

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(packet);
      copied = true;
    }
  } catch (err) {
    copied = false;
  }

  if (!copied && packetBox) {
    packetBox.style.display = "block";
    packetBox.focus();
    packetBox.select();
    try {
      copied = document.execCommand("copy");
    } catch (err) {
      copied = false;
    }
  }

  if (status) {
    status.innerText = copied
      ? "Copied for ChatGPT. Paste into ChatGPT when ready."
      : "Packet prepared. Browser blocked clipboard copy; select the text and copy manually.";
    status.className = copied ? "workbench-status good" : "workbench-status warn";
  }
}

function showFeedbackPacket() {
  const packet = buildChatGPTPacket();
  const packetBox = document.getElementById("dgem-feedback-packet-box");
  const assistantBox = document.getElementById("dgem-ai-assistance-box");
  const status = document.getElementById("dgem-copy-status");

  if (packetBox) {
    packetBox.value = packet;
    packetBox.style.display = "block";
    packetBox.focus();
    packetBox.select();
  }

  if (assistantBox) assistantBox.value = packet;

  if (status) {
    status.innerText = "Feedback packet displayed and selected.";
    status.className = "workbench-status";
  }
}

function fillApiConsole() {
  const apiBox = document.getElementById("dgem-api-console-box");
  if (!apiBox) return;

  apiBox.value = [
    "Governed API Console",
    "",
    `Page: ${cleanText(document.querySelector("h1")?.innerText || document.title)}`,
    `Route: ${window.location.pathname}`,
    `User/Role: ${getCurrentUserText()}`,
    "",
    "Current available proof actions:",
    "- /api/chat/test",
    "- /runner/test",
    "",
    "Boundary:",
    "- AI may propose actions.",
    "- Only registered runner actions may execute.",
    "- Results must be audited.",
    "",
    "Pending:",
    "- Action Console page",
    "- Operational Logs page",
    "- DuckDB read-only query page"
  ].join("\n");
}


function escapeHtmlForPopout(value) {
  return (value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function openWorkbenchPopout(kind) {
  let sourceId = "";
  let title = "";
  let subtitle = "";

  if (kind === "ai") {
    sourceId = "dgem-ai-assistance-box";
    title = "DG-E&M AI Assistance Popout";
    subtitle = "Snapshot of the AI Assistance work area.";
  } else if (kind === "api") {
    sourceId = "dgem-api-console-box";
    title = "DG-E&M Governed API Console Popout";
    subtitle = "Snapshot of the governed API/action console.";
  } else {
    return;
  }

  const source = document.getElementById(sourceId);
  const content = source ? source.value : "";
  const openedAt = new Date().toISOString();

  const w = window.open("", "_blank");
  if (!w) {
    alert("Popout was blocked by the browser. Allow popups for this local site and try again.");
    return;
  }

  w.document.open();
  w.document.write(`<!doctype html>
<html>
<head>
  <title>${escapeHtmlForPopout(title)}</title>
  <style>
    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: #0b0f16;
      color: #e8eef8;
    }
    header {
      background: #121820;
      border-bottom: 1px solid #263549;
      padding: 16px 22px;
    }
    h1 {
      margin: 0;
      font-size: 22px;
    }
    p {
      color: #9eb0c8;
    }
    main {
      padding: 18px 22px;
    }
    textarea {
      width: 100%;
      height: calc(100vh - 190px);
      background: #07101b;
      color: #e8eef8;
      border: 1px solid #263549;
      border-radius: 10px;
      padding: 12px;
      font-family: Consolas, monospace;
      font-size: 14px;
      box-sizing: border-box;
      white-space: pre;
    }
    button {
      background: #123456;
      color: #ffffff;
      border: 1px solid #55a7ff;
      border-radius: 8px;
      padding: 9px 13px;
      cursor: pointer;
      margin-right: 8px;
      margin-bottom: 12px;
    }
    .meta {
      color: #9eb0c8;
      font-size: 13px;
      margin-bottom: 12px;
    }
  </style>
</head>
<body>
  <header>
    <h1>${escapeHtmlForPopout(title)}</h1>
    <p>${escapeHtmlForPopout(subtitle)}</p>
  </header>
  <main>
    <div class="meta">Opened: ${escapeHtmlForPopout(openedAt)}</div>
    <button onclick="document.getElementById('popoutBox').select(); document.execCommand('copy');">Copy Text</button>
    <button onclick="document.getElementById('popoutBox').select();">Select All</button>
    <button onclick="window.close();">Close</button>
    <textarea id="popoutBox">${escapeHtmlForPopout(content)}</textarea>
  </main>
</body>
</html>`);
  w.document.close();
}


document.addEventListener("DOMContentLoaded", () => {
  const copyBtn = document.getElementById("dgem-copy-chatgpt-btn");
  const showBtn = document.getElementById("dgem-show-packet-btn");
  const popoutAiLink = document.getElementById("dgem-popout-ai-link");
  const popoutApiLink = document.getElementById("dgem-popout-api-link");
  const popoutAiBtn = document.getElementById("dgem-popout-ai-btn");
  const popoutApiBtn = document.getElementById("dgem-popout-api-btn");

  if (copyBtn) copyBtn.addEventListener("click", copyForChatGPT);
  if (showBtn) showBtn.addEventListener("click", showFeedbackPacket);
  if (popoutAiLink) popoutAiLink.addEventListener("click", (event) => { event.preventDefault(); openWorkbenchPopout("ai"); });
  if (popoutApiLink) popoutApiLink.addEventListener("click", (event) => { event.preventDefault(); openWorkbenchPopout("api"); });
  if (popoutAiBtn) popoutAiBtn.addEventListener("click", () => openWorkbenchPopout("ai"));
  if (popoutApiBtn) popoutApiBtn.addEventListener("click", () => openWorkbenchPopout("api"));

  fillApiConsole();
});
