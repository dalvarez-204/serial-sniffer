let state = { messages: [], analysis: {}, labels: {}, activeIndex: null };
let analysisSet = []; // [{index, hexBytes, ascii, expected: ""}]
let lastMatches = [];
let spanSelection = { start: null, end: null };
let lastCheckedIndex = null;

function formatTimestamp(epochSeconds) {
  const d = new Date(epochSeconds * 1000);
  const pad = (n, len = 2) => String(n).padStart(len, "0");
  const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  return `${date} ${time}`;
}

async function loadData() {
  const res = await fetch("/api/messages");
  state = { ...state, ...(await res.json()) };
  render();
}

function byteClass(groupKey, offset, analysis) {
  const info = analysis[groupKey];
  if (!info) return "";
  const checksum = info.checksum;
  if (checksum) {
    if (offset === checksum.checksum_offset) return "checksum";
    if (offset === checksum.end_offset) return "constant";
    const [start, end] = checksum.covers_offsets;
    if (offset >= start && offset <= end) return "data";
  }
  const variability = info.variability;
  if (Array.isArray(variability)) {
    const entry = variability.find((v) => v.offset === offset);
    if (entry) return entry.constant ? "constant" : "data";
  }
  return "";
}

function confidenceWarnings(analysis) {
  const warnings = [];
  for (const [key, info] of Object.entries(analysis)) {
    const n = info.sample_count;
    if (n < 2) {
      warnings.push(`"${key}": only ${n} sample — every byte will look "constant" by default, that's not real signal yet.`);
      continue;
    }
    const variesAtAll = Array.isArray(info.variability) && info.variability.some((v) => !v.constant);
    if (!variesAtAll) {
      warnings.push(`"${key}": ${n} samples but no byte ever changed — looks like the same message was sent repeatedly. Try varying the value you send (e.g. a sweep) so real data bytes stand out from real constants.`);
    }
  }
  return warnings;
}

function render() {
  const warnings = confidenceWarnings(state.analysis);
  const warningHtml = warnings.length
    ? `<div class="warning-banner"><strong>Low-confidence groups:</strong><ul>${warnings.map((w) => `<li>${w}</li>`).join("")}</ul></div>`
    : "";
  document.getElementById("confidence-warnings").innerHTML = warningHtml;

  const maxLen = Math.max(0, ...state.messages.map((m) => m.length));
  let html = "<table><thead><tr><th></th><th>#</th><th>dir</th><th>t</th>";
  for (let i = 0; i < maxLen; i++) html += `<th>${i}</th>`;
  html += "<th>ascii</th><th>label</th></tr></thead><tbody>";

  for (const msg of state.messages) {
    const label = state.labels[msg.index];
    const labeledClass = label ? "labeled" : "";
    html += `<tr class="message-row ${labeledClass}" data-index="${msg.index}">`;
    html += `<td><input type="checkbox" class="row-select" data-index="${msg.index}"></td>`;
    html += `<td>${msg.index}</td>`;
    html += `<td class="direction-${msg.direction}">${msg.direction}</td>`;
    html += `<td>${formatTimestamp(msg.timestamp)}</td>`;
    for (let i = 0; i < maxLen; i++) {
      const byte = msg.hex_bytes[i];
      if (byte === undefined) { html += "<td></td>"; continue; }
      const cls = byteClass(msg.group_key, i, state.analysis);
      html += `<td class="byte ${cls}">${byte}</td>`;
    }
    html += `<td>${msg.ascii}</td>`;
    html += `<td>${label ? label.name : ""}</td>`;
    html += "</tr>";
  }
  html += "</tbody></table>";
  document.getElementById("capture-table").innerHTML = html;

  document.querySelectorAll(".message-row").forEach((row) => {
    row.addEventListener("click", (e) => {
      if (e.target.classList.contains("row-select")) return;
      e.stopPropagation();
      openLabelPanel(Number(row.dataset.index));
    });
  });

  document.querySelectorAll(".row-select").forEach((cb) => {
    cb.addEventListener("click", (e) => {
      const index = Number(cb.dataset.index);
      if (e.shiftKey && lastCheckedIndex !== null) {
        const lo = Math.min(lastCheckedIndex, index);
        const hi = Math.max(lastCheckedIndex, index);
        document.querySelectorAll(".row-select").forEach((other) => {
          const otherIndex = Number(other.dataset.index);
          if (otherIndex >= lo && otherIndex <= hi) other.checked = cb.checked;
        });
      }
      lastCheckedIndex = index;
      updateSelectionUI();
    });
  });
}

function updateSelectionUI() {
  const anyChecked = document.querySelector(".row-select:checked") !== null;
  document.querySelectorAll(".message-row").forEach((row) => {
    const checked = row.querySelector(".row-select").checked;
    row.classList.toggle("dimmed", anyChecked && !checked);
  });
  document.getElementById("clear-selection").classList.toggle("hidden", !anyChecked);
}

document.getElementById("clear-selection").addEventListener("click", () => {
  document.querySelectorAll(".row-select").forEach((cb) => { cb.checked = false; });
  lastCheckedIndex = null;
  updateSelectionUI();
});

document.addEventListener("click", (e) => {
  const panel = document.getElementById("label-panel");
  if (!panel.classList.contains("hidden") && !panel.contains(e.target)) {
    panel.classList.add("hidden");
  }
});

function openLabelPanel(index) {
  state.activeIndex = index;
  const label = state.labels[index] || { name: "", note: "" };
  document.getElementById("label-index").textContent = index;
  document.getElementById("label-name").value = label.name;
  document.getElementById("label-notes").value = label.note;
  document.getElementById("label-panel").classList.remove("hidden");
}

document.getElementById("label-close").addEventListener("click", () => {
  document.getElementById("label-panel").classList.add("hidden");
});

document.getElementById("label-save").addEventListener("click", async () => {
  const index = state.activeIndex;
  const name = document.getElementById("label-name").value;
  const note = document.getElementById("label-notes").value;
  await fetch("/api/label", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ index, name, note }),
  });
  state.labels[index] = { name, note };
  document.getElementById("label-panel").classList.add("hidden");
  render();
});

document.getElementById("label-remove").addEventListener("click", async () => {
  const index = state.activeIndex;
  await fetch(`/api/label/${index}`, { method: "DELETE" });
  delete state.labels[index];
  document.getElementById("label-panel").classList.add("hidden");
  render();
});

document.getElementById("add-to-analysis").addEventListener("click", () => {
  const checked = Array.from(document.querySelectorAll(".row-select:checked")).map(
    (cb) => Number(cb.dataset.index)
  );
  if (checked.length === 0) return;
  analysisSet = checked.map((index) => {
    const msg = state.messages.find((m) => m.index === index);
    return { index, hexBytes: msg.hex_bytes, ascii: msg.ascii, expected: "" };
  });
  lastMatches = [];
  spanSelection = { start: null, end: null };
  document.getElementById("span-start").value = "";
  document.getElementById("span-end").value = "";
  document.getElementById("analysis-panel").classList.remove("hidden");
  renderAnalysisPanel();
});

document.getElementById("clear-analysis").addEventListener("click", () => {
  analysisSet = [];
  lastMatches = [];
  spanSelection = { start: null, end: null };
  document.getElementById("analysis-panel").classList.add("hidden");
});

function highlightClass(offset) {
  return lastMatches.some((m) => offset >= m.start && offset <= m.end) ? "match-highlight" : "";
}

function spanSelectClass(offset) {
  if (spanSelection.start === null) return "";
  if (spanSelection.end === null) return offset === spanSelection.start ? "span-select" : "";
  const lo = Math.min(spanSelection.start, spanSelection.end);
  const hi = Math.max(spanSelection.start, spanSelection.end);
  return offset >= lo && offset <= hi ? "span-select" : "";
}

function renderAnalysisPanel() {
  const maxLen = Math.max(0, ...analysisSet.map((m) => m.hexBytes.length));
  let html = "<table><thead><tr><th>#</th>";
  for (let i = 0; i < maxLen; i++) html += `<th>${i}</th>`;
  html += "<th>ascii</th><th>expected value</th></tr></thead><tbody>";

  analysisSet.forEach((msg, row) => {
    html += `<tr><td>${msg.index}</td>`;
    for (let i = 0; i < maxLen; i++) {
      const byte = msg.hexBytes[i];
      if (byte === undefined) { html += "<td></td>"; continue; }
      const cls = `${highlightClass(i)} ${spanSelectClass(i)}`.trim();
      html += `<td class="byte analysis-byte ${cls}" data-offset="${i}">${byte}</td>`;
    }
    html += `<td>${msg.ascii}</td>`;
    html += `<td><input type="text" class="expected-input" data-row="${row}" value="${msg.expected}" placeholder="e.g. 5.0"></td>`;
    html += "</tr>";
  });
  html += "</tbody></table>";
  document.getElementById("analysis-messages").innerHTML = html;

  document.querySelectorAll(".expected-input").forEach((input) => {
    input.addEventListener("input", (e) => {
      analysisSet[Number(e.target.dataset.row)].expected = e.target.value;
    });
  });

  document.querySelectorAll(".analysis-byte").forEach((cell) => {
    cell.addEventListener("click", () => {
      const offset = Number(cell.dataset.offset);
      if (spanSelection.start === null || spanSelection.end !== null) {
        spanSelection = { start: offset, end: null };
      } else {
        spanSelection.end = offset;
        if (spanSelection.end < spanSelection.start) {
          [spanSelection.start, spanSelection.end] = [spanSelection.end, spanSelection.start];
        }
      }
      document.getElementById("span-start").value = spanSelection.start;
      document.getElementById("span-end").value = spanSelection.end !== null ? spanSelection.end : "";
      renderAnalysisPanel();
    });
  });
}

document.getElementById("span-start").addEventListener("input", (e) => {
  spanSelection.start = e.target.value === "" ? null : Number(e.target.value);
  renderAnalysisPanel();
});

document.getElementById("span-end").addEventListener("input", (e) => {
  spanSelection.end = e.target.value === "" ? null : Number(e.target.value);
  renderAnalysisPanel();
});

function readSpan() {
  const startVal = document.getElementById("span-start").value;
  const endVal = document.getElementById("span-end").value;
  if (startVal === "" || endVal === "") return null;
  return [Number(startVal), Number(endVal)];
}

document.getElementById("probe-btn").addEventListener("click", () => {
  const span = readSpan();
  if (!span) {
    document.getElementById("analysis-results").innerHTML =
      '<p class="hint">Set both span start and end to probe a range.</p>';
    return;
  }
  const [start, end] = span;
  let html = "<h3>Probe result (decode only, no matching)</h3><ul>";
  for (const msg of analysisSet) {
    const bytesHex = msg.hexBytes.slice(start, end + 1);
    const big = parseInt(bytesHex.join(""), 16);
    const little = parseInt([...bytesHex].reverse().join(""), 16);
    html += `<li>#${msg.index}: bytes [${start}-${end}] = big-endian ${big}, little-endian ${little}</li>`;
  }
  html += "</ul>";
  lastMatches = [{ start, end }];
  document.getElementById("analysis-results").innerHTML = html;
  renderAnalysisPanel();
});

document.getElementById("search-btn").addEventListener("click", async () => {
  const expectedValues = analysisSet.map((m) => parseFloat(m.expected));
  if (expectedValues.some((v) => Number.isNaN(v))) {
    document.getElementById("analysis-results").innerHTML =
      '<p class="hint">Fill in an expected value for every selected message before searching.</p>';
    return;
  }
  const tolerance = Number(document.getElementById("tolerance").value) || 0;
  const scalesRaw = document.getElementById("scales").value.trim();
  const scales = scalesRaw ? scalesRaw.split(",").map((s) => Number(s.trim())) : null;
  const span = readSpan();

  const res = await fetch("/api/find_value", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      indices: analysisSet.map((m) => m.index),
      expected_values: expectedValues,
      tolerance,
      scales,
      span,
    }),
  });
  const { matches } = await res.json();
  lastMatches = matches;

  const html = matches.length
    ? `<h3>Matches</h3><ul>${matches
        .map((m) => `<li>bytes [${m.start}-${m.end}], ${m.byte_order}-endian, scale ${m.scale}</li>`)
        .join("")}</ul>`
    : "<p class=\"hint\">No match found for the given expected values/tolerance/scales.</p>";
  document.getElementById("analysis-results").innerHTML = html;
  renderAnalysisPanel();
});

loadData();
