let state = { messages: [], analysis: {}, labels: {}, deciphered: {}, monitors: {}, activeIndex: null };
let analysisSet = []; // [{index, hexBytes, ascii, expected: ""}]
let lastMatches = [];
let lastRawMatches = [];
let lastDebugHtml = "";
let lastExpectedValues = [];
let spanSelection = { start: null, end: null };
let lastCheckedIndex = null;
let analysisContext = null; // {label, direction} when the current analysis was launched from a label group

function decipheredKey(label, direction) {
  return `${label}::${direction}`;
}

function colorForLabel(name) {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue}, 65%, 60%)`;
}

function formatTimestamp(epochSeconds) {
  const d = new Date(epochSeconds * 1000);
  const pad = (n, len = 2) => String(n).padStart(len, "0");
  const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  return `${date} ${time}`;
}

async function loadData() {
  const res = await fetch("/api/messages");
  const fetched = await res.json();
  const unchanged = JSON.stringify(fetched) === JSON.stringify({
    messages: state.messages,
    analysis: state.analysis,
    labels: state.labels,
    deciphered: state.deciphered,
  });
  state = { ...state, ...fetched };
  if (!unchanged) render();
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

function decodeHexSpan(hexBytes, start, end, order) {
  const slice = hexBytes.slice(start, end + 1);
  const ordered = order === "little" ? [...slice].reverse() : slice;
  return parseInt(ordered.join(""), 16);
}

function getActiveMonitorForMessage(msg) {
  const label = state.labels[msg.index];
  if (!label || !label.name) return null;
  return state.monitors[decipheredKey(label.name, msg.direction)] || null;
}

function render() {
  const scrollY = window.scrollY;
  const previouslySelected = new Set(
    Array.from(document.querySelectorAll(".row-select:checked")).map((cb) => Number(cb.dataset.index))
  );

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
    const monitor = getActiveMonitorForMessage(msg);
    let isAnomaly = false;
    if (monitor) {
      const value = decodeHexSpan(msg.hex_bytes, monitor.start, monitor.end, monitor.byte_order) / monitor.scale;
      isAnomaly = Math.abs(value - monitor.expected_reading) > monitor.tolerance;
    }
    html += `<tr class="message-row ${isAnomaly ? "anomaly" : ""}" data-index="${msg.index}">`;
    html += `<td><input type="checkbox" class="row-select" data-index="${msg.index}"></td>`;
    html += `<td>${msg.index}</td>`;
    html += `<td class="direction-${msg.direction}">${msg.direction}</td>`;
    html += `<td>${formatTimestamp(msg.timestamp)}</td>`;
    for (let i = 0; i < maxLen; i++) {
      const byte = msg.hex_bytes[i];
      if (byte === undefined) { html += "<td></td>"; continue; }
      let cls = byteClass(msg.group_key, i, state.analysis);
      if (label && label.name) {
        const entry = state.deciphered[decipheredKey(label.name, msg.direction)];
        if (entry && i >= entry.start && i <= entry.end) cls += " deciphered";
      }
      if (monitor && i >= monitor.start && i <= monitor.end) cls += " monitored-byte";
      html += `<td class="byte ${cls}">${byte}</td>`;
    }
    html += `<td>${msg.ascii}</td>`;
    const eyeIcon = monitor ? ` <span class="eye-icon" title="${isAnomaly ? "Anomaly detected!" : "Being monitored"}">${isAnomaly ? "👁⚠" : "👁"}</span>` : "";
    const labelHtml =
      label && label.name
        ? `<span class="label-dot" style="background: ${colorForLabel(label.name)}"></span><span style="color: ${colorForLabel(label.name)}">${label.name}</span>`
        : "+ label";
    html += `<td class="label-cell">${labelHtml}${eyeIcon}</td>`;
    html += "</tr>";
  }
  html += "</tbody></table>";
  document.getElementById("capture-table").innerHTML = html;
  renderLabelGroups();
  renderMonitorsPanel();

  document.querySelectorAll(".message-row").forEach((row) => {
    row.addEventListener("click", (e) => {
      if (e.target.classList.contains("row-select")) return;
      e.stopPropagation();
      if (e.target.closest(".label-cell")) {
        openLabelPanel(Number(row.dataset.index));
        return;
      }
      const cb = row.querySelector(".row-select");
      cb.checked = !cb.checked;
      applySelectionClick(Number(row.dataset.index), cb.checked, e.shiftKey);
    });
  });

  document.querySelectorAll(".row-select").forEach((cb) => {
    cb.addEventListener("click", (e) => {
      e.stopPropagation();
      applySelectionClick(Number(cb.dataset.index), cb.checked, e.shiftKey);
    });
    if (previouslySelected.has(Number(cb.dataset.index))) cb.checked = true;
  });
  if (previouslySelected.size > 0) updateSelectionUI();
  window.scrollTo(0, scrollY);
}

function applySelectionClick(index, checked, shiftKey) {
  if (checked && pollingEnabled) {
    setPolling(false);
  }
  if (shiftKey && lastCheckedIndex !== null) {
    const lo = Math.min(lastCheckedIndex, index);
    const hi = Math.max(lastCheckedIndex, index);
    document.querySelectorAll(".row-select").forEach((other) => {
      const otherIndex = Number(other.dataset.index);
      if (otherIndex >= lo && otherIndex <= hi) other.checked = checked;
    });
  }
  lastCheckedIndex = index;
  updateSelectionUI();
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
  const label = state.labels[index] || { name: "", note: "", value: "" };
  document.getElementById("label-index").textContent = index;
  document.getElementById("label-name").value = label.name || "";
  document.getElementById("label-value").value = label.value ?? "";
  document.getElementById("label-notes").value = label.note || "";
  hideNameSuggestions();
  document.getElementById("label-panel").classList.remove("hidden");
  document.getElementById("label-name").focus();
}

function getKnownLabelNames() {
  const names = new Set();
  Object.values(state.labels).forEach((l) => { if (l && l.name) names.add(l.name); });
  Object.values(state.deciphered).forEach((d) => { if (d && d.label) names.add(d.label); });
  return Array.from(names).sort();
}

function hideNameSuggestions() {
  const box = document.getElementById("label-name-suggestions");
  box.classList.add("hidden");
  box.innerHTML = "";
}

let tabCycleIndex = -1;

function renderNameSuggestions(query) {
  const box = document.getElementById("label-name-suggestions");
  tabCycleIndex = -1;
  if (!query) {
    hideNameSuggestions();
    return;
  }
  const matches = getKnownLabelNames().filter((n) => n.toLowerCase().includes(query.toLowerCase()));
  if (matches.length === 0) {
    hideNameSuggestions();
    return;
  }
  box.innerHTML = matches.map((n) => `<div class="suggestion-item">${n}</div>`).join("");
  box.classList.remove("hidden");

  box.querySelectorAll(".suggestion-item").forEach((item) => {
    item.addEventListener("mousedown", (e) => {
      e.preventDefault();
      document.getElementById("label-name").value = item.textContent;
      hideNameSuggestions();
    });
  });
}

document.getElementById("label-name").addEventListener("input", (e) => {
  renderNameSuggestions(e.target.value);
});

document.getElementById("label-name").addEventListener("keydown", (e) => {
  if (e.key !== "Tab") return;
  const box = document.getElementById("label-name-suggestions");
  const items = Array.from(box.querySelectorAll(".suggestion-item"));
  if (box.classList.contains("hidden") || items.length === 0) return;
  e.preventDefault();
  if (items.length === 1) {
    document.getElementById("label-name").value = items[0].textContent;
    hideNameSuggestions();
    return;
  }
  tabCycleIndex = (tabCycleIndex + 1) % items.length;
  document.getElementById("label-name").value = items[tabCycleIndex].textContent;
  items.forEach((item, i) => item.classList.toggle("suggestion-active", i === tabCycleIndex));
});

document.getElementById("label-name").addEventListener("blur", hideNameSuggestions);

document.getElementById("label-panel").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.id !== "label-notes") {
    e.preventDefault();
    document.getElementById("label-save").click();
  }
});

document.getElementById("label-close").addEventListener("click", () => {
  document.getElementById("label-panel").classList.add("hidden");
});

document.getElementById("label-save").addEventListener("click", async () => {
  const index = state.activeIndex;
  const name = document.getElementById("label-name").value;
  const note = document.getElementById("label-notes").value;
  const valueRaw = document.getElementById("label-value").value.trim();
  const value = valueRaw === "" ? null : Number(valueRaw);
  await fetch("/api/label", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ index, name, note, value }),
  });
  state.labels[index] = { name, note, value };
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
    return { index, hexBytes: msg.hex_bytes, ascii: msg.ascii, expected: "", groupKey: msg.group_key };
  });
  lastMatches = [];
  lastRawMatches = [];
  lastDebugHtml = "";
  spanSelection = { start: null, end: null };
  analysisContext = null;
  document.getElementById("span-start").value = "";
  document.getElementById("span-end").value = "";
  document.getElementById("value-min").value = "";
  document.getElementById("value-max").value = "";
  document.getElementById("analysis-results").innerHTML = "";
  resetMatchFilters();
  document.getElementById("analysis-panel").classList.remove("hidden");
  renderAnalysisPanel();
});

document.getElementById("clear-analysis").addEventListener("click", () => {
  analysisSet = [];
  lastMatches = [];
  lastRawMatches = [];
  lastDebugHtml = "";
  spanSelection = { start: null, end: null };
  analysisContext = null;
  resetMatchFilters();
  document.getElementById("analysis-panel").classList.add("hidden");
});

function resetMatchFilters() {
  document.getElementById("filter-order").value = "";
  document.getElementById("filter-precision").value = "";
  document.getElementById("filter-scale").value = "";
}

document.getElementById("filter-order").addEventListener("change", renderMatchResults);
document.getElementById("filter-precision").addEventListener("change", renderMatchResults);
document.getElementById("filter-scale").addEventListener("input", renderMatchResults);

function highlightClass(offset) {
  return lastMatches.some((m) => offset >= m.start && offset <= m.end) ? "match-highlight" : "";
}

function spanSelectClass(offset) {
  if (spanSelection.start === null) return "";
  const lo = spanSelection.end === null ? spanSelection.start : Math.min(spanSelection.start, spanSelection.end);
  const hi = spanSelection.end === null ? spanSelection.start : Math.max(spanSelection.start, spanSelection.end);
  const classes = [];
  if (offset === lo) classes.push("span-start-marker");
  if (offset === hi) classes.push("span-end-marker");
  return classes.join(" ");
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
      const predicted = byteClass(msg.groupKey, i, state.analysis);
      const cls = `${predicted} ${highlightClass(i)} ${spanSelectClass(i)}`.trim();
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

document.getElementById("clear-span").addEventListener("click", () => {
  spanSelection = { start: null, end: null };
  document.getElementById("span-start").value = "";
  document.getElementById("span-end").value = "";
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

function evalScaleExpression(expr) {
  const trimmed = expr.trim();
  if (!/^[0-9+\-*/().\s]+$/.test(trimmed)) return NaN;
  try {
    // Function(), not eval() directly — but the real guard is the character
    // whitelist above: only digits/operators/parens can appear, so there's
    // no way to reach anything but arithmetic regardless of which we use.
    return Function(`"use strict"; return (${trimmed});`)();
  } catch {
    return NaN;
  }
}

function formatScale(scale) {
  return Number.isInteger(scale) ? String(scale) : scale.toFixed(4);
}

function groupMatchesBySpan(matches) {
  const groups = new Map();
  for (const m of matches) {
    const key = `${m.start}-${m.end}`;
    if (!groups.has(key)) groups.set(key, { start: m.start, end: m.end, entries: [] });
    groups.get(key).entries.push(m);
  }
  return Array.from(groups.values()).sort(
    (a, b) => a.start - b.start || (a.end - a.start) - (b.end - b.start)
  );
}

function getSearchDirection() {
  if (analysisContext) return analysisContext.direction;
  const first = analysisSet[0];
  if (!first) return null;
  const msg = state.messages.find((m) => m.index === first.index);
  return msg ? msg.direction : null;
}

function getKnownByteOrder(direction) {
  if (!direction) return null;
  for (const entry of Object.values(state.deciphered)) {
    if (entry.direction === direction) return entry.byte_order;
  }
  return null;
}

async function runSearch() {
  const expectedValues = analysisSet.map((m) => parseFloat(m.expected));
  if (expectedValues.some((v) => Number.isNaN(v))) {
    document.getElementById("analysis-results").innerHTML =
      '<p class="hint">Fill in an expected value for every selected message before searching.</p>';
    return;
  }
  const tolerance = Number(document.getElementById("tolerance").value) || 0;
  const scalesRaw = document.getElementById("scales").value.trim();
  const scales = scalesRaw
    ? scalesRaw.split(",").map((s) => evalScaleExpression(s)).filter((v) => !Number.isNaN(v))
    : null;
  const span = readSpan();
  const minRaw = document.getElementById("value-min").value.trim();
  const maxRaw = document.getElementById("value-max").value.trim();
  const min_value = minRaw === "" ? null : Number(minRaw);
  const max_value = maxRaw === "" ? null : Number(maxRaw);
  const searchDirection = getSearchDirection();
  const byte_order = getKnownByteOrder(searchDirection);
  const requestBody = {
    indices: analysisSet.map((m) => m.index),
    expected_values: expectedValues,
    tolerance,
    scales,
    span,
    min_value,
    max_value,
    byte_order,
  };

  const res = await fetch("/api/find_value", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  });
  const { matches } = await res.json();
  lastRawMatches = matches;

  const rangeNote = min_value !== null && max_value !== null ? `, device range [${min_value}, ${max_value}] (adds one derived precision-based scale per span)` : "";
  const byteOrderNote = byte_order ? `, assuming <strong>${byte_order}-endian</strong> (a "${searchDirection}" field has already been deciphered with this order)` : "";
  lastDebugHtml = `<p class="hint">Searched indices [${requestBody.indices}] with expected values [${requestBody.expected_values}], tolerance ${requestBody.tolerance}, scales ${requestBody.scales ? `[${requestBody.scales}]` : "(common defaults)"}, span ${requestBody.span ? `[${requestBody.span}]` : "(whole message — none set)"}${rangeNote}${byteOrderNote}.</p>`;
  lastExpectedValues = expectedValues;

  renderMatchResults();
}

function applyMatchFilters(matches) {
  const orderFilter = document.getElementById("filter-order").value;
  const precisionFilter = document.getElementById("filter-precision").value;
  const scaleFilter = document.getElementById("filter-scale").value.trim();
  return matches.filter((m) => {
    if (orderFilter && m.byte_order !== orderFilter) return false;
    if (precisionFilter === "none" && m.precision) return false;
    if (precisionFilter && precisionFilter !== "none" && String(m.precision) !== precisionFilter) return false;
    if (scaleFilter && !Number.isNaN(Number(scaleFilter)) && Math.abs(m.scale - Number(scaleFilter)) > 1e-6) return false;
    return true;
  });
}

function renderMatchResults() {
  const matches = applyMatchFilters(lastRawMatches);
  lastMatches = matches;
  const filteredNote = matches.length !== lastRawMatches.length ? ` (${lastRawMatches.length} before filters)` : "";

  const resultHtml = matches.length
    ? `<h3>Matches (${matches.length}${filteredNote})</h3>${groupMatchesBySpan(matches)
        .map((group) => {
          const entriesHtml = group.entries
            .map((m) => {
              const avgDecoded = m.decoded_values.reduce((a, b) => a + b, 0) / m.decoded_values.length;
              const saveBtn = analysisContext
                ? ` <button class="save-deciphered-btn" data-start="${m.start}" data-end="${m.end}" data-order="${m.byte_order}" data-scale="${m.scale}">Mark deciphered for "${analysisContext.label}" (${analysisContext.direction})</button>
                    <button class="watch-btn" data-start="${m.start}" data-end="${m.end}" data-order="${m.byte_order}" data-scale="${m.scale}" data-avg-decoded="${avgDecoded}">👁 Watch</button>`
                : "";
              const decoded = m.decoded_values.map((v) => v.toFixed(3)).join(", ");
              const precisionNote = m.precision ? ` <span class="precision-note">(precision ${m.precision})</span>` : "";
              return `<li>${m.byte_order}-endian, scale ${formatScale(m.scale)}${precisionNote}${saveBtn}<br><span class="hint">decoded back: [${decoded}] — compare against your expected values [${lastExpectedValues}]</span></li>`;
            })
            .join("");
          return `<div class="match-group"><h4>bytes [${group.start}-${group.end}] (width ${group.end - group.start + 1})</h4><ul>${entriesHtml}</ul></div>`;
        })
        .join("")}`
    : "<p class=\"hint error-text\">No match found for the given expected values/tolerance/scales/filters.</p>";
  document.getElementById("analysis-results").innerHTML = lastDebugHtml + resultHtml;
  renderAnalysisPanel();

  document.querySelectorAll(".save-deciphered-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch("/api/deciphered", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: analysisContext.label,
          direction: analysisContext.direction,
          start: Number(btn.dataset.start),
          end: Number(btn.dataset.end),
          byte_order: btn.dataset.order,
          scale: Number(btn.dataset.scale),
        }),
      });
      await loadData();
    });
  });

  document.querySelectorAll(".watch-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const defaultReading = Number(btn.dataset.avgDecoded).toFixed(3);
      const readingInput = prompt("Expected reading for this monitor (flag if a labeled message deviates from this):", defaultReading);
      if (readingInput === null || readingInput.trim() === "") return;
      const toleranceInput = prompt("Allowed tolerance before flagging as an anomaly:", "0.1");
      if (toleranceInput === null) return;
      await fetch("/api/monitors", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: analysisContext.label,
          direction: analysisContext.direction,
          start: Number(btn.dataset.start),
          end: Number(btn.dataset.end),
          byte_order: btn.dataset.order,
          scale: Number(btn.dataset.scale),
          expected_reading: Number(readingInput),
          tolerance: Number(toleranceInput) || 0,
        }),
      });
      await loadData();
    });
  });
}

document.getElementById("search-btn").addEventListener("click", runSearch);

function renderMonitorsPanel() {
  const container = document.getElementById("monitor-list");
  const keys = Object.keys(state.monitors);
  if (keys.length === 0) {
    container.innerHTML = '<p class="hint">No monitors yet — use the "👁 Watch" button on a search match to add one.</p>';
    return;
  }

  let html = "<ul>";
  for (const key of keys) {
    const monitor = state.monitors[key];
    const readings = state.messages
      .filter((msg) => {
        const label = state.labels[msg.index];
        return label && label.name === monitor.label && msg.direction === monitor.direction;
      })
      .map((msg) => ({
        index: msg.index,
        value: decodeHexSpan(msg.hex_bytes, monitor.start, monitor.end, monitor.byte_order) / monitor.scale,
      }));
    const anomalies = readings.filter((r) => Math.abs(r.value - monitor.expected_reading) > monitor.tolerance);
    const statusHtml =
      readings.length === 0
        ? '<span class="hint">no labeled messages yet</span>'
        : anomalies.length > 0
        ? `<span class="error-text">⚠ ANOMALY — #${anomalies.map((a) => `${a.index} (${a.value.toFixed(3)})`).join(", #")}</span>`
        : `<span class="monitor-ok">✓ OK (${readings.length} reading${readings.length === 1 ? "" : "s"} checked)</span>`;

    html += `<li>
      <strong>${monitor.label}</strong> (${monitor.direction}), bytes [${monitor.start}-${monitor.end}], ${monitor.byte_order}-endian, scale ${formatScale(monitor.scale)} —
      expecting ~${monitor.expected_reading} ± ${monitor.tolerance}: ${statusHtml}
      <button class="stop-watch-btn" data-label="${monitor.label}" data-direction="${monitor.direction}">Stop watching</button>
    </li>`;
  }
  html += "</ul>";
  container.innerHTML = html;

  document.querySelectorAll(".stop-watch-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch("/api/monitors", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: btn.dataset.label, direction: btn.dataset.direction }),
      });
      await loadData();
    });
  });
}

function renderLabelGroups() {
  const groups = {};
  for (const [indexStr, label] of Object.entries(state.labels)) {
    if (!label || !label.name) continue;
    const index = Number(indexStr);
    const msg = state.messages.find((m) => m.index === index);
    if (!msg) continue;
    const key = decipheredKey(label.name, msg.direction);
    groups[key] = groups[key] || { name: label.name, direction: msg.direction, members: [] };
    const value = parseFloat(label.value);
    groups[key].members.push({ index, value: Number.isNaN(value) ? null : value });
  }

  const container = document.getElementById("label-groups");
  const keys = Object.keys(groups);
  if (keys.length === 0) {
    container.innerHTML = "";
    return;
  }

  let html = "<h2>Label groups</h2><ul>";
  for (const key of keys) {
    const group = groups[key];
    const withValues = group.members.filter((m) => m.value !== null);
    const distinctValues = new Set(withValues.map((m) => m.value)).size;
    const deciphered = state.deciphered[key];
    const decipheredNote = deciphered
      ? ` — <span class="deciphered-note">deciphered: bytes [${deciphered.start}-${deciphered.end}], ${deciphered.byte_order}-endian, scale ${deciphered.scale}</span>`
      : "";
    html += `<li>
      <strong>${group.name}</strong> (${group.direction}, ${group.members.length} labeled, ${withValues.length} with a value, ${distinctValues} distinct)${decipheredNote}
      <button class="analyze-group-btn" data-key="${key}" ${distinctValues < 2 ? "disabled" : ""}>Analyze</button>
    </li>`;
  }
  html += "</ul>";
  container.innerHTML = html;

  document.querySelectorAll(".analyze-group-btn").forEach((btn) => {
    btn.addEventListener("click", () => analyzeLabelGroup(groups[btn.dataset.key]));
  });
}

function analyzeLabelGroup(group) {
  const withValues = group.members.filter((m) => m.value !== null);
  analysisSet = withValues.map((m) => {
    const msg = state.messages.find((mm) => mm.index === m.index);
    return { index: m.index, hexBytes: msg.hex_bytes, ascii: msg.ascii, expected: String(m.value), groupKey: msg.group_key };
  });
  lastMatches = [];
  spanSelection = { start: null, end: null };
  document.getElementById("span-start").value = "";
  document.getElementById("span-end").value = "";
  analysisContext = { label: group.name, direction: group.direction };
  document.getElementById("analysis-panel").classList.remove("hidden");
  renderAnalysisPanel();
  runSearch();
}

document.getElementById("clear-captures").addEventListener("click", async () => {
  if (!confirm("Clear all captured messages and labels? This can't be undone.")) return;
  await fetch("/api/capture", { method: "DELETE" });
  analysisSet = [];
  lastMatches = [];
  document.getElementById("analysis-panel").classList.add("hidden");
  await loadData();
});

let pollingEnabled = false;
let pollingInterval = null;

function setPolling(enabled) {
  pollingEnabled = enabled;
  document.getElementById("toggle-polling").textContent = enabled
    ? "Disable capture"
    : "Enable capture";
  document.getElementById("toggle-polling").classList.toggle("active", enabled);
  if (enabled) {
    pollingInterval = setInterval(loadData, 150);
  } else if (pollingInterval) {
    clearInterval(pollingInterval);
    pollingInterval = null;
  }
}

document.getElementById("toggle-polling").addEventListener("click", () => {
  setPolling(!pollingEnabled);
});

async function loadCaptureConfig() {
  const res = await fetch("/api/capture_config");
  const config = await res.json();
  document.getElementById("capture-interface").value = config.interface;
  document.getElementById("capture-device").value = config.device_address;
}

document.getElementById("save-capture-config").addEventListener("click", async () => {
  const interfaceValue = document.getElementById("capture-interface").value.trim() || "usbmon3";
  const deviceValue = Number(document.getElementById("capture-device").value) || 2;
  await fetch("/api/capture_config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ interface: interfaceValue, device_address: deviceValue }),
  });
  const savedMsg = document.getElementById("capture-config-saved");
  savedMsg.classList.remove("hidden");
  clearTimeout(savedMsg._hideTimeout);
  savedMsg._hideTimeout = setTimeout(() => savedMsg.classList.add("hidden"), 2000);
});

document.getElementById("scan-lsusb").addEventListener("click", async () => {
  const box = document.getElementById("lsusb-output");
  box.textContent = "Scanning...";
  box.classList.remove("hidden");
  const res = await fetch("/api/lsusb");
  const { output } = await res.json();
  box.textContent = output;
});

document.getElementById("capture-settings-toggle").addEventListener("click", () => {
  const body = document.getElementById("capture-settings-body");
  const nowHidden = body.classList.toggle("hidden");
  document.getElementById("capture-settings-toggle").innerHTML = (nowHidden ? "&#9656;" : "&#9662;") + " Capture settings";
});

let captureEnabled = false;

async function checkCaptureStatus() {
  const res = await fetch("/api/capture/status");
  const status = await res.json();
  captureEnabled = status.enabled;
  const btn = document.getElementById("toggle-capture");
  btn.textContent = captureEnabled ? "Disconnect" : "Connect";
  btn.classList.toggle("active", captureEnabled);

  const statusEl = document.getElementById("capture-status");
  if (status.error) {
    statusEl.textContent = `Capture error: ${status.error}`;
    statusEl.className = "error-text";
  } else {
    statusEl.textContent = `Capture thread: ${status.running ? "running" : "not running"}, writing: ${captureEnabled ? "on" : "off"}`;
    statusEl.className = "hint";
  }
}

document.getElementById("toggle-capture").addEventListener("click", async () => {
  await fetch(`/api/capture/${captureEnabled ? "disable" : "enable"}`, { method: "POST" });
  checkCaptureStatus();
});

setInterval(checkCaptureStatus, 3000);

loadCaptureConfig();
checkCaptureStatus();
loadData();
