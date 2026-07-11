// Label/param names are free text the user types (label-name, decipher/watch
// param name inputs) and get embedded into innerHTML strings all over this
// file — escape them everywhere or a name like `x" onmouseover="alert(1)`
// breaks out of an attribute and injects arbitrary markup/handlers.
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

let state = { messages: [], analysis: {}, labels: {}, deciphered: {}, monitors: {}, activeIndex: null };
let analysisSet = []; // [{index, hexBytes, ascii, expected: ""}]
let lastMatches = [];
let lastRawMatches = [];
let lastClosestMiss = null; // best-scoring non-match from the last search — only meaningful when lastRawMatches is empty
let lastDebugHtml = "";
let lastExpectedValues = [];
let spanSelection = { start: null, end: null };
let lastCheckedIndex = null;
let analysisContext = null; // {label, direction, param} when the current analysis was launched from a label group

// A message label can carry several named parameters at once (e.g. a
// "set_waveform" command's wave_type/freq/amplitude/offset all live in one
// frame) — these look up every deciphered/watched field for a label+direction,
// not just one.
function decipheredFieldsFor(label, direction) {
  return Object.values(state.deciphered).filter((d) => d.label === label && d.direction === direction);
}

function monitorsFor(label, direction) {
  return Object.values(state.monitors).filter((m) => m.label === label && m.direction === direction);
}

function hueForName(name) {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  return Math.abs(hash) % 360;
}

function colorForLabel(name) {
  return `hsl(${hueForName(name)}, 65%, 60%)`;
}

let showFullTimestamp = false; // default: time only
let showAscii = true;
let showDecipheredValues = false;

let pigSniffTimeout = null;

function playPigSniffAnimation() {
  const pig = document.getElementById("pig-sniff");
  pig.classList.remove("hidden", "sniffing");
  void pig.offsetWidth; // force reflow so the animation restarts if triggered again mid-run
  pig.classList.add("sniffing");
  clearTimeout(pigSniffTimeout);
  pigSniffTimeout = setTimeout(() => {
    pig.classList.add("hidden");
    pig.classList.remove("sniffing");
  }, 1800);
}

function formatTimestamp(epochSeconds) {
  const d = new Date(epochSeconds * 1000);
  const pad = (n, len = 2) => String(n).padStart(len, "0");
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  if (!showFullTimestamp) return time;
  const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
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
    monitors: state.monitors,
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

function getActiveMonitorsForMessage(msg) {
  const label = state.labels[msg.index];
  if (!label || !label.name) return [];
  // a watch only "activates" for this message once it has its own value —
  // there's no fixed baseline, each message is checked against its own entry
  if (Number.isNaN(parseFloat(label.value))) return [];
  return monitorsFor(label.name, msg.direction);
}

let selectedLabelFilters = new Set(); // empty = no filter, show every label (and unlabeled messages)

function updateLabelFilterOptions() {
  const names = new Set();
  Object.values(state.labels).forEach((l) => { if (l && l.name) names.add(l.name); });
  // a name that no longer exists (e.g. consolidated away) shouldn't linger as a phantom filter
  for (const name of Array.from(selectedLabelFilters)) {
    if (!names.has(name)) selectedLabelFilters.delete(name);
  }
  const sorted = Array.from(names).sort();
  document.getElementById("label-filter-checkboxes").innerHTML = sorted
    .map((n) => `<label class="checkbox-label"><input type="checkbox" class="label-filter-checkbox" value="${escapeHtml(n)}" ${selectedLabelFilters.has(n) ? "checked" : ""}> ${escapeHtml(n)}</label>`)
    .join("");
  document.getElementById("label-filter-summary").textContent =
    selectedLabelFilters.size > 0 ? `Label filter (${selectedLabelFilters.size})` : "Label filter";
  document.querySelectorAll(".label-filter-checkbox").forEach((cb) => {
    cb.addEventListener("change", (e) => {
      if (e.target.checked) selectedLabelFilters.add(e.target.value);
      else selectedLabelFilters.delete(e.target.value);
      render();
    });
  });
}

function render() {
  const scrollY = window.scrollY;
  const tableContainer = document.getElementById("capture-table");
  // "near bottom" (not just exactly at bottom) so rounding/sub-pixel scroll
  // math doesn't cause it to stop auto-following on every other render
  const wasNearBottom =
    tableContainer.scrollHeight - tableContainer.scrollTop - tableContainer.clientHeight < 40;
  const previouslySelected = new Set(
    Array.from(document.querySelectorAll(".row-select:checked")).map((cb) => Number(cb.dataset.index))
  );

  const directionFilter = document.getElementById("direction-filter").value;
  let filteredMessages = directionFilter
    ? state.messages.filter((m) => m.direction === directionFilter)
    : state.messages;

  updateLabelFilterOptions();
  if (selectedLabelFilters.size > 0) {
    filteredMessages = filteredMessages.filter((m) => selectedLabelFilters.has(state.labels[m.index]?.name || ""));
  }

  // Only warn about groups that actually have a message in view right now —
  // otherwise switching to "OUT only" still shows warnings about IN groups
  // you can't even see, which reads as noise unrelated to what's on screen.
  const visibleGroupKeys = new Set(filteredMessages.map((m) => m.group_key));
  const visibleAnalysis = Object.fromEntries(
    Object.entries(state.analysis).filter(([key]) => visibleGroupKeys.has(key))
  );
  const warnings = confidenceWarnings(visibleAnalysis);
  const warningHtml = warnings.length
    ? `<div class="warning-banner"><strong>Low-confidence groups:</strong><ul>${warnings.map((w) => `<li>${w}</li>`).join("")}</ul></div>`
    : "";
  document.getElementById("confidence-warnings").innerHTML = warningHtml;

  const maxLen = Math.max(0, ...state.messages.map((m) => m.length));
  let html = "<table><thead><tr><th></th><th>#</th><th>dir</th><th>t</th>";
  for (let i = 0; i < maxLen; i++) html += `<th>${i}</th>`;
  html += `${showAscii ? "<th>ascii</th>" : ""}<th>label</th></tr></thead><tbody>`;

  for (const msg of filteredMessages) {
    const label = state.labels[msg.index];
    const monitors = getActiveMonitorsForMessage(msg);
    let isAnomaly = false;
    for (const monitor of monitors) {
      const decoded = decodeHexSpan(msg.hex_bytes, monitor.start, monitor.end, monitor.byte_order) / monitor.scale;
      const expected = parseFloat(label.value);
      if (Math.abs(decoded - expected) > monitor.tolerance) isAnomaly = true;
    }
    const decipheredFields = label && label.name ? decipheredFieldsFor(label.name, msg.direction) : [];
    html += `<tr class="message-row ${isAnomaly ? "anomaly" : ""}" data-index="${msg.index}">`;
    html += `<td><input type="checkbox" class="row-select" data-index="${msg.index}"></td>`;
    html += `<td>${msg.index}</td>`;
    html += `<td class="direction-${msg.direction}">${msg.direction}</td>`;
    html += `<td>${formatTimestamp(msg.timestamp)}</td>`;
    for (let i = 0; i < maxLen; ) {
      const byte = msg.hex_bytes[i];
      if (byte === undefined) { html += "<td></td>"; i++; continue; }
      const decipheredField = decipheredFields.find((entry) => i >= entry.start && i <= entry.end);

      // collapse the whole field's byte range into one cell showing its
      // decoded real-world value, instead of the raw hex — only once, at
      // the field's first byte, and only if the message actually has every
      // byte the field spans (a shorter message under the same label skips
      // this and falls through to normal per-byte rendering below)
      if (
        showDecipheredValues && decipheredField &&
        i === decipheredField.start && msg.hex_bytes[decipheredField.end] !== undefined
      ) {
        const width = decipheredField.end - decipheredField.start + 1;
        const decodedValue = decodeHexSpan(msg.hex_bytes, decipheredField.start, decipheredField.end, decipheredField.byte_order) / decipheredField.scale;
        html += `<td class="byte deciphered-value" colspan="${width}" title="${escapeHtml(decipheredField.param)}">${decodedValue.toFixed(3)}</td>`;
        i = decipheredField.end + 1;
        continue;
      }

      let cls = byteClass(msg.group_key, i, state.analysis);
      let titleAttr = "";
      if (decipheredField) {
        cls += " deciphered";
        titleAttr = ` title="${escapeHtml(decipheredField.param)}"`;
        // a bold seam wherever the previous byte belongs to a different named
        // field, so adjacent deciphered fields are clearly distinguishable
        // even though they share the same gold styling
        const prevField = decipheredFields.find((entry) => i - 1 >= entry.start && i - 1 <= entry.end);
        if (!prevField || prevField.param !== decipheredField.param) cls += " deciphered-boundary";
      }
      if (monitors.some((m) => i >= m.start && i <= m.end)) cls += " monitored-byte";
      html += `<td class="byte ${cls}"${titleAttr}>${byte}</td>`;
      i++;
    }
    if (showAscii) html += `<td>${escapeHtml(msg.ascii)}</td>`;
    const eyeIcon = monitors.length ? ` <span class="eye-icon" title="${isAnomaly ? "Anomaly detected!" : "Being monitored"}">${isAnomaly ? "👁⚠" : "👁"}</span>` : "";
    const labelHtml =
      label && label.name
        ? `<span style="color: ${colorForLabel(label.name)}">● ${escapeHtml(label.name)}</span>`
        : "+ label";
    const removeLabelIcon = label && label.name
      ? `<span class="row-action-icon remove-label-icon" data-index="${msg.index}" title="Remove this label">×</span>`
      : "";
    const replayIcon = `<span class="row-action-icon replay-icon" data-index="${msg.index}" title="Duplicate or replicate this message">⧉</span>`;
    html += `<td class="label-cell">${labelHtml}${eyeIcon}${removeLabelIcon}${replayIcon}</td>`;
    html += "</tr>";
  }
  html += "</tbody></table>";
  tableContainer.innerHTML = html;
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

  document.querySelectorAll(".replay-icon").forEach((el) => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      openReplayPanel(Number(el.dataset.index), el);
    });
  });

  document.querySelectorAll(".remove-label-icon").forEach((el) => {
    el.addEventListener("click", async (e) => {
      e.stopPropagation();
      await removeLabel(Number(el.dataset.index));
      render();
    });
  });

  if (previouslySelected.size > 0) updateSelectionUI();
  window.scrollTo(0, scrollY);
  if (wasNearBottom) tableContainer.scrollTop = tableContainer.scrollHeight;
}

let replayContext = null; // {index, msg, label, fields} for whichever row's ⧉ was clicked

function resetReplayContent() {
  document.getElementById("replay-form").innerHTML = "";
  document.getElementById("replay-snippet").textContent = "";
  document.getElementById("replay-snippet").classList.add("hidden");
  document.getElementById("replay-copy").classList.add("hidden");
}

function openReplayPanel(index, anchorEl) {
  const msg = state.messages.find((m) => m.index === index);
  if (!msg) return;
  const label = state.labels[index];
  const fields = label && label.name ? decipheredFieldsFor(label.name, msg.direction) : [];
  replayContext = { index, msg, label, fields };

  document.getElementById("replay-title").textContent = `Send message #${index}`;
  document.getElementById("replay-chooser").classList.remove("hidden");
  resetReplayContent();

  const replicateBtn = document.getElementById("replay-choose-replicate");
  replicateBtn.disabled = fields.length === 0;
  replicateBtn.title = fields.length === 0
    ? "No deciphered fields yet for this label — Mark deciphered a match first"
    : "Send this command with different values";

  positionPanelNear(document.getElementById("replay-panel"), anchorEl);
  document.getElementById("replay-panel").classList.remove("hidden");
}

document.getElementById("replay-choose-duplicate").addEventListener("click", () => {
  const { index, msg } = replayContext;
  const hex = msg.hex_bytes.join("");
  document.getElementById("replay-title").textContent = `Duplicate message #${index}`;
  document.getElementById("replay-chooser").classList.add("hidden");
  document.getElementById("replay-form").innerHTML =
    '<p class="hint">Resends the exact captured bytes verbatim — no protocol knowledge needed.</p>';
  document.getElementById("replay-snippet").textContent = `ser.write(bytes.fromhex("${hex}"))`;
  document.getElementById("replay-snippet").classList.remove("hidden");
  document.getElementById("replay-copy").classList.remove("hidden");
});

document.getElementById("replay-choose-replicate").addEventListener("click", () => {
  const { msg, label, fields } = replayContext;
  if (!fields.length) return;

  document.getElementById("replay-title").textContent = `Replicate "${label.name}" (${msg.direction})`;
  document.getElementById("replay-chooser").classList.add("hidden");
  const formHtml = fields
    .map((f) => `<label>${escapeHtml(f.param)} <input class="replicate-param-input" data-param="${escapeHtml(f.param)}" type="text" placeholder="new value"></label>`)
    .join("");
  document.getElementById("replay-form").innerHTML =
    `<p class="hint">Sends the same command with different values — requires the generated <code>encode_${escapeHtml(label.name)}()</code> driver function (use "Generate driver function" on this label group first).</p>${formHtml}`;

  const paramInputs = Array.from(document.querySelectorAll(".replicate-param-input"));
  const updateSnippet = () => {
    const args = fields
      .map((f) => {
        const input = paramInputs.find((el) => el.dataset.param === f.param);
        return `${f.param}=${input.value || 0}`;
      })
      .join(", ");
    document.getElementById("replay-snippet").textContent = `ser.write(encode_${label.name}(${args}))`;
  };
  paramInputs.forEach((input) => input.addEventListener("input", updateSnippet));
  updateSnippet();
  document.getElementById("replay-snippet").classList.remove("hidden");
  document.getElementById("replay-copy").classList.remove("hidden");
});

document.getElementById("replay-close").addEventListener("click", () => {
  replayContext = null;
  document.getElementById("replay-panel").classList.add("hidden");
});

document.getElementById("replay-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText(document.getElementById("replay-snippet").textContent);
});

function applySelectionClick(index, checked, shiftKey) {
  if (checked && pollingInterval) {
    setPollingInterval(false);
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
    row.classList.toggle("selected", checked);
  });
  document.getElementById("clear-selection").classList.toggle("hidden", !anyChecked);
}

document.getElementById("clear-selection").addEventListener("click", () => {
  document.querySelectorAll(".row-select").forEach((cb) => { cb.checked = false; });
  lastCheckedIndex = null;
  updateSelectionUI();
});

document.addEventListener("click", (e) => {
  document.querySelectorAll(".modal-panel").forEach((panel) => {
    if (!panel.classList.contains("hidden") && !panel.contains(e.target)) {
      panel.classList.add("hidden");
    }
  });
});

// spacebar toggles capture — but only when focus isn't inside a text field,
// otherwise typing a literal space anywhere (a label note, a value input)
// would toggle capture instead of typing a space character
document.addEventListener("keydown", (e) => {
  if (e.code !== "Space") return;
  const active = document.activeElement;
  const isTyping = active && (
    active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.tagName === "SELECT" || active.isContentEditable
  );
  if (isTyping) return;
  e.preventDefault(); // space's default action is scrolling the page
  document.getElementById("toggle-capture").click();
});

function openLabelPanel(index) {
  // clicking in to inspect/label one specific measurement stops live
  // capture — otherwise the message you're looking at can keep moving
  // underneath you (new readings streaming in) while you're trying to name it
  disableCapture();
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

document.getElementById("label-value").addEventListener("input", (e) => {
  const entry = analysisSet.find((m) => m.index === state.activeIndex);
  if (entry) {
    entry.expected = e.target.value;
    renderAnalysisPanel();
  }
});

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
  tabCycleIndex = -1;
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
  if (e.key !== "Enter" || e.target.id === "label-notes" || e.target.tagName === "BUTTON") return;
  e.preventDefault();
  const box = document.getElementById("label-name-suggestions");
  if (e.target.id === "label-name" && !box.classList.contains("hidden") && tabCycleIndex >= 0) {
    // mid tab-cycle: Enter confirms the highlighted suggestion, it doesn't submit
    hideNameSuggestions();
    return;
  }
  document.getElementById("label-save").click();
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

async function removeLabel(index) {
  await fetch(`/api/label/${index}`, { method: "DELETE" });
  delete state.labels[index];
}

document.getElementById("label-remove").addEventListener("click", async () => {
  await removeLabel(state.activeIndex);
  document.getElementById("label-panel").classList.add("hidden");
  render();
});

function deriveSharedLabelContext(indices) {
  let context = null;
  for (const index of indices) {
    const label = state.labels[index];
    const msg = state.messages.find((m) => m.index === index);
    if (!label || !label.name || !msg) return null;
    if (!context) {
      context = { label: label.name, direction: msg.direction };
    } else if (context.label !== label.name || context.direction !== msg.direction) {
      return null;
    }
  }
  return context;
}

document.getElementById("add-to-analysis").addEventListener("click", () => {
  const checked = Array.from(document.querySelectorAll(".row-select:checked")).map(
    (cb) => Number(cb.dataset.index)
  );
  if (checked.length === 0) return;
  analysisSet = checked.map((index) => {
    const msg = state.messages.find((m) => m.index === index);
    const label = state.labels[index];
    const expected = label && !Number.isNaN(parseFloat(label.value)) ? String(label.value) : "";
    return { index, hexBytes: msg.hex_bytes, ascii: msg.ascii, expected, groupKey: msg.group_key };
  });
  lastMatches = [];
  lastRawMatches = [];
  lastClosestMiss = null;
  lastDebugHtml = "";
  spanSelection = { start: null, end: null };
  analysisContext = deriveSharedLabelContext(checked);
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
  lastClosestMiss = null;
  lastDebugHtml = "";
  spanSelection = { start: null, end: null };
  analysisContext = null;
  resetMatchFilters();
  document.getElementById("analysis-panel").classList.add("hidden");
});

// Right-click on a highlighted byte toggles its span into this set for
// side-by-side comparison — it never removes other spans from the blue
// highlighting, it just adds a green one alongside them.
let focusedSpans = new Set(); // keys of "start-end"
let hoveredSpan = null; // { start, end } while hovering a match-group's summary

function spanKey(start, end) {
  return `${start}-${end}`;
}

function resetMatchFilters() {
  document.getElementById("filter-order").value = "";
  document.getElementById("filter-precision").value = "";
  document.getElementById("filter-scale").value = "";
  document.getElementById("match-filters").classList.add("hidden");
  focusedSpans.clear();
  hoveredSpan = null;
}

document.getElementById("filter-order").addEventListener("change", renderMatchResults);
document.getElementById("filter-precision").addEventListener("change", renderMatchResults);
document.getElementById("filter-scale").addEventListener("input", renderMatchResults);

function highlightClass(offset) {
  const covering = lastMatches.filter((m) => offset >= m.start && offset <= m.end);
  if (covering.length === 0) return "";
  return covering.some((m) => focusedSpans.has(spanKey(m.start, m.end))) ? "match-highlight-focus" : "match-highlight";
}

function hoverClass(offset) {
  return hoveredSpan && offset >= hoveredSpan.start && offset <= hoveredSpan.end ? "match-hover" : "";
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
  document.getElementById("analysis-context-label").innerHTML = analysisContext
    ? `— <strong>${escapeHtml(analysisContext.label)}</strong> (${analysisContext.direction})`
    : "";

  const maxLen = Math.max(0, ...analysisSet.map((m) => m.hexBytes.length));
  let html = "<table><thead><tr><th>#</th>";
  for (let i = 0; i < maxLen; i++) html += `<th>${i}</th>`;
  html += `${showAscii ? "<th>ascii</th>" : ""}<th>expected value</th></tr></thead><tbody>`;

  analysisSet.forEach((msg, row) => {
    html += `<tr><td>${msg.index}</td>`;
    for (let i = 0; i < maxLen; i++) {
      const byte = msg.hexBytes[i];
      if (byte === undefined) { html += "<td></td>"; continue; }
      const predicted = byteClass(msg.groupKey, i, state.analysis);
      const highlighted = highlightClass(i);
      const cls = `${predicted} ${highlighted} ${hoverClass(i)} ${spanSelectClass(i)}`.trim();
      const titleAttr = highlighted ? ' title="Right-click to compare this span"' : "";
      html += `<td class="byte analysis-byte ${cls}" data-offset="${i}"${titleAttr}>${byte}</td>`;
    }
    if (showAscii) html += `<td>${escapeHtml(msg.ascii)}</td>`;
    html += `<td><input type="text" class="expected-input" data-row="${row}" value="${escapeHtml(msg.expected)}" placeholder="e.g. 5.0"></td>`;
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

    cell.addEventListener("contextmenu", (e) => {
      const offset = Number(cell.dataset.offset);
      const covering = lastMatches.find((m) => offset >= m.start && offset <= m.end);
      if (!covering) return;
      e.preventDefault();
      const key = spanKey(covering.start, covering.end);
      if (focusedSpans.has(key)) focusedSpans.delete(key);
      else focusedSpans.add(key);
      renderMatchResults();
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
  focusedSpans.clear();
  hoveredSpan = null;
  lastClosestMiss = null;
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
  document.getElementById("match-filters").classList.remove("hidden");
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

// A message that packs several samples (e.g. one ADC reading repeated N times)
// shows up here as many matching spans of the same width, evenly spaced by a
// constant stride — that repeating pattern is the tell, not a single field.
function longestConstantStrideRun(sortedSpans) {
  if (sortedSpans.length < 3) return null;
  const gaps = [];
  for (let i = 1; i < sortedSpans.length; i++) gaps.push(sortedSpans[i].start - sortedSpans[i - 1].start);

  let best = null;
  let runStart = 0;
  for (let i = 1; i <= gaps.length; i++) {
    if (i === gaps.length || gaps[i] !== gaps[runStart]) {
      const spanCount = i - runStart + 1;
      if (spanCount >= 3 && (!best || spanCount > best.spanCount)) {
        best = { stride: gaps[runStart], spanCount, spans: sortedSpans.slice(runStart, runStart + spanCount) };
      }
      runStart = i;
    }
  }
  return best;
}

function detectRepeatingArray(matches) {
  const seen = new Set();
  const byWidth = new Map();
  for (const m of matches) {
    const key = `${m.start}-${m.end}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const width = m.end - m.start + 1;
    if (!byWidth.has(width)) byWidth.set(width, []);
    byWidth.get(width).push({ start: m.start, end: m.end });
  }

  let best = null;
  for (const [width, group] of byWidth) {
    group.sort((a, b) => a.start - b.start);
    const run = longestConstantStrideRun(group);
    if (run && (!best || run.spanCount > best.spanCount)) best = { ...run, width };
  }
  return best;
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
  focusedSpans.clear();
  hoveredSpan = null;
  const tolerance = Number(document.getElementById("tolerance").value) || 0.15;
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
    // the actual bytes shown in the Analysis panel, not a message index —
    // an index isn't a stable identity once the capture buffer can trim
    // older messages while a live capture is still running, which would
    // otherwise make the server search completely different bytes
    messages_hex: analysisSet.map((m) => m.hexBytes.join("")),
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
  const { matches, closest_miss } = await res.json();
  lastRawMatches = matches;
  lastClosestMiss = closest_miss;
  document.getElementById("match-filters").classList.remove("hidden");

  const rangeNote = min_value !== null && max_value !== null ? `, device range [${min_value}, ${max_value}] (adds one derived precision-based scale per span)` : "";
  const byteOrderNote = byte_order ? `, assuming <strong>${byte_order}-endian</strong> (a "${searchDirection}" field has already been deciphered with this order)` : "";
  lastDebugHtml = `<p class="hint">Searched messages [${analysisSet.map((m) => m.index)}] with expected values [${requestBody.expected_values}], tolerance ${requestBody.tolerance}, scales ${requestBody.scales ? `[${requestBody.scales}]` : "(common defaults)"}, span ${requestBody.span ? `[${requestBody.span}]` : "(whole message — none set)"}${rangeNote}${byteOrderNote}.</p>`;
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
  lastMatches = matches; // drives blue highlighting for every passing match — unaffected by the green comparison selection

  // Right-clicking a span adds it to the comparison set without hiding any
  // other span's blue highlighting; only the results LIST below narrows to
  // the selected spans, so you can keep adding more to compare side by side.
  const displayMatches = focusedSpans.size > 0
    ? matches.filter((m) => focusedSpans.has(spanKey(m.start, m.end)))
    : matches;
  const filteredNote = displayMatches.length !== lastRawMatches.length ? ` (${lastRawMatches.length} before filters)` : "";

  const resultHtml = displayMatches.length
    ? `<h3>Matches (${displayMatches.length}${filteredNote})</h3><div class="match-groups-grid">${groupMatchesBySpan(displayMatches)
        .map((group) => {
          const entriesHtml = group.entries
            .map((m) => {
              const avgDecoded = m.decoded_values.reduce((a, b) => a + b, 0) / m.decoded_values.length;
              const actionsHtml = analysisContext
                ? `<div class="match-actions">
                     <button class="save-deciphered-btn" data-start="${m.start}" data-end="${m.end}" data-order="${m.byte_order}" data-scale="${m.scale}" title='Mark deciphered for "${escapeHtml(analysisContext.label)}" (${analysisContext.direction})'>Mark deciphered</button>
                     <button class="watch-btn" data-start="${m.start}" data-end="${m.end}" data-order="${m.byte_order}" data-scale="${m.scale}" data-precision="${m.precision ?? ""}" data-avg-decoded="${avgDecoded}">👁 Watch</button>
                   </div>`
                : "";
              const decoded = m.decoded_values.map((v) => v.toFixed(3)).join(", ");
              const precisionNote = m.precision ? ` <span class="precision-note">(precision ${m.precision})</span>` : "";
              return `<li>
                <div class="match-primary">decoded: [${decoded}] <span class="hint">vs expected [${lastExpectedValues}]</span></div>
                <div class="match-secondary hint">${m.byte_order}-endian · scale ${formatScale(m.scale)}${precisionNote}</div>
                ${actionsHtml}
              </li>`;
            })
            .join("");
          return `<div class="match-group" data-start="${group.start}" data-end="${group.end}"><h4>bytes [${group.start}-${group.end}] (width ${group.end - group.start + 1})</h4><ul>${entriesHtml}</ul></div>`;
        })
        .join("")}</div>`
    : "<p class=\"hint error-text\">No match found for the given expected values/tolerance/scales/filters.</p>";

  const repeatRun = detectRepeatingArray(matches);
  const repeatHtml = repeatRun
    ? `<p class="hint repeat-note">🔁 Looks like a repeated array: ${repeatRun.spanCount} samples of ${repeatRun.width} byte${repeatRun.width === 1 ? "" : "s"} each, stride ${repeatRun.stride} — offsets [${repeatRun.spans.map((s) => s.start).join(", ")}]. This message may pack multiple readings rather than one field.</p>`
    : "";

  const focusHtml =
    focusedSpans.size > 0
      ? `<p class="hint">🟢 Comparing ${focusedSpans.size} selected span${focusedSpans.size === 1 ? "" : "s"} — right-click another highlighted byte to add it, or <button id="clear-byte-focus" class="link-action-btn">clear</button></p>`
      : "";

  // Never a real match — deliberately kept out of the matches grid, with no
  // Mark-deciphered/Watch actions, so it can't be mistaken for one. A close
  // deviation hints "loosen tolerance/try another scale"; a wildly-off one
  // hints the value isn't transmitted directly at all (may need deriving
  // from more than one message, e.g. a delta between two readings).
  const closestMissHtml =
    displayMatches.length === 0 && lastClosestMiss
      ? `<details class="closest-miss">
           <summary>🔍 No exact match — closest attempt was off by ${lastClosestMiss.deviation.toFixed(3)} (click to see)</summary>
           <div class="closest-miss-detail">
             bytes [${lastClosestMiss.start}-${lastClosestMiss.end}], ${lastClosestMiss.byte_order}-endian, scale ${formatScale(lastClosestMiss.scale)}
             <div class="hint">decoded: [${lastClosestMiss.decoded_values.map((v) => v.toFixed(3)).join(", ")}] vs expected [${lastExpectedValues}]</div>
             <p class="hint">Close deviation? Try loosening tolerance or a different scale. Way off? The value might not be transmitted directly here — it may need deriving from more than one message.</p>
           </div>
         </details>`
      : "";

  document.getElementById("analysis-results").innerHTML = lastDebugHtml + focusHtml + repeatHtml + resultHtml + closestMissHtml;
  renderAnalysisPanel();

  document.getElementById("clear-byte-focus")?.addEventListener("click", () => {
    focusedSpans.clear();
    renderMatchResults();
  });

  document.querySelectorAll(".match-group").forEach((el) => {
    el.addEventListener("mouseenter", () => {
      hoveredSpan = { start: Number(el.dataset.start), end: Number(el.dataset.end) };
      renderAnalysisPanel();
    });
    el.addEventListener("mouseleave", () => {
      hoveredSpan = null;
      renderAnalysisPanel();
    });
  });

  document.querySelectorAll(".save-deciphered-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      pendingDecipher = {
        label: analysisContext.label,
        direction: analysisContext.direction,
        start: Number(btn.dataset.start),
        end: Number(btn.dataset.end),
        byte_order: btn.dataset.order,
        scale: Number(btn.dataset.scale),
      };
      document.getElementById("decipher-param-name").value = "";
      positionPanelNear(document.getElementById("decipher-name-panel"), btn);
      document.getElementById("decipher-name-panel").classList.remove("hidden");
      document.getElementById("decipher-param-name").focus();
    });
  });

  document.querySelectorAll(".watch-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      pendingWatch = {
        label: analysisContext.label,
        direction: analysisContext.direction,
        start: Number(btn.dataset.start),
        end: Number(btn.dataset.end),
        byte_order: btn.dataset.order,
        scale: Number(btn.dataset.scale),
        precision: btn.dataset.precision ? Number(btn.dataset.precision) : null,
      };
      document.getElementById("watch-param-name").value = "";
      document.getElementById("watch-tolerance").value = document.getElementById("tolerance").value || "0.15";
      positionPanelNear(document.getElementById("watch-panel"), btn);
      document.getElementById("watch-panel").classList.remove("hidden");
      document.getElementById("watch-param-name").focus();
    });
  });
}

function positionPanelNear(panel, anchorEl) {
  const rect = anchorEl.getBoundingClientRect();
  const width = panel.offsetWidth || 320;
  // the panel is still hidden (display:none) when this runs, so offsetHeight
  // reads 0 — fall back to a reasonable estimate for a small modal
  const height = panel.offsetHeight || 220;
  const margin = 12;
  let left = rect.left;
  let top = rect.bottom + 8;
  if (left + width > window.innerWidth - margin) left = window.innerWidth - width - margin;
  if (left < margin) left = margin;
  if (top + height > window.innerHeight - margin) {
    // not enough room below the anchor — flip above it instead, since this
    // is position:fixed and won't scroll into view once the page moves
    top = rect.top - height - 8;
  }
  if (top < margin) top = margin;
  panel.style.left = `${left}px`;
  panel.style.top = `${top}px`;
}

let pendingWatch = null;
let pendingDecipher = null;

document.getElementById("watch-save").addEventListener("click", async () => {
  if (!pendingWatch) return;
  const param = document.getElementById("watch-param-name").value.trim();
  if (!param) {
    document.getElementById("watch-param-name").focus();
    return;
  }
  const tolerance = Number(document.getElementById("watch-tolerance").value) || 0.15;
  await fetch("/api/monitors", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...pendingWatch, param, tolerance }),
  });
  pendingWatch = null;
  document.getElementById("watch-panel").classList.add("hidden");
  await loadData();
});

document.getElementById("watch-cancel").addEventListener("click", () => {
  pendingWatch = null;
  document.getElementById("watch-panel").classList.add("hidden");
});

document.getElementById("decipher-name-save").addEventListener("click", async () => {
  if (!pendingDecipher) return;
  const param = document.getElementById("decipher-param-name").value.trim();
  if (!param) {
    document.getElementById("decipher-param-name").focus();
    return;
  }
  await fetch("/api/deciphered", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...pendingDecipher, param }),
  });
  pendingDecipher = null;
  document.getElementById("decipher-name-panel").classList.add("hidden");
  playPigSniffAnimation();
  await loadData();
});

document.getElementById("decipher-name-cancel").addEventListener("click", () => {
  pendingDecipher = null;
  document.getElementById("decipher-name-panel").classList.add("hidden");
});

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
      .map((msg) => ({ msg, label: state.labels[msg.index] }))
      .filter(({ label, msg }) => label && label.name === monitor.label && msg.direction === monitor.direction)
      .map(({ msg, label }) => ({
        index: msg.index,
        expected: parseFloat(label.value),
        decoded: decodeHexSpan(msg.hex_bytes, monitor.start, monitor.end, monitor.byte_order) / monitor.scale,
      }))
      .filter((r) => !Number.isNaN(r.expected)); // not active for this message until it has its own value

    const anomalies = readings.filter((r) => Math.abs(r.decoded - r.expected) > monitor.tolerance);
    const statusHtml =
      readings.length === 0
        ? '<span class="hint">no labeled messages with a value yet</span>'
        : anomalies.length > 0
        ? `<span class="error-text">⚠ ANOMALY — #${anomalies.map((a) => `${a.index} (got ${a.decoded.toFixed(3)}, expected ${a.expected})`).join(", #")}</span>`
        : `<span class="monitor-ok">✓ OK (${readings.length} reading${readings.length === 1 ? "" : "s"} checked against their own labeled value)</span>`;

    const precisionNote = monitor.precision ? ` <span class="precision-note">(precision ${monitor.precision})</span>` : "";
    const deciphered = state.deciphered[key];
    const decipherHtml = deciphered
      ? ` <span class="deciphered-note">deciphered: bytes [${deciphered.start}-${deciphered.end}], ${deciphered.byte_order}-endian, scale ${deciphered.scale}</span>`
      : ` <button class="mark-deciphered-from-monitor-btn" data-key="${escapeHtml(key)}">Mark deciphered</button>`;
    html += `<li>
      <strong>${escapeHtml(monitor.label)}</strong> (${monitor.direction}) — param "${escapeHtml(monitor.param)}", bytes [${monitor.start}-${monitor.end}], ${monitor.byte_order}-endian, scale ${formatScale(monitor.scale)}${precisionNote} —
      tolerance ± ${monitor.tolerance}: ${statusHtml}
      <button class="stop-watch-btn" data-label="${escapeHtml(monitor.label)}" data-direction="${monitor.direction}" data-param="${escapeHtml(monitor.param)}">Stop watching</button>${decipherHtml}
    </li>`;
  }
  html += "</ul>";
  container.innerHTML = html;

  document.querySelectorAll(".stop-watch-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await fetch("/api/monitors", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: btn.dataset.label, direction: btn.dataset.direction, param: btn.dataset.param }),
      });
      await loadData();
    });
  });

  document.querySelectorAll(".mark-deciphered-from-monitor-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const monitor = state.monitors[btn.dataset.key];
      await fetch("/api/deciphered", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: monitor.label,
          direction: monitor.direction,
          param: monitor.param,
          start: monitor.start,
          end: monitor.end,
          byte_order: monitor.byte_order,
          scale: monitor.scale,
        }),
      });
      playPigSniffAnimation();
      await loadData();
    });
  });
}

let selectedConsolidateKeys = new Set(); // group keys ("name::direction") checked for consolidation

function renderLabelGroups() {
  const groups = {};
  for (const [indexStr, label] of Object.entries(state.labels)) {
    if (!label || !label.name) continue;
    const index = Number(indexStr);
    const msg = state.messages.find((m) => m.index === index);
    if (!msg) continue;
    const key = `${label.name}::${msg.direction}`;
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

  // the filter <select> lives inside this dynamically-regenerated HTML (it
  // only makes sense to show while there's at least one group), so its
  // chosen value has to be captured before the rewrite and restored after
  const previousFilter = document.getElementById("label-group-filter")?.value || "";

  function renderGroupLi(key) {
    const group = groups[key];
    const withValues = group.members.filter((m) => m.value !== null);
    const distinctValues = new Set(withValues.map((m) => m.value)).size;

    // One message label can still carry several independently deciphered
    // fields (e.g. a "set_waveform" command's wave_type/freq/amplitude/offset)
    // — they just aren't named up front here. Naming happens per-match when
    // you Mark deciphered or Watch, so this just lists what's been named so far.
    const decipheredFields = decipheredFieldsFor(group.name, group.direction);
    if (previousFilter === "deciphered" && decipheredFields.length === 0) return "";
    if (previousFilter === "not-deciphered" && decipheredFields.length > 0) return "";

    const decipheredNote = decipheredFields.length
      ? ` — <span class="deciphered-note">deciphered: ${decipheredFields
          .map((d) => `${escapeHtml(d.param)} (bytes [${d.start}-${d.end}], ${d.byte_order}-endian, scale ${formatScale(d.scale)})`)
          .join(", ")}</span>`
      : "";

    const consolidateCheckbox = `<input type="checkbox" class="consolidate-select-checkbox" data-key="${escapeHtml(key)}" title="Select for consolidating with another label" ${selectedConsolidateKeys.has(key) ? "checked" : ""}>`;
    const summaryLine = `${consolidateCheckbox} <strong>${escapeHtml(group.name)}</strong> (${group.members.length} labeled, ${withValues.length} with a value, ${distinctValues} distinct)${decipheredNote}`;
    const actionButtons = `
      <button class="analyze-group-btn" data-key="${escapeHtml(key)}" ${distinctValues < 2 ? "disabled" : ""}>Analyze</button>
      <button class="generate-driver-btn" data-label="${escapeHtml(group.name)}" data-direction="${group.direction}" ${decipheredFields.length ? "" : "disabled"} title="${decipheredFields.length ? "" : "Mark deciphered first"}">Generate driver function</button>
      <button class="remove-group-btn danger" data-key="${escapeHtml(key)}" title="Remove this label from every message in the group">Remove label</button>`;

    // every group stays in the list — a fully deciphered one just collapses
    // down to its one-line summary so the panel doesn't keep growing as you
    // finish more labels, without losing track of what's already been solved
    return decipheredFields.length
      ? `<li><details class="label-group-details"><summary>${summaryLine}</summary>${actionButtons}</details></li>`
      : `<li>${summaryLine}${actionButtons}</li>`;
  }

  // a stale key (its group no longer exists — consolidated away, or its
  // last message got unlabeled) shouldn't linger as a phantom selection
  for (const key of Array.from(selectedConsolidateKeys)) {
    if (!groups[key]) selectedConsolidateKeys.delete(key);
  }

  // outputs (commands the host sends) and inputs (readings the host
  // receives) are different mental categories entirely — mixing them in
  // one list made it harder to scan for "what can I send" vs "what am I
  // reading back"
  const outputsHtml = keys.filter((k) => groups[k].direction === "OUT").map(renderGroupLi).join("");
  const inputsHtml = keys.filter((k) => groups[k].direction === "IN").map(renderGroupLi).join("");

  // consolidating only makes sense within one direction — merging an OUT
  // command with an IN reading isn't "the same message, different fields"
  const selectedDirections = new Set(Array.from(selectedConsolidateKeys).map((k) => groups[k]?.direction));
  const canConsolidate = selectedConsolidateKeys.size >= 2 && selectedDirections.size === 1;

  let html = `<h2>Label groups</h2>
    <label>Show
      <select id="label-group-filter">
        <option value="">All</option>
        <option value="deciphered">Deciphered</option>
        <option value="not-deciphered">Not deciphered</option>
      </select>
    </label>
    <button id="consolidate-labels-btn" ${canConsolidate ? "" : "disabled"} title="Check two or more labels (same direction) that turned out to be different fields of the same message, then merge them into one">Consolidate selected labels${selectedConsolidateKeys.size ? ` (${selectedConsolidateKeys.size})` : ""}</button>`;
  if (outputsHtml) html += `<h3>Outputs (OUT)</h3><ul>${outputsHtml}</ul>`;
  if (inputsHtml) html += `<h3>Inputs (IN)</h3><ul>${inputsHtml}</ul>`;
  if (!outputsHtml && !inputsHtml) html += `<p class="hint">No groups match this filter.</p>`;
  container.innerHTML = html;
  document.getElementById("label-group-filter").value = previousFilter;
  document.getElementById("label-group-filter").addEventListener("change", renderLabelGroups);

  document.querySelectorAll(".consolidate-select-checkbox").forEach((cb) => {
    cb.addEventListener("change", (e) => {
      e.stopPropagation();
      if (e.target.checked) selectedConsolidateKeys.add(e.target.dataset.key);
      else selectedConsolidateKeys.delete(e.target.dataset.key);
      renderLabelGroups();
    });
  });

  document.getElementById("consolidate-labels-btn").addEventListener("click", async () => {
    const selectedGroups = Array.from(selectedConsolidateKeys).map((k) => groups[k]).filter(Boolean);
    const direction = selectedGroups[0].direction;
    const names = selectedGroups.map((g) => g.name);
    const newName = prompt(
      `Merge ${names.map((n) => `"${n}"`).join(", ")} (${direction}) into one label — what should the combined label be called?`,
      names[0]
    );
    if (!newName || !newName.trim()) return;
    const res = await fetch("/api/consolidate_labels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ names, direction, new_name: newName.trim() }),
    });
    const result = await res.json();
    if (result.error) {
      alert(`Couldn't consolidate: ${result.error}`);
      return;
    }
    selectedConsolidateKeys.clear();
    await loadData();
  });

  document.querySelectorAll(".analyze-group-btn").forEach((btn) => {
    btn.addEventListener("click", () => analyzeLabelGroup(groups[btn.dataset.key]));
  });

  document.querySelectorAll(".generate-driver-btn").forEach((btn) => {
    btn.addEventListener("click", () => generateDriver(btn.dataset.label, btn.dataset.direction));
  });

  document.querySelectorAll(".remove-group-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const group = groups[btn.dataset.key];
      if (!confirm(`Remove the "${group.name}" label from all ${group.members.length} message(s)? This can't be undone.`)) return;
      await fetch("/api/labels_by_name", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: group.name, direction: group.direction }),
      });
      for (const m of group.members) delete state.labels[m.index];
      render();
    });
  });
}

let driverGenerationSpinner = null;

function startDriverGenerationSpinner(codeEl) {
  clearInterval(driverGenerationSpinner);
  let dots = 0;
  codeEl.textContent = "Generating";
  driverGenerationSpinner = setInterval(() => {
    dots = (dots + 1) % 4;
    codeEl.textContent = "Generating" + ".".repeat(dots);
  }, 400);
}

async function generateDriver(label, direction) {
  const panel = document.getElementById("driver-panel");
  const codeEl = document.getElementById("driver-code");
  const noteEl = document.getElementById("driver-mock-note");
  document.getElementById("driver-heading").firstChild.textContent = "Generated driver function ";
  document.getElementById("driver-warnings").innerHTML = "";
  panel.classList.remove("hidden");
  noteEl.textContent = "";
  startDriverGenerationSpinner(codeEl);

  let result;
  try {
    const res = await fetch("/api/generate_driver", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label, direction }),
    });
    result = await res.json();
  } catch (e) {
    clearInterval(driverGenerationSpinner);
    codeEl.textContent = `Error: request failed (${e.message}) — check that the server is running and reachable.`;
    return;
  }
  clearInterval(driverGenerationSpinner);
  if (result.error) {
    codeEl.textContent = `Error: ${result.error}`;
    return;
  }
  codeEl.textContent = result.code;
  noteEl.textContent = result.mock
    ? "(mock output — export ANTHROPIC_API_KEY on the server and retry for a real generated function)"
    : "";
}

async function generateFullDriver() {
  const panel = document.getElementById("driver-panel");
  const codeEl = document.getElementById("driver-code");
  const noteEl = document.getElementById("driver-mock-note");
  const warningsEl = document.getElementById("driver-warnings");
  document.getElementById("driver-heading").firstChild.textContent = "Generated full driver ";
  warningsEl.innerHTML = "";
  panel.classList.remove("hidden");
  noteEl.textContent = "";
  startDriverGenerationSpinner(codeEl);

  let result;
  try {
    const res = await fetch("/api/generate_full_driver", { method: "POST" });
    result = await res.json();
  } catch (e) {
    clearInterval(driverGenerationSpinner);
    codeEl.textContent = `Error: request failed (${e.message}) — check that the server is running and reachable.`;
    return;
  }
  clearInterval(driverGenerationSpinner);
  if (result.error) {
    codeEl.textContent = `Error: ${result.error}`;
    return;
  }
  codeEl.textContent = result.code;
  noteEl.textContent = result.mock
    ? "(mock output — export ANTHROPIC_API_KEY on the server and retry for a real generated function)"
    : "";
  if (result.warnings && result.warnings.length) {
    warningsEl.innerHTML = `<div class="warning-banner"><strong>Heads up:</strong><ul>${result.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul></div>`;
  }
}

document.getElementById("generate-full-driver").addEventListener("click", generateFullDriver);

document.getElementById("driver-close").addEventListener("click", () => {
  clearInterval(driverGenerationSpinner);
  document.getElementById("driver-panel").classList.add("hidden");
});

document.getElementById("driver-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText(document.getElementById("driver-code").textContent);
});

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

document.getElementById("new-instrument").addEventListener("click", async () => {
  if (!confirm("Start on a new instrument? This wipes captures, labels, deciphered fields, AND watches — everything solved for the current device is gone. This can't be undone.")) return;
  await fetch("/api/instrument", { method: "DELETE" });
  analysisSet = [];
  lastMatches = [];
  document.getElementById("analysis-panel").classList.add("hidden");
  await loadData();
});

let pollingInterval = null;

function setPollingInterval(active) {
  if (active && !pollingInterval) {
    pollingInterval = setInterval(loadData, 150);
  } else if (!active && pollingInterval) {
    clearInterval(pollingInterval);
    pollingInterval = null;
  }
}

document.getElementById("toggle-full-timestamp").addEventListener("change", (e) => {
  showFullTimestamp = e.target.checked;
  render();
});

document.getElementById("toggle-ascii").addEventListener("change", (e) => {
  showAscii = e.target.checked;
  render();
});

document.getElementById("toggle-deciphered-values").addEventListener("click", () => {
  showDecipheredValues = !showDecipheredValues;
  document.getElementById("toggle-deciphered-values").textContent = showDecipheredValues ? "Hide deciphered" : "Show deciphered";
  document.getElementById("toggle-deciphered-values").classList.toggle("active", showDecipheredValues);
  render();
});

document.getElementById("direction-filter").addEventListener("change", render);

async function loadCaptureConfig() {
  const res = await fetch("/api/capture_config");
  const config = await res.json();
  document.getElementById("capture-interface").value = config.interface;
  document.getElementById("capture-device").value = config.device_address;
}

let captureConfigSaveTimeout = null;

function scheduleCaptureConfigSave() {
  // debounced, not saved on every keystroke — the backend restarts the
  // capture thread when this changes while running, which you don't want
  // happening on every character typed into the interface field
  clearTimeout(captureConfigSaveTimeout);
  captureConfigSaveTimeout = setTimeout(async () => {
    const interfaceValue = document.getElementById("capture-interface").value.trim() || "usbmon3";
    const deviceValue = Number(document.getElementById("capture-device").value) || 2;
    await fetch("/api/capture_config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: interfaceValue, device_address: deviceValue }),
    });
  }, 600);
}

document.getElementById("capture-interface").addEventListener("input", scheduleCaptureConfigSave);
document.getElementById("capture-device").addEventListener("input", scheduleCaptureConfigSave);

document.getElementById("scan-lsusb").addEventListener("click", async () => {
  const box = document.getElementById("lsusb-output");
  box.textContent = "Scanning...";
  box.classList.remove("hidden");
  const res = await fetch("/api/lsusb");
  const { output } = await res.json();
  box.textContent = output;
});

document.getElementById("detect-line-coding").addEventListener("click", async () => {
  const status = document.getElementById("line-coding-status");
  status.textContent = "Waiting for a SET_LINE_CODING request (up to 15s) — reconnect the device's original control software now...";
  const interfaceValue = document.getElementById("capture-interface").value.trim() || "usbmon3";
  const deviceValue = Number(document.getElementById("capture-device").value) || 2;
  const res = await fetch("/api/detect_line_coding", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ interface: interfaceValue, device_address: deviceValue }),
  });
  const result = await res.json();
  if (!result.ok) {
    status.textContent = result.error;
    return;
  }
  const s = result.settings;
  status.textContent = `Detected: baudrate=${s.baudrate}, bytesize=${s.bytesize}, parity=${s.parity}, stopbits=${s.stopbits}`;
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
  btn.textContent = captureEnabled ? "Disable capture" : "Enable capture";
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

async function disableCapture() {
  if (!captureEnabled) return;
  await fetch("/api/capture/disable", { method: "POST" });
  setPollingInterval(false);
  checkCaptureStatus();
}

document.getElementById("toggle-capture").addEventListener("click", async () => {
  const enabling = !captureEnabled;
  if (enabling) {
    // apply whatever's currently typed immediately, rather than depending
    // on the debounced auto-save (600ms after the last keystroke) having
    // already fired — otherwise enabling right after typing would silently
    // start capture on stale interface/device settings
    clearTimeout(captureConfigSaveTimeout);
    const interfaceValue = document.getElementById("capture-interface").value.trim() || "usbmon3";
    const deviceValue = Number(document.getElementById("capture-device").value) || 2;
    await fetch("/api/capture_config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: interfaceValue, device_address: deviceValue }),
    });
  }
  await fetch(`/api/capture/${enabling ? "enable" : "disable"}`, { method: "POST" });
  setPollingInterval(enabling);
  checkCaptureStatus();
});

setInterval(checkCaptureStatus, 3000);

loadCaptureConfig();
checkCaptureStatus();
loadData();
