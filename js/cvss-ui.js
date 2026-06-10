/* CVSS 計算器頁邏輯 — 3.1 自寫公式（cvss31.js）+ 4.0 官方 cvss40.js */
(function () {
  "use strict";

  var SEV_ZH = { None: "無", Low: "低", Medium: "中", High: "高", Critical: "重大" };

  function sevClass(sev) { return "sev-" + sev.toLowerCase(); }

  function severityOf(score) {
    if (score === 0) return "None";
    if (score <= 3.9) return "Low";
    if (score <= 6.9) return "Medium";
    if (score <= 8.9) return "High";
    return "Critical";
  }

  /* ── metric 定義（含中文說明） ────────────────── */

  var DEF31 = [
    { key: "AV", name: "攻擊途徑 (AV)", opts: [["N", "網路"], ["A", "相鄰網路"], ["L", "本機"], ["P", "實體"]] },
    { key: "AC", name: "攻擊複雜度 (AC)", opts: [["L", "低"], ["H", "高"]] },
    { key: "PR", name: "所需權限 (PR)", opts: [["N", "無"], ["L", "低"], ["H", "高"]] },
    { key: "UI", name: "使用者互動 (UI)", opts: [["N", "不需要"], ["R", "需要"]] },
    { key: "S", name: "影響範圍 (S)", opts: [["U", "不變"], ["C", "擴散"]] },
    { key: "C", name: "機密性衝擊 (C)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] },
    { key: "I", name: "完整性衝擊 (I)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] },
    { key: "A", name: "可用性衝擊 (A)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] }
  ];

  var DEF40 = [
    { key: "AV", name: "攻擊途徑 (AV)", opts: [["N", "網路"], ["A", "相鄰網路"], ["L", "本機"], ["P", "實體"]] },
    { key: "AC", name: "攻擊複雜度 (AC)", opts: [["L", "低"], ["H", "高"]] },
    { key: "AT", name: "攻擊前提條件 (AT)", opts: [["N", "無"], ["P", "有"]] },
    { key: "PR", name: "所需權限 (PR)", opts: [["N", "無"], ["L", "低"], ["H", "高"]] },
    { key: "UI", name: "使用者互動 (UI)", opts: [["N", "不需要"], ["P", "被動"], ["A", "主動"]] },
    { key: "VC", name: "受攻擊系統：機密性 (VC)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] },
    { key: "VI", name: "受攻擊系統：完整性 (VI)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] },
    { key: "VA", name: "受攻擊系統：可用性 (VA)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] },
    { key: "SC", name: "後續系統：機密性 (SC)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] },
    { key: "SI", name: "後續系統：完整性 (SI)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] },
    { key: "SA", name: "後續系統：可用性 (SA)", opts: [["H", "高"], ["L", "低"], ["N", "無"]] }
  ];

  var state31 = {};
  var state40 = {};

  /* ── UI 建構 ────────────────── */

  function buildMetricRows(defs, container, state, onChange) {
    defs.forEach(function (d) {
      var row = document.createElement("div");
      row.className = "metric-row";

      var nameEl = document.createElement("div");
      nameEl.className = "metric-name";
      nameEl.textContent = d.name;
      row.appendChild(nameEl);

      var group = document.createElement("div");
      group.className = "opt-group";
      d.opts.forEach(function (o) {
        var btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = o[1] + "（" + o[0] + "）";
        btn.dataset.key = d.key;
        btn.dataset.val = o[0];
        btn.addEventListener("click", function () {
          state[d.key] = o[0];
          var sibs = group.querySelectorAll("button");
          for (var i = 0; i < sibs.length; i++) sibs[i].classList.remove("selected");
          btn.classList.add("selected");
          onChange();
        });
        group.appendChild(btn);
      });
      row.appendChild(group);
      container.appendChild(row);
    });
  }

  function syncButtons(container, state) {
    var btns = container.querySelectorAll("button[data-key]");
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      if (state[b.dataset.key] === b.dataset.val) b.classList.add("selected");
      else b.classList.remove("selected");
    }
  }

  function showScore(scoreEl, sevEl, score) {
    var sev = severityOf(score);
    scoreEl.textContent = score.toFixed(1);
    sevEl.textContent = SEV_ZH[sev] + " " + sev;
    sevEl.className = "severity-pill " + sevClass(sev);
  }

  /* ── 3.1 ────────────────── */

  var panel31 = document.getElementById("metrics-31");
  var score31 = document.getElementById("score-31");
  var sev31 = document.getElementById("sev-31");
  var vec31 = document.getElementById("vector-31");
  var hint31 = document.getElementById("hint-31");

  function update31() {
    var r = window.CVSS31.calculate(state31);
    if (!r) {
      var remaining = DEF31.filter(function (d) { return !state31[d.key]; }).length;
      hint31.textContent = "還有 " + remaining + " 個欄位未選。";
      score31.textContent = "–";
      sev31.textContent = "";
      sev31.className = "severity-pill";
      vec31.textContent = "";
      return;
    }
    hint31.textContent = "";
    showScore(score31, sev31, r.score);
    vec31.textContent = r.vector;
  }

  buildMetricRows(DEF31, panel31, state31, update31);

  document.getElementById("parse-31").addEventListener("click", function () {
    var m = window.CVSS31.parseVector(document.getElementById("vector-in-31").value);
    var msg = document.getElementById("parse-msg-31");
    if (!m) { msg.textContent = "向量格式不正確（需含 CVSS:3.1 前綴與全部 8 個 Base 欄位）。"; return; }
    msg.textContent = "";
    // 就地更新、不可整個換掉物件（按鈕 closure 抓的是原物件）
    Object.keys(state31).forEach(function (k) { delete state31[k]; });
    Object.assign(state31, m);
    syncButtons(panel31, state31);
    update31();
  });

  /* ── 4.0（官方 CVSS40 class） ────────────────── */

  var panel40 = document.getElementById("metrics-40");
  var score40 = document.getElementById("score-40");
  var sev40 = document.getElementById("sev-40");
  var vec40 = document.getElementById("vector-40");
  var hint40 = document.getElementById("hint-40");

  function vector40() {
    var s = "CVSS:4.0";
    DEF40.forEach(function (d) { s += "/" + d.key + ":" + state40[d.key]; });
    return s;
  }

  function update40() {
    var missing = DEF40.filter(function (d) { return !state40[d.key]; }).length;
    if (missing) {
      hint40.textContent = "還有 " + missing + " 個欄位未選。";
      score40.textContent = "–";
      sev40.textContent = "";
      sev40.className = "severity-pill";
      vec40.textContent = "";
      return;
    }
    var v = vector40();
    try {
      // CVSS40 是 cvss40.js 的頂層 class 宣告＝global lexical binding、不掛 window
      var c = new CVSS40(v);
      hint40.textContent = "";
      showScore(score40, sev40, c.score);
      vec40.textContent = v;
    } catch (e) {
      hint40.textContent = "計算失敗：" + e.message;
    }
  }

  buildMetricRows(DEF40, panel40, state40, update40);

  document.getElementById("parse-40").addEventListener("click", function () {
    var raw = document.getElementById("vector-in-40").value.trim();
    var msg = document.getElementById("parse-msg-40");
    try {
      // 先讓官方 class 驗證向量、再回填 Base 欄位到按鈕
      var c = new CVSS40(raw);
      var m = {};
      raw.split("/").forEach(function (p) {
        var kv = p.split(":");
        if (kv.length === 2) m[kv[0]] = kv[1];
      });
      var lack = DEF40.filter(function (d) { return !m[d.key]; });
      if (lack.length) { msg.textContent = "缺少 Base 欄位：" + lack.map(function (d) { return d.key; }).join("、"); return; }
      msg.textContent = "";
      // 就地更新、不可整個換掉物件（按鈕 closure 抓的是原物件）
      Object.keys(state40).forEach(function (k) { delete state40[k]; });
      DEF40.forEach(function (d) { state40[d.key] = m[d.key]; });
      syncButtons(panel40, state40);
      update40();
    } catch (e) {
      msg.textContent = "向量格式不正確（官方驗證未通過）。";
    }
  });

  /* ── tab 切換 + 複製 ────────────────── */

  var tabs = document.querySelectorAll(".tabs button");
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].addEventListener("click", function () {
      for (var j = 0; j < tabs.length; j++) tabs[j].classList.remove("active");
      this.classList.add("active");
      var which = this.dataset.tab;
      document.getElementById("panel-31").style.display = which === "31" ? "" : "none";
      document.getElementById("panel-40").style.display = which === "40" ? "" : "none";
    });
  }

  var copyBtns = document.querySelectorAll("[data-copy]");
  for (var c = 0; c < copyBtns.length; c++) {
    copyBtns[c].addEventListener("click", function () {
      var text = document.getElementById(this.dataset.copy).textContent;
      if (!text) return;
      var self = this;
      navigator.clipboard.writeText(text).then(function () {
        var orig = self.textContent;
        self.textContent = "已複製 ✓";
        setTimeout(function () { self.textContent = orig; }, 1200);
      });
    });
  }
})();
