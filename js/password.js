/* 密碼強度檢查頁邏輯 — zxcvbn-ts 本地版、全程瀏覽器內計算 */
(function () {
  "use strict";

  var core = window.zxcvbnts.core;
  var common = window.zxcvbnts["language-common"];
  var en = window.zxcvbnts["language-en"];

  var dict = {};
  var k;
  for (k in common.dictionary) dict[k] = common.dictionary[k];
  for (k in en.dictionary) dict[k] = en.dictionary[k];

  core.zxcvbnOptions.setOptions({
    translations: window.zxcvbnZhTW,
    graphs: common.adjacencyGraphs,
    dictionary: dict
  });

  var SCORE_LABELS = [
    { text: "非常弱", color: "#b05656" },
    { text: "弱", color: "#b05656" },
    { text: "普通", color: "#b3823f" },
    { text: "強", color: "#4f8a6d" },
    { text: "非常強", color: "#3e7a9c" }
  ];

  var input = document.getElementById("pw-input");
  var toggleBtn = document.getElementById("pw-toggle");
  var bar = document.getElementById("strength-bar");
  var scoreLabel = document.getElementById("score-label");
  var crackBox = document.getElementById("crack-times");
  var feedbackBox = document.getElementById("feedback");
  var resultCard = document.getElementById("result-card");

  toggleBtn.addEventListener("click", function () {
    var showing = input.type === "text";
    input.type = showing ? "password" : "text";
    toggleBtn.textContent = showing ? "顯示" : "隱藏";
  });

  function render() {
    var pw = input.value;
    if (!pw) {
      resultCard.style.display = "none";
      return;
    }
    resultCard.style.display = "";

    // zxcvbn 計算超過 100 字元會變慢、截斷評估（行為與官方展示一致）
    var result = core.zxcvbn(pw.slice(0, 100));
    var score = result.score; // 0-4
    var label = SCORE_LABELS[score];

    var segs = bar.children;
    for (var i = 0; i < segs.length; i++) {
      segs[i].style.background = i <= score ? label.color : "rgba(55,69,97,.12)";
    }
    scoreLabel.textContent = label.text + "（" + score + " / 4 級）";
    scoreLabel.style.color = label.color;

    var ct = result.crackTimesDisplay;
    crackBox.innerHTML = "";
    var rows = [
      ["線上攻擊（有節流、每小時 100 次）", ct.onlineThrottling100PerHour],
      ["線上攻擊（無節流、每秒 10 次）", ct.onlineNoThrottling10PerSecond],
      ["離線攻擊（慢雜湊、每秒 1 萬次）", ct.offlineSlowHashing1e4PerSecond],
      ["離線攻擊（快雜湊、每秒 100 億次）", ct.offlineFastHashing1e10PerSecond]
    ];
    rows.forEach(function (r) {
      var li = document.createElement("li");
      var b = document.createElement("strong");
      b.textContent = r[1];
      li.textContent = r[0] + "：";
      li.appendChild(b);
      crackBox.appendChild(li);
    });

    feedbackBox.innerHTML = "";
    var fb = result.feedback;
    if (fb.warning) {
      var w = document.createElement("p");
      w.className = "fb-warning";
      w.textContent = "⚠ " + fb.warning;
      feedbackBox.appendChild(w);
    }
    if (fb.suggestions && fb.suggestions.length) {
      var ul = document.createElement("ul");
      fb.suggestions.forEach(function (s) {
        var li = document.createElement("li");
        li.textContent = s;
        ul.appendChild(li);
      });
      feedbackBox.appendChild(ul);
    }
    if (!fb.warning && (!fb.suggestions || !fb.suggestions.length)) {
      var ok = document.createElement("p");
      ok.textContent = "沒有發現明顯弱點。";
      feedbackBox.appendChild(ok);
    }
  }

  input.addEventListener("input", core.debounce(render, 120, false));

  // 防表單意外送出（本頁根本沒有 form action、雙保險）
  document.addEventListener("submit", function (e) { e.preventDefault(); });
})();
