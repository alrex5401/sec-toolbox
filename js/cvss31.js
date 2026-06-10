/*
 * CVSS v3.1 Base Score 計算（依 FIRST CVSS v3.1 Specification Document 公式自寫）
 * https://www.first.org/cvss/v3.1/specification-document
 * 僅 Base Metric Group。
 */
(function (global) {
  "use strict";

  var WEIGHTS = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    // PR 權重依 Scope 變動
    PR: {
      U: { N: 0.85, L: 0.62, H: 0.27 },
      C: { N: 0.85, L: 0.68, H: 0.5 }
    },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 }
  };

  var METRICS = {
    AV: ["N", "A", "L", "P"],
    AC: ["L", "H"],
    PR: ["N", "L", "H"],
    UI: ["N", "R"],
    S: ["U", "C"],
    C: ["H", "L", "N"],
    I: ["H", "L", "N"],
    A: ["H", "L", "N"]
  };

  // 官方 Roundup 函式（spec Appendix A 偽碼、避免浮點誤差）
  function roundup(input) {
    var intInput = Math.round(input * 100000);
    if (intInput % 10000 === 0) {
      return intInput / 100000;
    }
    return (Math.floor(intInput / 10000) + 1) / 10;
  }

  function severity(score) {
    if (score === 0) return "None";
    if (score <= 3.9) return "Low";
    if (score <= 6.9) return "Medium";
    if (score <= 8.9) return "High";
    return "Critical";
  }

  /**
   * m = { AV, AC, PR, UI, S, C, I, A }（單字母值）
   * 回傳 { score, severity, vector }；輸入不全回傳 null
   */
  function calculate(m) {
    for (var k in METRICS) {
      if (!m[k] || METRICS[k].indexOf(m[k]) === -1) return null;
    }

    var iss =
      1 -
      (1 - WEIGHTS.CIA[m.C]) * (1 - WEIGHTS.CIA[m.I]) * (1 - WEIGHTS.CIA[m.A]);

    var impact;
    if (m.S === "U") {
      impact = 6.42 * iss;
    } else {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    }

    var exploitability =
      8.22 *
      WEIGHTS.AV[m.AV] *
      WEIGHTS.AC[m.AC] *
      WEIGHTS.PR[m.S][m.PR] *
      WEIGHTS.UI[m.UI];

    var score;
    if (impact <= 0) {
      score = 0;
    } else if (m.S === "U") {
      score = roundup(Math.min(impact + exploitability, 10));
    } else {
      score = roundup(Math.min(1.08 * (impact + exploitability), 10));
    }

    var vector =
      "CVSS:3.1/AV:" + m.AV + "/AC:" + m.AC + "/PR:" + m.PR + "/UI:" + m.UI +
      "/S:" + m.S + "/C:" + m.C + "/I:" + m.I + "/A:" + m.A;

    return { score: score, severity: severity(score), vector: vector };
  }

  /** 解析 CVSS:3.1 向量字串 → metrics object；格式錯回傳 null */
  function parseVector(str) {
    if (!str) return null;
    var s = str.trim();
    var m = {};
    var parts = s.split("/");
    if (!/^CVSS:3\.[01]$/.test(parts[0])) return null;
    for (var i = 1; i < parts.length; i++) {
      var kv = parts[i].split(":");
      if (kv.length !== 2) return null;
      if (METRICS[kv[0]] && METRICS[kv[0]].indexOf(kv[1]) !== -1) {
        m[kv[0]] = kv[1];
      }
    }
    for (var k in METRICS) {
      if (!m[k]) return null;
    }
    return m;
  }

  global.CVSS31 = { calculate: calculate, parseVector: parseVector, METRICS: METRICS };
})(window);
