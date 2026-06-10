# 仆洛宅資安工具箱（sec-toolbox）

公開、免費、純前端的資安小工具站。`https://toolbox.angelz13.com`

- 🔑 密碼強度檢查（zxcvbn 引擎、CISSP 觀點解說）
- 📊 CVSS 計算器（3.1 自寫公式＋4.0 官方計算邏輯、向量輸出/解析）

## 隱私設計

- 純靜態、零後端、零 analytics、零 cookie、零 CDN。
- 每頁 CSP `connect-src 'none'`：瀏覽器層封鎖所有對外連線、使用者輸入技術上不可能離開分頁。
- 所有第三方程式庫本地打包（vendored）、不引外部資源。

## 第三方授權

| 元件 | 授權 | 來源 |
|---|---|---|
| `js/zxcvbn/`（@zxcvbn-ts core 3.0.4 / language-common 3.0.4 / language-en 3.0.2） | MIT | https://github.com/zxcvbn-ts/zxcvbn |
| `js/cvss40.js` | BSD-2-Clause（Copyright FIRST.ORG, Inc., Red Hat, and contributors） | https://github.com/RedHatProductSecurity/cvss-v4-calculator |
| `js/cvss31.js` | 自寫（依 FIRST CVSS v3.1 規格文件公式、經官方測試向量驗證） | — |

CVSS 為 FIRST.ORG 之標準。本站分數為依官方規範計算之參考值、非官方判定。

## 本地開發

無 build step。`python3 -m http.server 8000` 後開 `http://localhost:8000/`。
