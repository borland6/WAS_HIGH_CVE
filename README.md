# IBM WAS High-Risk CVE Scraper

自動從 IBM Support 網站擷取 IBM WebSphere Application Server 的 Security Bulletin，
篩選高風險 CVE（CVSS ≥ 7.0），並生成 Bootstrap 響應式 HTML 報表。

---

## 功能特色

- 🔍 **自動爬取** IBM Security Bulletin 搜尋頁，支援多頁分頁
- 🎯 **雙重篩選**：Severity（High / Critical）且 Publish Date 在指定天數內
- 📊 **個別 CVE 展開**：一篇 Bulletin 含多個 CVE 時，各自獨立列出
- 🏷️ **類型識別**：自動區分 WAS Traditional（V9/V8）與 Liberty Bulletin
- 🔧 **Fixpack 解析**：正確取 `Apply Fix Pack` 後的目標版本號（非舊版）
- 📄 **Bootstrap 5 + DataTables**：可排序、可搜尋、RWD 響應式 HTML 報表
- 🕒 **時間戳記檔名**：每次執行自動產生含日期時間的報表檔名

---

## 報表欄位

| # | 欄位 | 說明 |
|---|------|------|
| 1 | Security Bulletin | 標題（含原始頁面連結） |
| 2 | Affected WAS Version | Traditional → `9.0, 8.5`；Liberty → 版本範圍，例如 `17.0.0.3 - 26.0.0.7` |
| 3 | CVE-ID | 連結至 MITRE CVE 資料庫 |
| 4 | Severity | Critical（紅色）/ High（橙色）顏色標示 |
| 5 | Publish Date | 公告發布日期 |
| 6 | CVSS Base Score | 顏色標籤：Critical ≥ 9.0（紅）、High ≥ 7.0（橙） |
| 7 | iFix | V9 / V8 / Liberty 各自的 Interim Fix 編號（含連結） |
| 8 | Fixpack Version | V9 / V8 / Liberty 各自的 Fix Pack 目標版本號 |
| 9 | Fixpack Release Date | V9 / V8 / Liberty 各自的 targeted availability（例如 3Q2026） |

---

## 環境需求

- **Python** 3.10+
- **Google Chrome**（或 Chromium）已安裝
- ChromeDriver 由 Selenium Manager（Selenium 4.6+）自動管理

---

## 安裝

```bash
# 1. 複製或下載此專案
git clone <repo-url>
cd new-high-cve

# 2. 安裝 Python 套件
pip install -r requirements.txt
```

### requirements.txt

```
selenium
beautifulsoup4
lxml
python-dateutil
```

---

## 使用方式

### 基本執行（預設：最近 30 天）

```bash
python scraper.py
```

### 常用指令

```bash
# 爬取最近 60 天
python scraper.py --days 60

# 只擷取 Critical（CVSS ≥ 9.0）
python scraper.py --min-cvss 9.0

# 最近 90 天 + 顯示瀏覽器視窗（除錯用）
python scraper.py --days 90 --no-headless

# 指定輸出路徑
python scraper.py --output output/was-cve-report.html

# 顯示詳細執行過程
python scraper.py --days 60 --verbose
```

### 所有參數

```
usage: scraper.py [-h] [--days N] [--output FILE] [--no-headless]
                  [--min-cvss SCORE] [--verbose]

options:
  --days N          爬取最近 N 天內的公告（預設: 30）
  --output FILE     輸出 HTML 報表路徑（預設: output/report-YYYY-MM-DD-HHMMss.html）
  --no-headless     顯示瀏覽器視窗（除錯用，預設為 headless 模式）
  --min-cvss SCORE  CVSS Base Score 最低門檻（預設: 7.0）
  --verbose, -v     顯示詳細 debug 訊息
```

---

## 輸出範例

執行後產生含時間戳記的 HTML 報表，例如：

```
output/report-2026-07-09-172452.html
```

報表頂部顯示統計摘要（Total / Critical / High 筆數），
表格支援點擊欄位標題排序、搜尋框即時篩選。

---

## 專案結構

```
new-high-cve/
├── scraper.py       # 主程式：CLI 參數、主流程、WebDriver 初始化
├── crawler.py       # 清單頁爬蟲：爬取搜尋結果、處理分頁
├── parser.py        # 內頁解析：CVSS Score、iFix、Fixpack、Affected Versions
├── report.py        # HTML 報表生成器（Bootstrap 5 + DataTables）
├── models.py        # 資料結構定義（SecurityBulletin、CveDetail dataclass）
├── requirements.txt # Python 相依套件
└── output/          # 輸出目錄（報表檔案）
```

---

## 執行流程

```
Step 1  開啟 IBM Security Bulletin 搜尋頁
        設定每頁顯示 50 筆，擷取清單資料
        篩選：Severity = High/Critical 且 Publish Date 在 N 天內

Step 2  逐一進入每篇 Bulletin 內頁
        解析各 CVE 的 CVSS Base Score
        解析 Remediation/Fixes 段落：
          - Traditional WAS → V9 / V8 的 iFix、Fixpack Version、Fixpack Release Date
          - Liberty → Liberty Fixpack 版本與日期、受影響版本範圍

Step 3  將含多個 CVE 的 Bulletin 展開為多筆輸出列
        依 CVSS 分數降冪排序

Step 4  生成 HTML 報表至 output/ 目錄
```

---

## 常見問題

**Q：執行後報表是空的**

- 嘗試增加 `--days` 天數（預設 30 天，若近期無 High/Critical 公告會是空的）
- 加入 `--no-headless` 確認瀏覽器是否能正常載入 IBM 網站

**Q：出現 `cannot find Chrome binary` 錯誤**

程式會自動偵測以下路徑，確認 Chrome 或 Chromium 已安裝：
- 系統 PATH（`google-chrome`、`chromium` 等）
- `~/.cache/selenium/chrome/linux64/*/chrome`
- `~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome`

**Q：部分 Bulletin 的 Fixpack Version 欄位空白**

Liberty-only Bulletin 的 Fixpack 格式為 `Apply Liberty Fix Pack 26.0.0.7`，
若 Remediation 段落中找不到此格式則欄位為空，屬正常現象（可查看 `--verbose` 輸出確認）。

---

## 資料來源

- **IBM Security Bulletins**：https://www.ibm.com/support/pages/bulletin/search/?q=WebSphere%20Application%20Server
- **CVE 詳細資訊**：https://cve.mitre.org/
