"""
parser.py — IBM Security Bulletin 內頁解析器

基於實際頁面結構（2026-07 分析）：

頁面文字結構（get_text 後）:
  Vulnerability Details
  CVEID:
  CVE-2026-XXXX
  ...
  CVSS Base score:
  9.3                        ← 直接是數字
  CVSS Vector:
  ...
  （下一個 CVE 重複以上結構）

  Remediation/Fixes
  ...
  For IBM WebSphere Application Server traditional:
  For V9.0.0.0 through 9.0.5.28:
    · apply Interim Fix PH71670
    --OR--
    · Apply Fix Pack 9.0.5.29 or later (targeted availability 3Q2026).  ← 大寫 Apply
  For V8.5.0.0 through 8.5.5.30:
    · Apply Fix Pack 8.5.5.31 or later (targeted availability 3Q2026).
"""

import logging
import re
import time
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from models import SecurityBulletin, CveDetail

logger = logging.getLogger(__name__)

WAIT_TIMEOUT = 20

# 正規表示式
RE_CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
RE_IFIX = re.compile(r"\b((?:PH|PI|PM|PK|PT|IF|DT)\d{5,})\b", re.IGNORECASE)
RE_FIXPACK_V9 = re.compile(r"\b(9\.\d+\.\d+\.\d+)\b")
RE_FIXPACK_V8 = re.compile(r"\b(8\.\d+\.\d+\.\d+)\b")
RE_QUARTER = re.compile(r"\b([1-4]Q\s*\d{4})\b", re.IGNORECASE)
# 符合 "Apply <任意文字> 9.X.X.X" 的正規表示式（大寫 Apply 開頭，版本號在同一行即可）
# 涵蓋以下格式：
#   Apply Fix Pack 9.0.5.29 or later
#   Apply Web Server Plug-ins Fix Pack 9.0.5.28 or later
#   Apply Liberty Fix Pack 26.0.0.8 or later（Liberty 版本，不影響 V9/V8 解析）
RE_APPLY_FP_V9 = re.compile(r"Apply\b.+(9\.\d+\.\d+\.\d+)", re.IGNORECASE)
RE_APPLY_FP_V8 = re.compile(r"Apply\b.+(8\.\d+\.\d+\.\d+)", re.IGNORECASE)


def _severity_from_score(score: float) -> str:
    """依 CVSS 分數計算 Severity（Critical >= 9.0, High >= 7.0）。"""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return ""


def _wait_for_page_load(driver, timeout: int = WAIT_TIMEOUT):
    """等待內頁主要內容載入。

    策略：
      1. 等待 DOM 中出現主要內容容器（body / article 等）
      2. 再等待頁面文字包含 "CVSS Base score"，確保動態內容已渲染
         — IBM 公告頁面的漏洞詳情由 JavaScript 非同步插入，若僅等 DOM 出現
           會在 CVSS 分數插入前就開始解析，導致抓到 cvss=0。
      3. 若 "CVSS Base score" 等待逾時，補等一段時間再繼續（graceful fallback）。
    """
    try:
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "article, main, .ibm-content, #content, body")
            )
        )
    except TimeoutException:
        logger.warning("等待頁面載入逾時，嘗試繼續解析")
        return

    # 等待 CVSS 分數文字出現在頁面上（最多再等 15 秒）
    try:
        WebDriverWait(driver, 15).until(
            lambda d: "CVSS Base score" in d.page_source or "Vulnerability Details" in d.page_source
        )
    except TimeoutException:
        logger.debug("  等待 CVSS 內容逾時，補等 3 秒後繼續")
        time.sleep(3)
        return

    time.sleep(0.5)


def _parse_cve_details(lines: List[str], vd_start: int, vd_end: int) -> List[CveDetail]:
    """
    從 Vulnerability Details 區段解析每個 CVE 的 ID 與 CVSS Base Score。

    頁面文字結構（每個 CVE 區塊）：
      CVEID:
      CVE-XXXX-YYYY
      DESCRIPTION:
      ...
      CVSS Base score:
      9.3              ← 緊接在 "CVSS Base score:" 下一個非空行就是分數
      CVSS Vector:
      ...
    """
    details: List[CveDetail] = []
    vd_lines = lines[vd_start:vd_end]

    current_cve = ""
    expect_score = False  # 下一個數字行是 CVSS Score

    for line in vd_lines:
        stripped = line.strip()
        if not stripped:
            continue

        # 偵測 CVE ID 行
        cve_match = RE_CVE.fullmatch(stripped.upper())
        if cve_match:
            # 若已有前一個 CVE 但還沒抓到分數，補進 list
            if current_cve and not any(d.cve_id == current_cve for d in details):
                details.append(CveDetail(cve_id=current_cve, cvss_score=0.0))
            current_cve = stripped.upper()
            expect_score = False
            continue

        # 偵測 "CVSS Base score:" 標記
        if re.match(r"CVSS\s+Base\s+score\s*:?$", stripped, re.IGNORECASE):
            expect_score = True
            continue

        # 讀取 CVSS 分數（緊接在 "CVSS Base score:" 後的數字行）
        if expect_score and current_cve:
            try:
                score = float(stripped)
                severity = _severity_from_score(score)
                details.append(CveDetail(
                    cve_id=current_cve,
                    cvss_score=score,
                    severity=severity,
                ))
                logger.debug("  CVE %s → CVSS %.1f (%s)", current_cve, score, severity)
                current_cve = ""
                expect_score = False
            except ValueError:
                # 不是數字，繼續等
                pass
            continue

    # 若最後一個 CVE 還沒被加入
    if current_cve and not any(d.cve_id == current_cve for d in details):
        details.append(CveDetail(cve_id=current_cve, cvss_score=0.0))

    return details


# Liberty Fixpack 版本號（例如 26.0.0.7，格式為 YY.0.0.N 或 17.0.0.N）
RE_APPLY_FP_LIBERTY = re.compile(
    r"Apply\s+Liberty\s+Fix\s+Pack\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE
)
# Affected Versions 範圍（例如 17.0.0.3 - 26.0.0.7）
RE_LIBERTY_VERSION_RANGE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+\s*[-–]\s*\d+\.\d+\.\d+\.\d+)"
)


def _fallback_detect_bulletin_type(page_text: str, title: str) -> str:
    """當 Affected Products 區段不存在時，從全文與標題判斷公告類型。"""
    has_liberty = "liberty" in page_text.lower() or "liberty" in title.lower()
    has_traditional = bool(
        re.search(r"\b(V9\.0\.0\.0|V8\.5\.0\.0|WebSphere Application Server traditional)\b", page_text, re.IGNORECASE)
    )
    if has_traditional and has_liberty:
        return "both"
    if has_liberty:
        return "liberty"
    return "traditional"


def _fallback_parse_cve_details(text: str, cve_ids: List[str]) -> List[CveDetail]:
    """當找不到 Vulnerability Details 段落時，直接從全文抓取每個 CVE 的 CVSS。

    搜尋策略：優先從「Vulnerability Details」段落後的 CVE 位置開始；
    若找不到該段落，則使用 CVE ID 最後一次出現的位置，以避免頁面標題等
    早期出現的重複字串把搜尋 window 帶偏，導致搜尋不到 CVSS 分數。
    """
    details: List[CveDetail] = []
    upper_text = text.upper()
    # 以 Vulnerability Details 段落起點為搜尋基準，搜不到則從頭
    vd_pos = upper_text.find("VULNERABILITY DETAILS")
    search_from = vd_pos if vd_pos != -1 else 0

    for cve_id in cve_ids:
        # 優先取 Vulnerability Details 後的 CVE 位置，否則取全文最後一次
        idx = upper_text.find(cve_id.upper(), search_from)
        if idx == -1:
            # 找全文最後一次出現（避開頁頭早期位置）
            idx = upper_text.rfind(cve_id.upper())
        score = 0.0
        if idx != -1:
            window = text[idx:idx + 2000]
            m = re.search(r"CVSS\s*Base\s*score\s*:?[\s\n]*([0-9]+(?:\.[0-9])?)", window, re.IGNORECASE)
            if m:
                score = float(m.group(1))
        details.append(CveDetail(cve_id=cve_id.upper(), cvss_score=score, severity=_severity_from_score(score)))
    return details


def _fallback_find_affected_versions(text: str, bulletin_type: str) -> str:
    """當找不到 Affected Products 區段時，從全文抓受影響版本。"""
    liberty_match = RE_LIBERTY_VERSION_RANGE.search(text)
    if bulletin_type == "liberty":
        if liberty_match:
            return liberty_match.group(1).strip()
        return ""
    if bulletin_type == "both":
        if liberty_match:
            return f"9.0, 8.5<br>{liberty_match.group(1).strip()}"
        return "9.0, 8.5"
    return "9.0, 8.5"


def _find_first_url_for_ifix(soup: BeautifulSoup, label: str) -> str:
    if not label:
        return ""
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = a.get_text(strip=True)
        if label.upper() in text.upper() or label.upper() in href.upper():
            return href
    return ""



def _detect_bulletin_type(lines: List[str], aff_start: int, rem_start: int) -> str:
    """
    偵測 Bulletin 類型：
      - "traditional"：包含 WebSphere Application Server traditional（V9/V8）
      - "liberty"：僅包含 Liberty（無 traditional WAS）
      - "both"：同時包含 traditional 與 Liberty

    依據 Affected Products 表格中的產品名稱判斷。
    """
    aff_end = rem_start if rem_start > aff_start else aff_start + 20
    aff_lines = lines[aff_start:aff_end]
    aff_text = "\n".join(aff_lines)

    has_traditional = bool(re.search(
        r"WebSphere Application Server\b(?!\s*[-–]\s*Liberty|\s*Liberty)",
        aff_text, re.IGNORECASE
    ))
    has_liberty = bool(re.search(r"Liberty", aff_text, re.IGNORECASE))

    if has_traditional and has_liberty:
        return "both"
    if has_liberty:
        return "liberty"
    return "traditional"


def _parse_affected_versions(lines: List[str], aff_start: int, rem_start: int) -> str:
    """
    從 Affected Products and Versions 表格解析 Version(s) 欄位值。

    表格文字結構：
      Affected Products and Versions
      Affected Product(s)
      Version(s)
      WebSphere Application Server - Liberty   ← 產品名
      17.0.0.3 - 26.0.0.7                     ← 版本值（緊接在產品名後）
    """
    aff_end = rem_start if rem_start > aff_start else aff_start + 20
    aff_lines = lines[aff_start:aff_end]

    aff_text = "\n".join(aff_lines)

    # 先抓 Liberty 範圍格式
    for l in aff_lines:
        m = RE_LIBERTY_VERSION_RANGE.search(l)
        if m:
            return m.group(1).strip()

    # 若表格中同時出現 V9 / V8 的 traditional 版本，統一回傳報表使用值
    has_v9 = bool(re.search(r"\b9\.0(?:\.0\.0)?\b|\bV9\b", aff_text, re.IGNORECASE))
    has_v8 = bool(re.search(r"\b8\.5(?:\.0\.0)?\b|\bV8\b", aff_text, re.IGNORECASE))
    if has_v9 and has_v8:
        return "9.0, 8.5"

    # 找 "Version(s)" 標題行後的版本值，但忽略單獨的 9.0 / 8.5
    for i, l in enumerate(aff_lines):
        if re.match(r"Version\(s\)", l, re.IGNORECASE):
            for candidate in aff_lines[i+1:i+6]:
                candidate = candidate.strip()
                if candidate in {"9.0", "8.5", "9.0, 8.5", "8.5, 9.0"}:
                    continue
                if re.match(r"[\d.,\s\-–]+$", candidate) and candidate:
                    return candidate

    return ""


def _parse_liberty_fixpack(lines: List[str], rem_start: int) -> Dict:
    """
    從 Remediation 段落解析 Liberty Fixpack 資訊。

    頁面有兩種 iFix 格式：
      格式 A（同行）: apply the Interim Fix that resolves PH71687
      格式 B（換行）: apply ... interim fix\nPH71687   ← PH 獨立一行

    Fixpack 格式：
      · Apply Liberty Fix Pack 26.0.0.7 or later (targeted availability 3Q2026).
    """
    result = {"fixpack_liberty": "", "fixpack_date_liberty": "", "ifix_liberty": ""}

    rem_lines = lines[rem_start:]
    for idx, line in enumerate(rem_lines):
        # Liberty Fixpack 版本
        if not result["fixpack_liberty"]:
            m = RE_APPLY_FP_LIBERTY.search(line)
            if m:
                result["fixpack_liberty"] = m.group(1)
                q = RE_QUARTER.search(line)
                if q:
                    result["fixpack_date_liberty"] = q.group(1).replace(" ", "")

        # Liberty iFix 編號（兩種格式）
        if not result["ifix_liberty"]:
            # 格式 A：同行有 "Interim Fix" 且有 PH 編號
            if re.search(r"interim.?fix", line, re.IGNORECASE):
                ifix = RE_IFIX.findall(line)
                if ifix:
                    result["ifix_liberty"] = ifix[0].upper()
                else:
                    # 格式 B：PH 編號在下一行（獨立一行）
                    next_line = rem_lines[idx + 1] if idx + 1 < len(rem_lines) else ""
                    ifix_next = RE_IFIX.fullmatch(next_line.strip().upper())
                    if ifix_next:
                        result["ifix_liberty"] = next_line.strip().upper()

        if result["fixpack_liberty"] and result["fixpack_date_liberty"]:
            break

    return result


def _parse_remediation(lines: List[str], rem_start: int) -> Dict:
    """
    從 Remediation 段落解析 V9 和 V8 的 iFix 編號與 Fixpack 版本。

    關鍵規則：
      - iFix 編號：在 "Interim Fix" 關鍵字後的 PH/PI 編號
      - Fixpack 版本：在 "Apply <any> Fix Pack X.X.X.X" 中（大寫 Apply 開頭，同行有版本號）
      - Fixpack 日期：在 "targeted availability XQYYYY" 中
      - V9 區塊：從 "For V9" 開始
      - V8 區塊：從 "For V8" 開始
    """
    result = {
        "ifix_v9": "", "ifix_v9_url": "",
        "ifix_v8": "", "ifix_v8_url": "",
        "fixpack_v9": "", "fixpack_v8": "",
        "fixpack_date_v9": "", "fixpack_date_v8": "",
    }

    rem_lines = lines[rem_start:]
    rem_text = "\n".join(rem_lines)

    # 找 "For IBM WebSphere Application Server traditional" 位置
    was_trad_idx = None
    for i, l in enumerate(rem_lines):
        if re.search(r"For IBM WebSphere Application Server traditional", l, re.IGNORECASE):
            was_trad_idx = i
            break
    if was_trad_idx is None:
        was_trad_idx = 0

    trad_lines = rem_lines[was_trad_idx:]
    trad_text = "\n".join(trad_lines)

    # 定位 V9 與 V8 區塊邊界
    v9_start = None
    v8_start = None
    for i, l in enumerate(trad_lines):
        if v9_start is None and re.search(r"For V9\.", l, re.IGNORECASE):
            v9_start = i
        if v8_start is None and re.search(r"For V8\.", l, re.IGNORECASE):
            v8_start = i

    # 切出 V9 / V8 文字段落
    if v9_start is not None:
        v9_end = v8_start if (v8_start and v8_start > v9_start) else v9_start + 20
        v9_text = "\n".join(trad_lines[v9_start:v9_end])
    else:
        v9_text = trad_text[:500]

    if v8_start is not None:
        v8_text = "\n".join(trad_lines[v8_start:v8_start + 20])
    else:
        v8_text = ""

    # --- 解析 V9 ---
    if v9_text:
        # Fixpack 版本：取 "Apply Fix Pack 9.X.X.X" 的版本號
        m = RE_APPLY_FP_V9.search(v9_text)
        if m:
            result["fixpack_v9"] = m.group(1)
        # targeted availability
        q = RE_QUARTER.search(v9_text)
        if q:
            result["fixpack_date_v9"] = q.group(1).replace(" ", "")
        # iFix 編號
        ifix = RE_IFIX.findall(v9_text)
        if ifix:
            result["ifix_v9"] = ifix[0].upper()

    # --- 解析 V8 ---
    if v8_text:
        m = RE_APPLY_FP_V8.search(v8_text)
        if m:
            result["fixpack_v8"] = m.group(1)
        q = RE_QUARTER.search(v8_text)
        if q:
            result["fixpack_date_v8"] = q.group(1).replace(" ", "")
        ifix = RE_IFIX.findall(v8_text)
        if ifix:
            result["ifix_v8"] = ifix[0].upper()

    # --- Fallback：若 V9/V8 區塊定位失敗，從全段落掃描 ---
    if not result["fixpack_v9"]:
        m = RE_APPLY_FP_V9.search(trad_text)
        if m:
            result["fixpack_v9"] = m.group(1)
    if not result["fixpack_v8"]:
        m = RE_APPLY_FP_V8.search(trad_text)
        if m:
            result["fixpack_v8"] = m.group(1)

    # --- 從 soup 取 iFix URL（在主流程中傳入 soup 處理）---
    return result


def _get_ifix_urls(soup: BeautifulSoup, ifix_v9: str, ifix_v8: str) -> Tuple[str, str]:
    """從 soup 中取得 V9 和 V8 iFix 的超連結 URL。"""
    def find_url(label: str) -> str:
        if not label:
            return ""
        for a in soup.find_all("a", href=True):
            href = a["href"]
            text = a.get_text(strip=True)
            if label.upper() in text.upper() or label.upper() in href.upper():
                return href
        # 找任何 fixcentral 連結
        for a in soup.find_all("a", href=True):
            if "fixcentral" in a["href"].lower():
                return a["href"]
        return ""

    return find_url(ifix_v9), find_url(ifix_v8)


def parse_bulletin_detail(driver, bulletin_dict: Dict) -> SecurityBulletin:
    """
    進入 Security Bulletin 內頁，解析：
      1. 每個 CVE 各自的 CVSS Base Score（存入 cve_details）
      2. Remediation 段落的 iFix、Fixpack Version（Apply Fix Pack X.X.X.X）、targeted availability

    回傳的 SecurityBulletin.cve_details 包含所有 CVE 的詳細資訊。
    主程式（scraper.py）負責將其展開為多筆輸出列。
    """
    url = bulletin_dict.get("url", "")
    title = bulletin_dict.get("title", "")
    cve_ids_from_list = bulletin_dict.get("cve_ids", [])
    list_severity = bulletin_dict.get("severity", "")
    publish_date = bulletin_dict.get("publish_date", "")

    logger.info("解析內頁: %s", url)

    bulletin = SecurityBulletin(
        title=title,
        bulletin_url=url,
        publish_date=publish_date,
        _list_severity=list_severity,
    )

    try:
        driver.get(url)
        _wait_for_page_load(driver)

        # 最多重試 2 次：當頁面已載入但 cvss=0（動態內容未就緒）時重新讀取
        for attempt in range(2):
            soup = BeautifulSoup(driver.page_source, "lxml")
            text = soup.get_text(separator="\n", strip=True)
            lines = [l.strip() for l in text.split("\n")]

            # 找各段落位置
            vd_start = next(
                (i for i, l in enumerate(lines) if "Vulnerability Details" in l), -1
            )
            aff_start = next(
                (i for i, l in enumerate(lines) if "Affected Products and Versions" in l), -1
            )
            rem_start = next(
                (i for i, l in enumerate(lines) if re.match(r"Remediation(?:/Fixes)?", l, re.IGNORECASE)), -1
            )
            vd_end = rem_start if rem_start > vd_start else len(lines)

            # 1. 解析每個 CVE 的 CVSS Score
            tmp_details: List[CveDetail] = []
            if vd_start != -1:
                tmp_details = _parse_cve_details(lines, vd_start, vd_end)
                # VD 段落找到 CVE 但分數仍為 0 時，用全文 regex 補搜分數
                missing_score = [d.cve_id for d in tmp_details if d.cvss_score == 0.0]
                if missing_score:
                    logger.debug("  VD 段落分數缺失，嘗試全文補搜: %s", missing_score)
                    retry_details = _fallback_parse_cve_details(text, missing_score)
                    score_map = {d.cve_id: d.cvss_score for d in retry_details if d.cvss_score > 0}
                    for d in tmp_details:
                        if d.cvss_score == 0.0 and d.cve_id in score_map:
                            d.cvss_score = score_map[d.cve_id]
                            d.severity = _severity_from_score(d.cvss_score)
            elif cve_ids_from_list:
                tmp_details = _fallback_parse_cve_details(text, cve_ids_from_list)

            # 若仍有 cvss=0 且還有重試機會，等待後重新讀取頁面
            still_missing = [d.cve_id for d in tmp_details if d.cvss_score == 0.0]
            if still_missing and attempt == 0:
                logger.warning("  [attempt %d] cvss=0 仍未解析: %s，等待 3 秒後重試", attempt + 1, still_missing)
                time.sleep(3)
                continue  # 重新讀取 page_source

            bulletin.cve_details = tmp_details
            break

        if bulletin.cve_details:
            logger.info(
                "  解析到 %d 個 CVE: %s",
                len(bulletin.cve_details),
                [(d.cve_id, d.cvss_score) for d in bulletin.cve_details]
            )

        # 若內頁解析不到 CVE，依序嘗試：清單頁 CVE IDs → title 中的 CVE IDs
        if not bulletin.cve_details:
            fallback_ids = cve_ids_from_list or RE_CVE.findall(title.upper())
            if fallback_ids:
                bulletin.cve_details = _fallback_parse_cve_details(text, fallback_ids)
                logger.debug(
                    "  CVE ID fallback（%s）: %s",
                    "清單頁" if cve_ids_from_list else "title",
                    fallback_ids,
                )
            # 若全文也搜不到分數，至少保留 CVE ID（CVSS=0）
            if not bulletin.cve_details and fallback_ids:
                for cid in fallback_ids:
                    bulletin.cve_details.append(CveDetail(cve_id=cid, cvss_score=0.0))
                logger.debug("  使用 fallback CVE IDs，CVSS=0")

        if vd_start == -1:
            logger.warning("  找不到 Vulnerability Details 段落")
        if rem_start == -1:
            logger.warning("  找不到 Remediation 段落")

        # 2. 偵測 Bulletin 類型（traditional / liberty / both）
        bulletin_type = "traditional"
        if aff_start != -1 and rem_start != -1:
            bulletin_type = _detect_bulletin_type(lines, aff_start, rem_start)
        else:
            bulletin_type = _fallback_detect_bulletin_type(text, title)
        logger.info("  Bulletin 類型: %s", bulletin_type)

        # 3. 解析 Affected Versions
        if aff_start != -1:
            affected_ver = _parse_affected_versions(lines, aff_start, rem_start)
            if affected_ver:
                if bulletin_type == "both" and affected_ver != "9.0, 8.5" and "<br>" not in affected_ver:
                    bulletin.affected_versions = f"9.0, 8.5<br>{affected_ver}"
                else:
                    bulletin.affected_versions = affected_ver
                logger.info("  Affected Versions: %s", bulletin.affected_versions)
        else:
            bulletin.affected_versions = _fallback_find_affected_versions(text, bulletin_type)

        # 4. 解析 Remediation（iFix + Fixpack）
        if rem_start != -1:
            if bulletin_type in ("traditional", "both"):
                fix_info = _parse_remediation(lines, rem_start)
                bulletin.ifix_v9 = fix_info["ifix_v9"]
                bulletin.ifix_v8 = fix_info["ifix_v8"]
                bulletin.fixpack_v9 = fix_info["fixpack_v9"]
                bulletin.fixpack_v8 = fix_info["fixpack_v8"]
                bulletin.fixpack_date_v9 = fix_info["fixpack_date_v9"]
                bulletin.fixpack_date_v8 = fix_info["fixpack_date_v8"]

                # 取 iFix URL
                url_v9, url_v8 = _get_ifix_urls(soup, bulletin.ifix_v9, bulletin.ifix_v8)
                bulletin.ifix_v9_url = url_v9
                bulletin.ifix_v8_url = url_v8

                logger.info(
                    "  V9: ifix=%s fixpack=%s date=%s",
                    bulletin.ifix_v9, bulletin.fixpack_v9, bulletin.fixpack_date_v9
                )
                logger.info(
                    "  V8: ifix=%s fixpack=%s date=%s",
                    bulletin.ifix_v8, bulletin.fixpack_v8, bulletin.fixpack_date_v8
                )

            if bulletin_type in ("liberty", "both"):
                lib_info = _parse_liberty_fixpack(lines, rem_start)
                if bulletin_type == "liberty":
                    bulletin.fixpack_v9 = lib_info["fixpack_liberty"]
                    bulletin.fixpack_date_v9 = lib_info["fixpack_date_liberty"]
                    if lib_info["ifix_liberty"]:
                        bulletin.ifix_v9 = lib_info["ifix_liberty"]

                    lib_url_v9, _ = _get_ifix_urls(soup, bulletin.ifix_v9, "")
                    bulletin.ifix_v9_url = lib_url_v9
                else:
                    bulletin.fixpack_liberty = lib_info["fixpack_liberty"]
                    bulletin.fixpack_date_liberty = lib_info["fixpack_date_liberty"]
                    bulletin.ifix_liberty = lib_info["ifix_liberty"]
                    lib_url_v9, _ = _get_ifix_urls(soup, bulletin.ifix_liberty, "")
                    bulletin.ifix_liberty_url = lib_url_v9

                logger.info(
                    "  Liberty: ifix=%s url=%s fixpack=%s date=%s",
                    bulletin.ifix_v9 if bulletin_type == "liberty" else bulletin.ifix_liberty,
                    bulletin.ifix_v9_url if bulletin_type == "liberty" else bulletin.ifix_liberty_url,
                    bulletin.fixpack_v9 if bulletin_type == "liberty" else bulletin.fixpack_liberty,
                    bulletin.fixpack_date_v9 if bulletin_type == "liberty" else bulletin.fixpack_date_liberty
                )

    except Exception as e:
        logger.error("解析內頁失敗 (%s): %s", url, e, exc_info=True)

    return bulletin


def expand_bulletin_to_rows(bulletin: SecurityBulletin, min_cvss: float = 7.0) -> List[SecurityBulletin]:
    """
    將一個 SecurityBulletin（含多個 CVE）展開為多筆輸出列。
    每筆各對應一個 CVE，共用 Bulletin、iFix、Fixpack 等欄位。
    只保留 CVSS >= min_cvss 的 CVE（CVSS=0 的也保留，作為 fallback）。

    Parameters
    ----------
    bulletin : SecurityBulletin
        已解析的公告（cve_details 含多個 CVE）
    min_cvss : float
        CVSS 篩選門檻

    Returns
    -------
    List[SecurityBulletin]
        展開後的多筆列，每筆對應一個 CVE
    """
    rows = []

    for detail in bulletin.cve_details:
        # 篩選：CVSS >= min_cvss，或 CVSS=0（解析失敗，用 list severity 判斷）
        if detail.cvss_score >= min_cvss or (
            detail.cvss_score == 0.0
            and bulletin._list_severity.lower() in {"high", "critical"}
        ):
            # 計算 Severity
            if detail.cvss_score > 0:
                severity = detail.severity or _severity_from_score(detail.cvss_score)
            else:
                severity = bulletin._list_severity  # fallback

            row = SecurityBulletin(
                title=bulletin.title,
                bulletin_url=bulletin.bulletin_url,
                affected_versions=bulletin.affected_versions,
                cve_id=detail.cve_id,
                severity=severity,
                publish_date=bulletin.publish_date,
                cvss_score=detail.cvss_score,
                ifix_v9=bulletin.ifix_v9,
                ifix_v9_url=bulletin.ifix_v9_url,
                ifix_v8=bulletin.ifix_v8,
                ifix_v8_url=bulletin.ifix_v8_url,
                ifix_liberty=bulletin.ifix_liberty,
                ifix_liberty_url=bulletin.ifix_liberty_url,
                fixpack_v9=bulletin.fixpack_v9,
                fixpack_v8=bulletin.fixpack_v8,
                fixpack_liberty=bulletin.fixpack_liberty,
                fixpack_date_v9=bulletin.fixpack_date_v9,
                fixpack_date_v8=bulletin.fixpack_date_v8,
                fixpack_date_liberty=bulletin.fixpack_date_liberty,
            )
            rows.append(row)

    # 若 cve_details 完全為空（解析失敗），才建立 placeholder 兜底。
    # 注意：若 cve_details 有資料但全部低於 min_cvss，代表篩選結果正常為空，
    # 不應建立 placeholder（否則 --min-cvss 較高時會輸出錯誤的 N/A 列）。
    if not rows and not bulletin.cve_details and bulletin._list_severity.lower() in {"high", "critical"}:
        rows.append(SecurityBulletin(
            title=bulletin.title,
            bulletin_url=bulletin.bulletin_url,
            affected_versions=bulletin.affected_versions,
            cve_id="",
            severity=bulletin._list_severity,
            publish_date=bulletin.publish_date,
            cvss_score=0.0,
            ifix_v9=bulletin.ifix_v9,
            ifix_v9_url=bulletin.ifix_v9_url,
            ifix_v8=bulletin.ifix_v8,
            ifix_v8_url=bulletin.ifix_v8_url,
            ifix_liberty=bulletin.ifix_liberty,
            ifix_liberty_url=bulletin.ifix_liberty_url,
            fixpack_v9=bulletin.fixpack_v9,
            fixpack_v8=bulletin.fixpack_v8,
            fixpack_liberty=bulletin.fixpack_liberty,
            fixpack_date_v9=bulletin.fixpack_date_v9,
            fixpack_date_v8=bulletin.fixpack_date_v8,
            fixpack_date_liberty=bulletin.fixpack_date_liberty,
        ))

    return rows
