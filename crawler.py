"""
crawler.py — IBM Security Bulletin 清單頁爬蟲

基於實際頁面結構（2026-07 分析）：
  - Table ID: plc--results-table（DataTable，5欄）
  - 欄位順序: Security Bulletin | Product | CVE ID | Severity | Publish date
  - 每頁顯示下拉: select.select2-hidden-accessible，options=[10,25,50,100,All]，用 index 選
  - 下一頁按鈕: a.ibm-next-link
  - URL 格式: 相對路徑（/support/pages/node/XXXXXXX），需加 https://www.ibm.com

同一篇公告（同 URL）可能有多列（多個 CVE），爬取時合併為一筆。
"""

import logging
import re
import time
from datetime import datetime, timedelta
from typing import List, Dict

from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import TimeoutException, NoSuchElementException

logger = logging.getLogger(__name__)

BASE_URL = "https://www.ibm.com"
SEARCH_URL = (
    "https://www.ibm.com/support/pages/bulletin/search/"
    "?q=WebSphere%20Application%20Server"
)
TABLE_ID = "plc--results-table"
WAIT_TIMEOUT = 30
TARGET_SEVERITIES = {"high", "critical"}


def _parse_date(date_str: str) -> datetime | None:
    """日期字串 → datetime，失敗回傳 None。"""
    if not date_str:
        return None
    try:
        return dateparser.parse(date_str.strip(), ignoretz=True)
    except Exception:
        return None


def _is_within_days(date_str: str, days: int) -> bool:
    """判斷日期是否在 days 天內。"""
    dt = _parse_date(date_str)
    if dt is None:
        return False
    return dt >= (datetime.now() - timedelta(days=days))


def _wait_for_table(driver, timeout: int = WAIT_TIMEOUT):
    """等待清單 table 出現。"""
    WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.ID, TABLE_ID))
    )
    time.sleep(1.5)  # 讓 DataTable JS 完成渲染


def _set_page_size(driver, size: int = 50):
    """
    設定每頁顯示筆數。
    IBM 網站使用 Select2 元件（隱藏原生 select），
    先嘗試直接操作原生 select，若失敗則點擊 Select2 自訂 UI。
    """
    # 找所有含 10/25/50/100 選項的 select
    selects = driver.find_elements(By.CSS_SELECTOR, "select.select2-hidden-accessible")
    for sel in selects:
        try:
            options = sel.find_elements(By.TAG_NAME, "option")
            texts = [o.text.strip() for o in options]
            if str(size) in texts:
                idx = texts.index(str(size))
                # Select2 的原生 select 是隱藏的，用 JS 觸發
                driver.execute_script(
                    "arguments[0].selectedIndex = arguments[1]; "
                    "arguments[0].dispatchEvent(new Event('change'));",
                    sel, idx
                )
                logger.info("已設定每頁顯示 %d 筆（index %d）", size, idx)
                time.sleep(2)
                _wait_for_table(driver)
                return True
        except Exception as e:
            logger.debug("設定每頁筆數失敗: %s", e)

    # 備用：點擊 Select2 自訂下拉 UI
    try:
        # Select2 的觸發元素通常是 .select2-selection 或 .select2-container
        containers = driver.find_elements(
            By.CSS_SELECTOR,
            ".select2-container:not(.ibm-fullwidth .select2-container)"
        )
        for container in containers:
            try:
                container.click()
                time.sleep(0.5)
                # 找彈出的選項清單
                option_els = driver.find_elements(
                    By.CSS_SELECTOR, ".select2-results__option"
                )
                for opt in option_els:
                    if opt.text.strip() == str(size):
                        opt.click()
                        logger.info("已透過 Select2 UI 選擇 %d 筆", size)
                        time.sleep(2)
                        _wait_for_table(driver)
                        return True
            except Exception:
                continue
    except Exception as e:
        logger.debug("Select2 UI 操作失敗: %s", e)

    logger.warning("無法設定每頁筆數為 %d，使用預設值", size)
    return False


def _parse_table(driver) -> Dict[str, Dict]:
    """
    解析 plc--results-table，回傳以 URL 為 key 的公告字典。
    同一 URL 的多列（多個 CVE）會被合併。

    欄位對應（0-based）:
      0: Security Bulletin 標題 + href
      1: Product（忽略）
      2: CVE ID + href
      3: Severity
      4: Publish date
    """
    soup = BeautifulSoup(driver.page_source, "lxml")
    table = soup.find("table", id=TABLE_ID)
    if not table:
        logger.warning("找不到 table#%s", TABLE_ID)
        return {}

    bulletins: Dict[str, Dict] = {}
    rows = table.find_all("tr")

    for row in rows[1:]:  # 跳過 header
        cells = row.find_all("td")
        if len(cells) < 5:
            continue

        # 欄 0：標題與 URL
        link_el = cells[0].find("a", href=True)
        if not link_el:
            continue
        title = link_el.get_text(strip=True)
        href = link_el["href"]
        url = href if href.startswith("http") else BASE_URL + href

        # 欄 2：CVE ID
        cve_text = cells[2].get_text(strip=True)
        cve_ids = re.findall(r"CVE-\d{4}-\d+", cve_text, re.IGNORECASE)
        cve_ids = [c.upper() for c in cve_ids]

        # 欄 3：Severity
        severity = cells[3].get_text(strip=True)

        # 欄 4：Publish date
        publish_date = cells[4].get_text(strip=True)

        # 合併同 URL 的多列
        if url not in bulletins:
            bulletins[url] = {
                "title": title,
                "url": url,
                "cve_ids": [],
                "severity": severity,
                "publish_date": publish_date,
            }
        for cve in cve_ids:
            if cve not in bulletins[url]["cve_ids"]:
                bulletins[url]["cve_ids"].append(cve)

    return bulletins


def _go_to_next_page(driver) -> bool:
    """點擊「Next」按鈕，成功回傳 True，無下一頁回傳 False。"""
    try:
        next_btn = driver.find_element(By.CSS_SELECTOR, "a.ibm-next-link")
        # 檢查是否被停用（disabled class 或 aria-disabled）
        classes = next_btn.get_attribute("class") or ""
        aria_disabled = next_btn.get_attribute("aria-disabled") or ""
        if "disabled" in classes.lower() or aria_disabled.lower() == "true":
            logger.info("下一頁按鈕已停用，已到最後一頁")
            return False

        driver.execute_script("arguments[0].click();", next_btn)
        logger.info("點擊下一頁")
        time.sleep(2)
        _wait_for_table(driver)
        return True
    except NoSuchElementException:
        logger.info("找不到下一頁按鈕，已到最後一頁")
        return False
    except Exception as e:
        logger.debug("點擊下一頁失敗: %s", e)
        return False


def fetch_bulletin_list(driver, days: int = 30) -> List[Dict]:
    """
    爬取 IBM Security Bulletin 清單頁，回傳符合條件的公告列表。

    篩選條件（AND）：
      1. Severity 為 High 或 Critical
      2. Publish Date 在 days 天內

    Parameters
    ----------
    driver : WebDriver
        已初始化的 Selenium WebDriver 實例
    days : int
        爬取最近 days 天內的公告，預設 30

    Returns
    -------
    List[Dict]
        每筆包含：title, url, cve_ids, severity, publish_date
    """
    logger.info("開始爬取清單頁，時間範圍：最近 %d 天", days)
    driver.get(SEARCH_URL)

    # 等待 table 載入
    try:
        _wait_for_table(driver)
    except TimeoutException:
        logger.error("等待清單頁 table 載入逾時（selector: #%s）", TABLE_ID)
        return []

    logger.info("清單頁載入成功")

    # 設定每頁顯示 50 筆
    _set_page_size(driver, 50)

    all_results: List[Dict] = []
    page_num = 1

    while True:
        logger.info("解析第 %d 頁...", page_num)
        bulletins_on_page = _parse_table(driver)

        if not bulletins_on_page:
            logger.info("第 %d 頁沒有解析到資料，停止", page_num)
            break

        logger.info("  第 %d 頁：找到 %d 筆公告", page_num, len(bulletins_on_page))

        page_has_recent = False  # 本頁是否有在時間範圍內的項目
        any_out_of_range = False  # 是否有超出時間範圍的項目

        for item in bulletins_on_page.values():
            severity_lower = item["severity"].lower()
            in_severity = severity_lower in TARGET_SEVERITIES
            in_date = _is_within_days(item["publish_date"], days)

            logger.debug(
                "  [%s] severity=%s(%s) date=%s(%s) cves=%s",
                item["title"][:45],
                item["severity"], "✓" if in_severity else "✗",
                item["publish_date"], "✓" if in_date else "✗",
                item["cve_ids"],
            )

            if in_date:
                page_has_recent = True
                if in_severity:
                    all_results.append(item)
                    logger.info(
                        "  ✅ 納入: [%s] %s | %s | %s",
                        item["severity"], item["publish_date"],
                        item["cve_ids"], item["title"][:50]
                    )
            else:
                any_out_of_range = True

        # 停止條件：本頁所有項目的日期都超出範圍
        all_dates = [
            _parse_date(item["publish_date"])
            for item in bulletins_on_page.values()
            if _parse_date(item["publish_date"])
        ]
        if all_dates:
            oldest = min(all_dates)
            cutoff = datetime.now() - timedelta(days=days)
            if oldest < cutoff and not page_has_recent:
                logger.info("本頁最舊日期 %s 超出 %d 天範圍且無符合項目，停止翻頁", oldest.date(), days)
                break

        # 翻到下一頁
        if not _go_to_next_page(driver):
            break
        page_num += 1

    logger.info("清單頁爬取完成，共找到 %d 筆符合條件的公告", len(all_results))
    return all_results
