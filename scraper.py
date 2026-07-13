"""
scraper.py — IBM WAS High-Risk CVE Scraper 主程式

使用方式:
    python scraper.py                          # 預設：最近 30 天，CVSS >= 7.0
    python scraper.py --days 60                # 最近 60 天
    python scraper.py --days 90 --min-cvss 9.0 # 最近 90 天，只取 Critical
    python scraper.py --no-headless            # 顯示瀏覽器視窗（除錯用）
    python scraper.py --output output/my.html  # 自訂輸出路徑
"""

import argparse
from datetime import datetime
import glob as _glob
import logging
import os
import sys
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

import crawler
import bulletin_parser as detail_parser
import report
from models import SecurityBulletin
from bulletin_parser import expand_bulletin_to_rows


def setup_logging(verbose: bool = False):
    """設定 logging 格式與層級。"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _find_chrome_binary() -> str | None:
    """
    自動尋找 Chrome / Chromium binary 路徑。
    依序搜尋：系統路徑 → Selenium Manager 快取 → Playwright 快取。
    """
    # 1. 系統常見路徑
    candidates = [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    import shutil
    for c in candidates:
        if shutil.which(c):
            return shutil.which(c)

    # 2. Selenium Manager 快取（~/.cache/selenium/chrome）
    cache_pattern = os.path.expanduser("~/.cache/selenium/chrome/linux64/*/chrome")
    cached = sorted(_glob.glob(cache_pattern), reverse=True)  # 最新版本優先
    if cached:
        return cached[0]

    # 3. Playwright 快取
    pw_pattern = os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome")
    pw_cached = sorted(_glob.glob(pw_pattern), reverse=True)
    if pw_cached:
        return pw_cached[0]

    return None


def create_driver(headless: bool = True) -> webdriver.Chrome:
    """
    初始化 Chrome WebDriver。
    使用 _find_chrome_binary() 自動偵測 Chrome binary，
    Selenium 4.6+ 內建的 selenium-manager 負責自動下載配對版本的 ChromeDriver。
    """
    options = Options()

    # 自動偵測 Chrome binary
    chrome_binary = _find_chrome_binary()
    if chrome_binary:
        logging.getLogger(__name__).info("使用 Chrome binary: %s", chrome_binary)
        options.binary_location = chrome_binary
    else:
        logging.getLogger(__name__).warning(
            "找不到 Chrome binary，嘗試使用系統預設路徑"
        )

    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    # 關閉 automation 旗標，降低被偵測機率
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    # Selenium 4.6+ 內建 selenium-manager，不需手動指定 Service/ChromeDriver
    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(5)
    driver.set_page_load_timeout(300)
    return driver


def parse_args() -> argparse.Namespace:
    """解析命令列參數。"""
    parser = argparse.ArgumentParser(
        description="自動擷取 IBM WAS Security Bulletin 高風險 CVE 並生成 HTML 報表",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例:
  python scraper.py
  python scraper.py --days 60
  python scraper.py --days 90 --min-cvss 9.0
  python scraper.py --no-headless --verbose
        """,
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        metavar="N",
        help="爬取最近 N 天內的公告（預設: 30）",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="輸出 HTML 報表路徑（預設: output/report-YYYY-MM-DD-HHMMss.html）",
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        help="顯示瀏覽器視窗（除錯用，預設為 headless 模式）",
    )
    parser.add_argument(
        "--min-cvss",
        type=float,
        default=7.0,
        metavar="SCORE",
        help="CVSS Base Score 最低門檻（預設: 7.0）",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="顯示詳細 debug 訊息",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # 若未指定輸出路徑，自動產生含日期時間的檔名
    if args.output is None:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        args.output = f"output/report-{timestamp}.html"

    # 建立輸出目錄
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    headless = not args.no_headless
    logger.info("=" * 60)
    logger.info("IBM WAS CVE Scraper 開始執行")
    logger.info("  時間範圍: 最近 %d 天", args.days)
    logger.info("  最低 CVSS: %.1f", args.min_cvss)
    logger.info("  瀏覽器模式: %s", "Headless" if headless else "有頭模式")
    logger.info("  輸出路徑: %s", args.output)
    logger.info("=" * 60)

    driver = None
    try:
        # 初始化 WebDriver
        logger.info("初始化 Chrome WebDriver...")
        driver = create_driver(headless=headless)

        # ── Step 1：爬取清單頁 ──
        logger.info("\n【Step 1】爬取 IBM Security Bulletin 清單頁...")
        bulletin_list = crawler.fetch_bulletin_list(driver, days=args.days)

        if not bulletin_list:
            logger.warning("清單頁沒有找到符合條件的公告（Severity=High/Critical，最近 %d 天）", args.days)
            logger.info("提示：可嘗試增加 --days 參數，或使用 --no-headless 確認頁面是否正常載入")
            # 仍然生成空報表
            report.generate_html([], args.output, args.days, args.min_cvss)
            logger.info("已生成空報表: %s", args.output)
            return

        logger.info("清單頁找到 %d 筆符合條件的公告", len(bulletin_list))

        # ── Step 2：逐一進入內頁解析詳細資訊 ──
        logger.info("\n【Step 2】逐一解析內頁詳細資訊...")
        total = len(bulletin_list)
        all_rows: list[SecurityBulletin] = []

        for i, item in enumerate(bulletin_list, 1):
            logger.info("[%d/%d] 解析: %s", i, total, item.get("title", "")[:60])
            try:
                bulletin = detail_parser.parse_bulletin_detail(driver, item)
                # 將一筆 Bulletin 展開為多筆（每個 CVE 各自一列）
                rows = expand_bulletin_to_rows(bulletin, min_cvss=args.min_cvss)
                all_rows.extend(rows)
                logger.info(
                    "  展開為 %d 筆（符合 CVSS >= %.1f）",
                    len(rows), args.min_cvss
                )
            except Exception as e:
                logger.error("[%d/%d] 解析失敗，略過: %s", i, total, e)

            # 爬取間隔，避免 rate limiting
            if i < total:
                time.sleep(1.5)

        logger.info("內頁解析完成，共產生 %d 筆 CVE 列", len(all_rows))

        # ── Step 3：依 CVSS 排序（高分在前）──
        logger.info("\n【Step 3】依 CVSS 分數排序...")
        filtered = sorted(all_rows, key=lambda b: b.cvss_score, reverse=True)
        logger.info("最終納入報表: %d 筆", len(filtered))

        # ── Step 4：生成 HTML 報表 ──
        logger.info("\n【Step 4】生成 HTML 報表...")
        report.generate_html(filtered, args.output, args.days, args.min_cvss)

        logger.info("\n" + "=" * 60)
        logger.info("✅ 完成！報表已輸出至: %s", os.path.abspath(args.output))
        logger.info("   總計: %d 筆高風險 CVE 公告", len(filtered))
        logger.info("=" * 60)

    except KeyboardInterrupt:
        logger.info("\n使用者中斷執行")
        sys.exit(0)
    except Exception as e:
        logger.error("執行失敗: %s", e, exc_info=True)
        sys.exit(1)
    finally:
        if driver:
            logger.info("關閉 WebDriver")
            driver.quit()


if __name__ == "__main__":
    main()
