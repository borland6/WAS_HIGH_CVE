"""
report.py — HTML 報表生成器

將 SecurityBulletin 列表轉換為 Bootstrap 5 + DataTables 的 HTML 報表。

表格欄位（依序）:
  1. Security Bulletin（含連結）
  2. Affected WAS Version（固定 "9.0, 8.5"）
  3. CVE-ID（連結至 MITRE）
  4. Severity（顏色 badge）
  5. Publish Date
  6. CVSS Base Score（顏色標籤）
  7. iFix（V9 / V8 各自連結）
  8. Fixpack Version（V9 / V8）
  9. Fixpack Release Date（V9 / V8）
"""

import logging
import os
from datetime import datetime
from typing import List

from models import SecurityBulletin

logger = logging.getLogger(__name__)

MITRE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"


# ─────────────────────────────────────────────
# 輔助函式
# ─────────────────────────────────────────────

def _severity_badge(severity: str) -> str:
    """回傳 Bootstrap badge HTML，Critical 紅色，High 橙色。"""
    s = severity.strip().lower()
    if s == "critical":
        return (
            '<span class="badge rounded-pill bg-danger px-3 py-2 fs-badge">'
            f'Critical</span>'
        )
    elif s == "high":
        return (
            '<span class="badge rounded-pill px-3 py-2 fs-badge" '
            'style="background-color:#fd7e14;">High</span>'
        )
    elif s == "medium":
        return (
            '<span class="badge rounded-pill bg-warning text-dark px-3 py-2 fs-badge">'
            f'Medium</span>'
        )
    elif s == "low":
        return (
            '<span class="badge rounded-pill bg-secondary px-3 py-2 fs-badge">'
            f'Low</span>'
        )
    return f'<span class="badge rounded-pill bg-secondary px-3 py-2 fs-badge">{severity or "N/A"}</span>'


def _cvss_badge(score: float) -> str:
    """回傳 CVSS Score 顏色標籤：≥9.0 紅色，7.0-8.9 橙色，<7.0 灰色。"""
    if score <= 0:
        return '<span class="cvss-badge cvss-na">N/A</span>'
    elif score >= 9.0:
        return f'<span class="cvss-badge cvss-critical">{score:.1f}</span>'
    elif score >= 7.0:
        return f'<span class="cvss-badge cvss-high">{score:.1f}</span>'
    else:
        return f'<span class="cvss-badge cvss-medium">{score:.1f}</span>'


def _cve_link(cve_id: str) -> str:
    """將單一 CVE ID 轉換為 MITRE 連結 HTML。"""
    if not cve_id:
        return '<span class="text-muted">N/A</span>'
    url = MITRE_URL.format(cve_id=cve_id)
    return f'<a href="{url}" target="_blank" rel="noopener" class="cve-link">{cve_id}</a>'


def _ifix_cell(
    v9_label: str,
    v9_url: str,
    v8_label: str,
    v8_url: str,
    liberty_label: str = "",
    liberty_url: str = "",
    is_liberty: bool = False,
) -> str:
    """回傳 iFix 欄位 HTML。"""
    lines = []

    def _make_link(label: str, url: str, prefix: str) -> str:
        if not label:
            return ""
        text = f"{prefix}{label}"
        if url:
            return f'<a href="{url}" target="_blank" rel="noopener" class="ifix-link">{text}</a>'
        return f'<span class="ifix-text">{text}</span>'

    if is_liberty:
        liberty = _make_link(v9_label, v9_url, "Liberty: ")
        if liberty:
            lines.append(liberty)
    else:
        v9 = _make_link(v9_label, v9_url, "V9: ")
        v8 = _make_link(v8_label, v8_url, "V8: ")
        liberty = _make_link(liberty_label, liberty_url, "Liberty: ")
        if v9:
            lines.append(v9)
        if v8:
            lines.append(v8)
        if liberty:
            lines.append(liberty)

    return "<br>".join(lines) if lines else '<span class="text-muted">—</span>'


def _fixpack_cell(v9: str, v8: str, liberty: str = "", is_liberty: bool = False) -> str:
    """回傳 Fixpack Version 欄位 HTML。"""
    lines = []
    if is_liberty:
        if v9:
            lines.append(f'<span class="version-tag liberty-tag">Liberty: {v9}</span>')
    else:
        if v9:
            lines.append(f'<span class="version-tag v9-tag">V9: {v9}</span>')
        if v8:
            lines.append(f'<span class="version-tag v8-tag">V8: {v8}</span>')
        if liberty:
            lines.append(f'<span class="version-tag liberty-tag">Liberty: {liberty}</span>')
    return "<br>".join(lines) if lines else '<span class="text-muted">—</span>'


def _fixdate_cell(v9_date: str, v8_date: str, liberty_date: str = "", is_liberty: bool = False) -> str:
    """回傳 Fixpack Release Date 欄位 HTML。"""
    lines = []
    if is_liberty:
        if v9_date:
            lines.append(f'<span class="date-tag">Liberty: {v9_date}</span>')
    else:
        if v9_date:
            lines.append(f'<span class="date-tag">V9: {v9_date}</span>')
        if v8_date:
            lines.append(f'<span class="date-tag">V8: {v8_date}</span>')
        if liberty_date:
            lines.append(f'<span class="date-tag">Liberty: {liberty_date}</span>')
    return "<br>".join(lines) if lines else '<span class="text-muted">—</span>'


def _bulletin_link(title: str, url: str) -> str:
    """回傳 Security Bulletin 標題連結 HTML。"""
    if url:
        return f'<a href="{url}" target="_blank" rel="noopener" class="bulletin-link">{title or url}</a>'
    return title or "N/A"


def _build_table_rows(bulletins: List[SecurityBulletin]) -> str:
    """組裝所有表格列 HTML。"""
    rows = []
    for b in bulletins:
        # 判斷是否為 Liberty-only（只有 V9 欄承載 Liberty 資料）
        is_liberty = (
            not b.ifix_v8 and not b.fixpack_v8 and not b.fixpack_date_v8
            and not b.ifix_liberty and not b.fixpack_liberty and not b.fixpack_date_liberty
            and b.affected_versions != "9.0, 8.5"
        )

        # 依 Severity 決定列背景色
        sev = b.severity.lower()
        row_class = "table-danger-light" if sev == "critical" else ("table-warning-light" if sev == "high" else "")

        row = f"""        <tr class="{row_class}">
          <td class="bulletin-col">{_bulletin_link(b.title, b.bulletin_url)}</td>
          <td class="text-center">{b.affected_versions}</td>
          <td class="cve-col">{_cve_link(b.cve_id)}</td>
          <td class="text-center">{_severity_badge(b.severity)}</td>
          <td class="text-nowrap">{b.publish_date or "—"}</td>
          <td class="text-center">{_cvss_badge(b.cvss_score)}</td>
          <td class="fix-col">{_ifix_cell(b.ifix_v9, b.ifix_v9_url, b.ifix_v8, b.ifix_v8_url, b.ifix_liberty, b.ifix_liberty_url, is_liberty)}</td>
          <td class="fix-col">{_fixpack_cell(b.fixpack_v9, b.fixpack_v8, b.fixpack_liberty, is_liberty)}</td>
          <td class="text-center">{_fixdate_cell(b.fixpack_date_v9, b.fixpack_date_v8, b.fixpack_date_liberty, is_liberty)}</td>
        </tr>"""
        rows.append(row)
    return "\n".join(rows)


# ─────────────────────────────────────────────
# 主要函式
# ─────────────────────────────────────────────

def generate_html(
    bulletins: List[SecurityBulletin],
    output_path: str,
    days: int = 30,
    min_cvss: float = 7.0,
) -> None:
    """
    生成 HTML 報表檔案。

    Parameters
    ----------
    bulletins : List[SecurityBulletin]
        已篩選的公告列表
    output_path : str
        輸出 HTML 檔案路徑
    days : int
        查詢的天數範圍（用於報表摘要顯示）
    min_cvss : float
        CVSS 篩選門檻（用於報表摘要顯示）
    """
    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(bulletins)
    critical_count = sum(1 for b in bulletins if b.severity.lower() == "critical")
    high_count = sum(1 for b in bulletins if b.severity.lower() == "high")

    table_rows = _build_table_rows(bulletins)

    html = f"""<!DOCTYPE html>
<html lang="zh-Hant">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IBM WAS High-Risk CVE Report</title>

  <!-- Bootstrap 5 -->
  <link rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
    crossorigin="anonymous">

  <!-- DataTables + Bootstrap 5 整合 -->
  <link rel="stylesheet"
    href="https://cdn.datatables.net/1.13.8/css/dataTables.bootstrap5.min.css">

  <style>
    /* ── 基礎樣式 ── */
    body {{
      font-size: 14px;
      background-color: #f8f9fa;
    }}
    .page-wrapper {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 24px 16px;
    }}

    /* ── 頁頭 ── */
    .report-header {{
      background: #1d3557;
      color: #fff;
      border-radius: 8px;
      padding: 24px 28px;
      margin-bottom: 20px;
    }}
    .report-header h1 {{
      font-size: 1.5rem;
      font-weight: 600;
      margin: 0 0 8px 0;
    }}
    .report-header .subtitle {{
      font-size: 0.875rem;
      opacity: 0.85;
    }}

    /* ── 統計卡片 ── */
    .stat-card {{
      border: none;
      border-radius: 8px;
    }}
    .stat-card .card-body {{
      padding: 16px 20px;
    }}
    .stat-card .stat-number {{
      font-size: 2rem;
      font-weight: 700;
      line-height: 1;
    }}
    .stat-card .stat-label {{
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-top: 4px;
    }}

    /* ── 表格 ── */
    .table-wrapper {{
      background: #fff;
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 1px 4px rgba(0,0,0,.08);
    }}
    table.dataTable thead th {{
      background-color: #1d3557;
      color: #fff;
      font-weight: 500;
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      white-space: nowrap;
      border: none !important;
    }}
    table.dataTable tbody tr:hover {{
      background-color: #f0f4ff !important;
    }}
    .table-danger-light {{
      background-color: #fff5f5 !important;
    }}
    .table-warning-light {{
      background-color: #fffbf0 !important;
    }}

    /* ── Severity Badge ── */
    .fs-badge {{
      font-size: 0.75rem;
    }}

    /* ── CVSS Badge ── */
    .cvss-badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 12px;
      font-weight: 700;
      font-size: 0.88rem;
    }}
    .cvss-critical {{
      background-color: #dc3545;
      color: #fff;
    }}
    .cvss-high {{
      background-color: #fd7e14;
      color: #fff;
    }}
    .cvss-medium {{
      background-color: #ffc107;
      color: #212529;
    }}
    .cvss-na {{
      background-color: #dee2e6;
      color: #6c757d;
    }}

    /* ── CVE 連結 ── */
    .cve-link {{
      font-family: monospace;
      font-size: 0.82rem;
      color: #1d3557;
      text-decoration: none;
      white-space: nowrap;
    }}
    .cve-link:hover {{
      text-decoration: underline;
      color: #e63946;
    }}

    /* ── Bulletin 連結 ── */
    .bulletin-link {{
      color: #1d3557;
      font-size: 0.83rem;
      text-decoration: none;
      line-height: 1.4;
    }}
    .bulletin-link:hover {{
      color: #e63946;
      text-decoration: underline;
    }}

    /* ── iFix 連結 ── */
    .ifix-link {{
      font-family: monospace;
      font-size: 0.82rem;
      color: #0d6efd;
      text-decoration: none;
    }}
    .ifix-link:hover {{
      text-decoration: underline;
    }}
    .ifix-text {{
      font-family: monospace;
      font-size: 0.82rem;
      color: #495057;
    }}

    /* ── Version Tag ── */
    .version-tag {{
      display: inline-block;
      font-family: monospace;
      font-size: 0.8rem;
      padding: 2px 7px;
      border-radius: 4px;
    }}
    .v9-tag {{
      background-color: #cfe2ff;
      color: #084298;
    }}
    .v8-tag {{
      background-color: #d1e7dd;
      color: #0a3622;
    }}
    .liberty-tag {{
      background-color: #e2d9f3;
      color: #432874;
    }}

    /* ── Date Tag ── */
    .date-tag {{
      display: inline-block;
      font-size: 0.8rem;
      color: #495057;
    }}

    /* ── 欄位寬度 ── */
    .bulletin-col {{ min-width: 200px; max-width: 320px; }}
    .cve-col {{ min-width: 130px; }}
    .fix-col {{ min-width: 120px; }}

    /* ── Footer ── */
    .report-footer {{
      text-align: center;
      font-size: 0.75rem;
      color: #6c757d;
      margin-top: 24px;
      padding-top: 12px;
      border-top: 1px solid #dee2e6;
    }}

    /* ── RWD ── */
    @media (max-width: 768px) {{
      .report-header h1 {{ font-size: 1.2rem; }}
      .stat-card .stat-number {{ font-size: 1.5rem; }}
    }}
  </style>
</head>

<body>
<div class="page-wrapper">

  <!-- 頁頭 -->
  <div class="report-header">
    <h1>🔒 IBM WebSphere Application Server — High-Risk CVE Report</h1>
    <div class="subtitle">
      資料來源：IBM Security Bulletins &nbsp;|&nbsp;
      查詢範圍：最近 <strong>{days}</strong> 天 &nbsp;|&nbsp;
      CVSS 門檻：<strong>≥ {min_cvss:.1f}</strong> &nbsp;|&nbsp;
      報表生成時間：<strong>{generated_time}</strong>
    </div>
  </div>

  <!-- 統計卡片 -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
      <div class="card stat-card bg-primary text-white">
        <div class="card-body">
          <div class="stat-number">{total}</div>
          <div class="stat-label">Total Bulletins</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="card stat-card bg-danger text-white">
        <div class="card-body">
          <div class="stat-number">{critical_count}</div>
          <div class="stat-label">Critical</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="card stat-card text-white" style="background-color:#fd7e14;">
        <div class="card-body">
          <div class="stat-number">{high_count}</div>
          <div class="stat-label">High</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="card stat-card bg-dark text-white">
        <div class="card-body">
          <div class="stat-number">{days}</div>
          <div class="stat-label">Days Range</div>
        </div>
      </div>
    </div>
  </div>

  <!-- 報表表格 -->
  <div class="table-wrapper">
    <div class="table-responsive">
      <table id="cveTable" class="table table-bordered table-sm align-middle w-100">
        <thead>
          <tr>
            <th>Security Bulletin</th>
            <th class="text-center">Affected WAS Version</th>
            <th class="text-center">CVE-ID</th>
            <th class="text-center">Severity</th>
            <th class="text-center">Publish Date</th>
            <th class="text-center">CVSS Base Score</th>
            <th class="text-center">iFix</th>
            <th class="text-center">Fixpack Version</th>
            <th class="text-center">Fixpack Release Date</th>
          </tr>
        </thead>
        <tbody>
{table_rows if table_rows else '          <tr><td colspan="9" class="text-center text-muted py-4">沒有找到符合條件的高風險 CVE 公告</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Footer -->
  <div class="report-footer">
    Generated by IBM WAS CVE Scraper &nbsp;|&nbsp; {generated_time}
  </div>

</div><!-- /page-wrapper -->

<!-- jQuery -->
<script src="https://code.jquery.com/jquery-3.7.1.min.js" crossorigin="anonymous"></script>
<!-- Bootstrap 5 JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"
  crossorigin="anonymous"></script>
<!-- DataTables -->
<script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.8/js/dataTables.bootstrap5.min.js"></script>

<script>
  $(document).ready(function () {{
    $('#cveTable').DataTable({{
      pageLength: 25,
      lengthMenu: [10, 25, 50, 100],
      order: [[5, 'desc']],  // 預設依 CVSS Score 降冪排序
      language: {{
        search: '搜尋：',
        lengthMenu: '每頁顯示 _MENU_ 筆',
        info: '顯示第 _START_ 至 _END_ 筆，共 _TOTAL_ 筆',
        infoEmpty: '沒有資料',
        zeroRecords: '找不到符合條件的記錄',
        paginate: {{
          first: '第一頁',
          last: '最末頁',
          next: '下一頁',
          previous: '上一頁'
        }}
      }},
      columnDefs: [
        {{ orderable: false, targets: [0, 2, 6, 7, 8] }},  // 不可排序的欄位
        {{ className: 'text-center', targets: [1, 2, 3, 4, 5, 6, 7, 8] }}
      ],
      responsive: true
    }});
  }});
</script>

</body>
</html>"""

    # 寫入檔案
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("HTML 報表已寫入: %s（共 %d 筆）", output_path, total)
