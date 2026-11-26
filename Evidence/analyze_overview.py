#!/usr/bin/env python3
"""analyze_overview.py - ภาพรวม IIS log (W3C extended) สำหรับ Group Work 1
usage: python analyze_overview.py <log_dir_or_file> [> result_overview.txt]
อ่าน #Fields อัตโนมัติ ไม่ต้องแก้ script ถ้า field ต่างกัน
"""
import sys, os, re, glob
from collections import Counter, defaultdict

PATTERNS = {  # ตรวจเฉพาะ cs-uri-stem + cs-uri-query (ถ้ามี) ผลเป็น "ตัวบ่งชี้" ไม่ใช่การยืนยันการโจมตี
    "sqli":       re.compile(r"(union(\s|%20|\+)+select|select(\s|%20|\+).+from|or(\s|%20|\+)+1=1|sleep\(|waitfor|information_schema|xp_cmdshell|'--|%27)", re.I),
    "traversal":  re.compile(r"(\.\./|\.\.%2f|%2e%2e|\.\.\\|etc/passwd|win\.ini|boot\.ini)", re.I),
    "webshell":   re.compile(r"\.(aspx?|asmx|ashx|php|jsp|cer|config|bak|sql|zip)(\?|$)", re.I),
    "scanner_path": re.compile(r"(wp-login|wp-admin|phpmyadmin|\.env|\.git|/admin|actuator|cgi-bin|vendor/phpunit|manager/html)", re.I),
    "xss":        re.compile(r"(<script|%3cscript|onerror=|javascript:)", re.I),
}
TOOL_UA = re.compile(r"(sqlmap|nikto|nmap|curl|python-requests|go-http|masscan|zgrab|wget|java/|httpclient|postman|nuclei|dirbuster|gobuster)", re.I)

def files(p):
    if os.path.isfile(p): return [p]
    fs = []
    for ext in ("*.log", "*.txt", "*.log.*"):
        fs += glob.glob(os.path.join(p, "**", ext), recursive=True)
    return sorted(set(fs))

def rows(path):
    fields = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#Fields:"):
                fields = line[8:].split(); continue
            if line.startswith("#") or not line.strip() or not fields: continue
            parts = line.split(" ")
            if len(parts) != len(fields): continue
            yield dict(zip(fields, parts))

def top(c, n=10):
    for k, v in c.most_common(n): print(f"  {v:>8}  {k}")

def main(p):
    fs = files(p)
    if not fs: sys.exit(f"ไม่พบไฟล์ log ใน {p}")
    print("== FILES =="); [print(" ", f) for f in fs]
    ips, st, uri, ua, hour, meth = (Counter() for _ in range(6))
    sec = defaultdict(int)            # (ip, วินาที) -> จำนวน request
    hits = {k: Counter() for k in PATTERNS}
    err_uri, tool_ua = Counter(), Counter()
    fields_seen, n, tmin, tmax = set(), 0, None, None
    for f in fs:
        for r in rows(f):
            n += 1; fields_seen |= set(r)
            ip = r.get("c-ip", "-"); t = f'{r.get("date","")} {r.get("time","")}'
            tmin = min(tmin, t) if tmin else t; tmax = max(tmax, t) if tmax else t
            s = r.get("sc-status", "-"); stem = r.get("cs-uri-stem", "-"); q = r.get("cs-uri-query", "-")
            u = r.get("cs(User-Agent)", "-")
            ips[ip] += 1; st[s] += 1; uri[stem] += 1; ua[u] += 1; meth[r.get("cs-method", "-")] += 1
            hour[t[:13]] += 1; sec[(ip, t)] += 1
            if s[:1] in "45": err_uri[(s, stem)] += 1
            if TOOL_UA.search(u): tool_ua[u] += 1
            target = stem + ("?" + q if q not in ("-", "") else "")
            for k, rx in PATTERNS.items():
                if rx.search(target): hits[k][f"{ip} {s} {target[:110]}"] += 1
    print(f"\n== SUMMARY ==\n  requests: {n}\n  range: {tmin} -> {tmax}\n  unique IPs: {len(ips)}")
    print("  fields:", " ".join(sorted(fields_seen)))
    for need in ("cs-uri-query", "cs(Referer)", "cs(User-Agent)", "sc-status", "sc-bytes", "time-taken"):
        if need not in fields_seen: print(f"  [!] log ไม่มี field {need}  -> เป็นข้อจำกัด/Visibility gap ที่ควรเขียนในรายงาน")
    for title, c in (("TOP IPs", ips), ("STATUS", st), ("METHODS", meth), ("TOP URI", uri), ("TOP USER-AGENT", ua),
                     ("TOP 4xx/5xx (status,uri)", err_uri), ("TOOL-LIKE USER-AGENT", tool_ua), ("REQUESTS PER HOUR", hour)):
        print(f"\n== {title} =="); top(c, 24 if title.startswith("REQUESTS") else 10)
    burst = Counter({k: v for k, v in sec.items() if v >= 5})
    print("\n== SUB-SECOND/BURST: (ip, วินาที) ที่มี >=5 requests ใน 1 วินาที ==")
    for (ip, t), v in burst.most_common(15): print(f"  {v:>4}  {ip}  {t}")
    print(f"  จำนวน (ip,วินาที) ที่เป็น burst ทั้งหมด: {len(burst)}")
    for k, c in hits.items():
        print(f"\n== INDICATOR: {k} (ตัวบ่งชี้ ต้องตรวจ status/บริบทก่อนสรุป) =="); top(c, 8)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")