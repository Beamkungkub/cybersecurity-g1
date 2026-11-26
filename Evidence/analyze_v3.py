#!/usr/bin/env python3
"""analyze_v3.py - ตรวจสมมติฐานเฉพาะจุดของ Group Work 1 (ผลลัพธ์ปลอดภัยต่อการแชร์)
รันบนเครื่องตัวเองเท่านั้น ห้ามอัปโหลด log | IP ถูก mask (INT/EXT/LOOP) | ไม่แสดงค่า query | referer แสดงเฉพาะ path
usage: cmd /c 'python -X utf8 analyze_v3.py "<log_dir>" > result_v3.txt'
"""
import sys, os, re, glob, ipaddress
from collections import Counter, defaultdict
from urllib.parse import urlparse
from datetime import datetime

SENS = re.compile(r"(salary|repslip|staffinfo|staffattrequest|web025)", re.I)   # แก้รายการได้
ASMX = re.compile(r"\.asmx$", re.I)
PAGERES = re.compile(r"pageresource\.aspx$", re.I)
LOGIN = re.compile(r"login\.aspx$", re.I)

def rows(path):
    fields = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#Fields:"): fields = line[8:].split(); continue
            if line.startswith("#") or not line.strip() or not fields: continue
            p = line.split(" ")
            if len(p) == len(fields): yield dict(zip(fields, p))

class Masker:
    def __init__(self): self.m, self.c = {}, Counter()
    def __call__(self, ip):
        if ip not in self.m:
            try:
                a = ipaddress.ip_address(ip); k = "LOOP" if a.is_loopback else ("INT" if a.is_private else "EXT")
            except ValueError: k = "UNK"
            self.c[k] += 1; self.m[ip] = f"{k}-{self.c[k]:03d}"
        return self.m[ip]

def ref_path(r):
    if r in ("-", ""): return "-"
    try: return urlparse(r).path or "/"
    except Exception: return "?"

def family(ua):
    for k in ("MSIE", "Edg/", "Firefox", "Chrome", "Safari", "Web+Services"):
        if k in ua: return k
    return "other"

def top(c, n=8):
    for k, v in c.most_common(n): print(f"  {v:>6}  {k}")

def main(d):
    mk = Masker(); recs = []
    for f in sorted(glob.glob(os.path.join(d, "**", "*.log"), recursive=True)):
        for r in rows(f):
            r["_lab"] = mk(r["c-ip"]); r["_k"] = r["_lab"].split("-")[0]
            r["_t"] = datetime.strptime(r["date"] + " " + r["time"], "%Y-%m-%d %H:%M:%S"); recs.append(r)
    recs.sort(key=lambda r: r["_t"])
    print(f"records: {len(recs)}")

    print("\n== A. บริการ .asmx (รวม loopback): ความถี่/ความสม่ำเสมอ/status ==")
    by = defaultdict(list)
    for r in recs:
        if ASMX.search(r["cs-uri-stem"]): by[(r["cs-uri-stem"], r["_k"])].append(r)
    for (stem, k), L in by.items():
        gaps = Counter(int((b["_t"] - a["_t"]).total_seconds()) for a, b in zip(L, L[1:]))
        days = Counter(x["date"] for x in L)
        print(f"  {stem} [{k}] n={len(L)} status={dict(Counter(x['sc-status'] for x in L))} method={dict(Counter(x['cs-method'] for x in L))}")
        print(f"    ต่อวัน: {dict(sorted(days.items()))}\n    ช่วงห่างระหว่างครั้ง (วินาที:จำนวน) top5: {gaps.most_common(5)}")
        print(f"    avg time-taken(ms)={sum(int(x['time-taken']) for x in L)/len(L):.0f}  sc-bytes distinct={len(set(x['sc-bytes'] for x in L))}")

    print("\n== B. PageResource.aspx ==")
    P = [r for r in recs if PAGERES.search(r["cs-uri-stem"])]
    print(f"  n={len(P)} status={dict(Counter(r['sc-status'] for r in P))} INT/EXT={dict(Counter(r['_k'] for r in P))}")
    print("  referer path top:"); top(Counter(ref_path(r["cs(Referer)"]) for r in P), 5)
    print("  param names:", Counter(tuple(sorted(x.split('=')[0] for x in r['cs-uri-query'].split('&'))) for r in P if r['cs-uri-query'] != '-').most_common(3))
    print("  ต่อวัน:", dict(sorted(Counter(r["date"] for r in P).items())))

    print("\n== C. หน้าสำคัญ (SENS): INT/EXT, method, status, พารามิเตอร์ ==")
    S = defaultdict(list)
    for r in recs:
        if SENS.search(r["cs-uri-stem"]): S[r["cs-uri-stem"]].append(r)
    for stem, L in sorted(S.items(), key=lambda x: -len(x[1])):
        ext = [x for x in L if x["_k"] == "EXT"]
        pn = Counter(tuple(sorted(y.split("=")[0] for y in x["cs-uri-query"].split("&"))) for x in L if x["cs-uri-query"] != "-")
        gq = sum(1 for x in L if x["cs-method"] == "GET" and x["cs-uri-query"] != "-")
        print(f"  {stem}\n    n={len(L)} EXT={len(ext)} (EXT IP {len(set(x['_lab'] for x in ext))}, EXT user {len(set(x['cs-username'] for x in ext))}) status={dict(Counter(x['sc-status'] for x in L))} GET-with-query={gq}")
        print(f"    EXT status={dict(Counter(x['sc-status'] for x in ext))} param sets top2={pn.most_common(2)}")

    print("\n== D. ผู้ใช้/IP ภายนอกที่เข้าหน้าสำคัญ ==")
    E = defaultdict(list)
    for L in S.values():
        for x in L:
            if x["_k"] == "EXT": E[x["_lab"]].append(x)
    for lab, L in sorted(E.items(), key=lambda x: -len(x[1]))[:12]:
        print(f"  {lab} n={len(L)} users={sorted(set(x['cs-username'] for x in L))} status={dict(Counter(x['sc-status'] for x in L))} วัน={sorted(set(x['date'] for x in L))}")

    print("\n== E. login POST: ลำดับต่อ IP (200 = ฟอร์มแสดงซ้ำ, 302 = redirect) ==")
    seq = defaultdict(list)
    for r in recs:
        if LOGIN.search(r["cs-uri-stem"]) and r["cs-method"] == "POST": seq[r["_lab"]].append(r["sc-status"])
    runs = 0
    for lab, s in seq.items():
        cur = best = 0
        for x in s: cur = cur + 1 if x == "200" else 0; best = max(best, cur)
        runs += best >= 3
    print(f"  IP ที่ POST login: {len(seq)} | IP ที่มี 200 ติดกัน >=3: {runs} | รวมสถานะ: {dict(Counter(x for s in seq.values() for x in s))}")

    print("\n== F. ร่องรอยสำรวจจากภายนอก: robots.txt / root ==")
    for r in recs:
        if r["_k"] == "EXT" and (r["cs-uri-stem"] in ("/robots.txt", "/", "/webname/")):
            print(f"  {r['_lab']} {r['date']} {r['cs-uri-stem']} {r['sc-status']} {family(r['cs(User-Agent)'])}") if r["cs-uri-stem"] == "/robots.txt" else None
    root = Counter((r["_lab"], r["cs-uri-stem"]) for r in recs if r["_k"] == "EXT" and r["cs-uri-stem"] in ("/", "/webname/"))
    print("  root/webname ต่อ (IP,path) top:"); top(Counter({f'{a} {b}': v for (a, b), v in root.items()}), 6)

    print("\n== G. 5xx: เวลา, IP(mask), หน้า, referer path ==")
    for r in recs:
        if r["sc-status"][:1] == "5": print(f"  {r['date']} {r['time']} {r['_lab']} {r['sc-status']}.{r['sc-substatus']} {r['cs-method']} {r['cs-uri-stem']} ref={ref_path(r['cs(Referer)'])}")

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else ".")