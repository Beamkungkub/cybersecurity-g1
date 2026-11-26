#!/usr/bin/env python3
"""analyze_v2.py - วิเคราะห์ IIS log แบบ "ผลลัพธ์ปลอดภัยต่อการแชร์" (Group Work 1)
- รันบนเครื่องตัวเองเท่านั้น ห้ามอัปโหลด log
- IP ในผลลัพธ์ถูกแทนด้วย INT-001 / EXT-001 ; ตารางจับคู่จริงเขียนลง ip_map_LOCAL_ONLY.csv (ห้ามส่งต่อ)
- query string แสดงเฉพาะ "ชื่อพารามิเตอร์" ไม่แสดงค่า
usage: python -X utf8 analyze_v2.py <log_dir> > result_v2.txt   (ใน PowerShell ใช้ cmd /c เพื่อให้เป็น UTF-8)
"""
import sys, os, re, glob, csv, ipaddress
from collections import Counter, defaultdict

STATIC = re.compile(r"\.(css|js|png|jpe?g|gif|ico|svg|woff2?|ttf|map)$|\.axd$", re.I)
BURST_N, ID_MIN_DISTINCT = 5, 10

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
                a = ipaddress.ip_address(ip)
                kind = "LOOP" if a.is_loopback else ("INT" if a.is_private else "EXT")
            except ValueError: kind = "UNK"
            self.c[kind] += 1; self.m[ip] = f"{kind}-{self.c[kind]:03d}"
        return self.m[ip]

def top(c, n=10, fmt=None):
    for k, v in c.most_common(n): print(f"  {v:>7}  {fmt(k) if fmt else k}")

def main(d):
    fs = sorted(set(glob.glob(os.path.join(d, "**", "*.log"), recursive=True)))
    if not fs: sys.exit("ไม่พบไฟล์ .log")
    mk = Masker()
    n = ns = 0
    status_by_kind = defaultdict(Counter); ips = Counter(); sec = Counter()
    ids = defaultdict(set); id_status = defaultdict(Counter)
    login = defaultdict(Counter); u_ips = defaultdict(set); ip_users = defaultdict(set)
    e404, e5xx, hourc = Counter(), Counter(), Counter()
    tt = defaultdict(list); ext_stems = Counter(); methods_uri = defaultdict(Counter)
    for f in fs:
        for r in rows(f):
            n += 1
            lab = mk(r["c-ip"]); kind = lab.split("-")[0]
            stem, q, s = r["cs-uri-stem"], r.get("cs-uri-query", "-"), r["sc-status"]
            if kind == "LOOP": continue
            if STATIC.search(stem): ns += 1; continue
            t = f'{r["date"]} {r["time"]}'; m = r["cs-method"]
            status_by_kind[kind][s] += 1; ips[lab] += 1; sec[(lab, t)] += 1; hourc[t[11:13]] += 1
            methods_uri[stem][m] += 1
            try: tt[stem].append(int(r["time-taken"]))
            except (KeyError, ValueError): pass
            pnames = tuple(sorted(x.split("=")[0] for x in q.split("&"))) if q not in ("-", "") else ()
            u = r.get("cs-username", "-")
            if u != "-": u_ips[u].add(lab); ip_users[lab].add(u)
            if kind == "EXT": ext_stems[stem] += 1
            for x in (q.split("&") if q != "-" else []):
                if x.lower().startswith("id="): ids[(lab, stem)].add(x[3:]); id_status[(lab, stem)][s] += 1
            if "login" in stem.lower() and m == "POST": login[(lab, stem)][s] += 1
            if s == "404": e404[stem] += 1
            if s[:1] == "5": e5xx[(s, stem, pnames)] += 1
    with open("ip_map_LOCAL_ONLY.csv", "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows([("ip", "label"), *mk.m.items()])
    print(f"== SUMMARY ==\n  total records: {n}  | loopback ข้ามไว้ | static/.axd ข้ามไว้: {ns}  | วิเคราะห์: {sum(ips.values())}")
    print("  IP labels:", dict(mk.c), "\n  หมายเหตุ: เวลาใน log ไม่ทราบ timezone (IIS ปกติเป็น UTC)")
    print("\n== STATUS แยก INT/EXT (ไม่รวม static) ==")
    for k, c in status_by_kind.items(): print(" ", k, dict(c))
    print("\n== TOP IP (masked, ไม่รวม static) =="); top(ips)
    bs = Counter({k: v for k, v in sec.items() if v >= BURST_N})
    print(f"\n== BURST ไม่รวม static: >={BURST_N} req/วินาที  (ทั้งหมด {len(bs)}) ==")
    for (lab, t), v in bs.most_common(10): print(f"  {v:>4}  {lab}  {t}")
    print(f"\n== ID PARAM: (IP,หน้า) ที่ใช้ id= ต่างกัน >= {ID_MIN_DISTINCT} ค่า ==")
    for (lab, stem), vs in sorted(ids.items(), key=lambda x: -len(x[1])):
        if len(vs) < ID_MIN_DISTINCT: break
        nums = sorted(int(v) for v in vs if v.isdigit())
        seq = sum(1 for a, b in zip(nums, nums[1:]) if b - a == 1) / max(len(nums) - 1, 1)
        print(f"  {lab} {stem}  distinct={len(vs)} sequential_ratio={seq:.2f} status={dict(id_status[(lab, stem)])}")
    print("\n== LOGIN (POST) ต่อ IP/หน้า =="); [print(f"  {k[0]} {k[1]} {dict(c)}") for k, c in sorted(login.items(), key=lambda x: -sum(x[1].values()))[:10]]
    print("\n== USER ที่ใช้ >1 IP (top) ==")
    for u, s_ in sorted(u_ips.items(), key=lambda x: -len(x[1]))[:10]: print(f"  {u}: {len(s_)} IP")
    print("== IP ที่มี >1 user (top) ==")
    for l, s_ in sorted(ip_users.items(), key=lambda x: -len(x[1]))[:10]: print(f"  {l}: {len(s_)} users")
    print("\n== 404 ตามหน้า =="); top(e404)
    print("\n== 5xx (status, หน้า, ชื่อพารามิเตอร์) =="); top(e5xx, 15)
    print("\n== EXT: หน้าที่ถูกเรียก =="); top(ext_stems)
    print("\n== ชั่วโมงของวัน (ตามเวลาใน log) =="); [print(f"  {h}:00  {c}") for h, c in sorted(hourc.items())]
    print("\n== ช้าที่สุด (avg time-taken ms, >=5 ครั้ง) ==")
    for stem, v in sorted(((s, sum(x)/len(x)) for s, x in tt.items() if len(x) >= 5), key=lambda z: -z[1])[:10]: print(f"  {v:>9.0f}  {stem}")
    print("\n== METHOD ผสมต่อหน้า (GET+POST) ==")
    for stem, c in sorted(methods_uri.items(), key=lambda x: -sum(x[1].values()))[:8]: print(f"  {dict(c)}  {stem}")

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else ".")