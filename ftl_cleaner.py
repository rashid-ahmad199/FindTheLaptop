# -*- coding: utf-8 -*-
"""
Find the Laptop - CLEANER (v2.1). Scans for malware, junk, hijacks, Task Manager hogs and ways in/out.
Shows everything in an HTML page. NOTHING is changed until you tick items, type CLEAN and press Approve.
Author: Rashid Ahmad
"""
import os, sys, time, datetime, threading, webbrowser
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
os.environ.setdefault("FTL_CLEANER", "1")
import findthelaptop as FT
import ftl_clean_core as C
import ftl_clean_scan as S
import ftl_clean_scan2 as S2
import ftl_clean_web as W
import ftl_engines as eng, ftl_engines2 as eng2


def main():
    quick = "--quick" in sys.argv
    os.makedirs(C.OUT, exist_ok=True)
    try: sys.stdout = FT.Tee(os.path.join(C.OUT, "cleaner_log.txt"))
    except Exception: pass
    if os.name == "nt": os.system("title Find the Laptop CLEANER - by Rashid Ahmad")
    print("=" * 62); print("  FIND THE LAPTOP - CLEANER v%s" % FT.VERSION); print("  %s" % FT.AUTHOR); print("=" * 62)
    if C.DRY: print("\n  [DRY RUN] This is not Windows or FTL_DRY=1: the page will work but NOTHING will be changed.\n")
    if "--consented" not in sys.argv and not C.DRY:
        print("\nThis scans the whole laptop for malware, junk, hijacks and open doors.\nIt changes NOTHING until you approve items in the page that opens.")
        if input("Continue? [Y/N]: ").strip().lower() not in ("y", "yes"): print("Cancelled."); return
    FT.stage("install libraries", FT.ensure_libs)
    steps = [("Junk files", S.scan_junk)]
    if not quick: steps.append(("Big folders", S.scan_big_folders))
    reg = FT.stage("registry", eng2.eng_registry, [])
    steps += [("Hijacks and start-ups", lambda: S.scan_persistence(reg)), ("Windows Defender threats", S.scan_defender_threats), ("Malware files (C++ scanner)", S.scan_malware_files),
              ("Task Manager hogs", S.scan_hogs), ("Ways in / ways out", S2.scan_exposure), ("Maintenance items", S2.maintenance_items)]
    for i, (name, fn) in enumerate(steps, 1):
        print("\n[%d/%d] %s..." % (i, len(steps), name))
        FT.stage(name, fn)
    for n, why in FT.STAGE_ERRORS: C.SCAN_NOTES.append("%s failed: %s" % (n, why))
    sub = "Cleanup scan &middot; %s &middot; %d findings" % (datetime.datetime.now().strftime("%d %b %Y, %H:%M"), len(C.ITEMS))
    page = W.build_page(sub)
    path = os.path.join(C.OUT, "cleanup_%s.html" % C.STAMP)
    with open(path, "w", encoding="utf-8") as f: f.write(page)
    srv, url = W.serve(page)
    print("\nScan finished: %d items. Review them in the page (nothing is changed yet):\n  %s" % (len(C.ITEMS), url))
    for n in C.SCAN_NOTES: print("  note:", n)
    if "--no-browser" not in sys.argv: print("Opening in %s" % FT.open_in_browser(url))
    print("\nKeep this window OPEN while you use the page. Press Ctrl+C or close it to stop.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: pass
    except BaseException:
        import traceback; traceback.print_exc(); print("\nSomething went wrong; details above and in Cleanup\\cleaner_log.txt")
    if "--no-browser" not in sys.argv: FT.pause_forever()
