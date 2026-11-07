# -*- coding: utf-8 -*-
"""
Find the Laptop - engines module (v2.1)
Everything here is read-only diagnostics: it reads hardware/OS state, plays a short
test tone, records a short mic sample (kept in memory only, never saved), and runs
small benchmarks. Nothing is uploaded anywhere.
"""
import os, sys, re, json, time, shutil, subprocess, tempfile, threading, datetime, importlib
import xml.etree.ElementTree as ET

IS_WIN = os.name == "nt"
BASE = os.path.dirname(os.path.abspath(__file__))
LOG = []            # every command that was run: shell, command, seconds, ok
LIBS = {}           # python libraries: status
_lock = threading.Lock()


def log(shell, cmd, secs, ok, note=""):
    with _lock:
        LOG.append({"shell": shell, "cmd": str(cmd)[:160], "secs": round(secs, 1), "ok": bool(ok), "note": note})


def sh(cmd, timeout=120, shell_name="CMD"):
    """Run a CMD / program command, log it, return stdout text."""
    t = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, shell=isinstance(cmd, str))
        raw = r.stdout or b""
        txt = raw.decode("utf-8", "replace") if b"\x00" not in raw else raw.decode("utf-16le", "replace")
        txt = txt.replace("\x00", "").strip()
        log(shell_name, cmd if isinstance(cmd, str) else " ".join(cmd), time.time() - t, r.returncode == 0)
        return txt
    except Exception as e:
        log(shell_name, cmd if isinstance(cmd, str) else " ".join(cmd), time.time() - t, False, type(e).__name__)
        return ""


# ------------------------------------------------------------------ python libraries
LIB_SPEC = [
    # (pip name, import name, what we use it for)
    ("psutil", "psutil", "CPU cores, RAM, disk, processes, network connections"),
    ("py-cpuinfo", "cpuinfo", "CPU model, cache and feature flags"),
    ("wmi", "wmi", "Windows WMI cross-check (BIOS, board, drivers)"),
    ("nvidia-ml-py", "pynvml", "NVIDIA GPU temperature / memory / load"),
    ("sounddevice", "sounddevice", "Speaker + microphone self-test"),
    ("numpy", "numpy", "Signal analysis, RAM pattern test"),
    ("pyserial", "serial.tools.list_ports", "COM / serial ports"),
    ("opencv-python-headless", "cv2", "Camera self-test (opens the camera and checks the picture)"),
    ("pycaw", "pycaw.pycaw", "Un-mute / set volume so the sound test is audible"),
    ("comtypes", "comtypes", "Windows COM bridge for pycaw"),
]


def load_libs():
    mods = {}
    for pip_name, imp, purpose in LIB_SPEC:
        entry = {"pip": pip_name, "purpose": purpose, "ok": False, "ver": "", "note": ""}
        try:
            m = importlib.import_module(imp)
            mods[imp] = m; mods[imp.split(".")[0]] = importlib.import_module(imp.split(".")[0])
            entry["ok"] = True
            try:
                from importlib.metadata import version
                entry["ver"] = version(pip_name)
            except Exception:
                entry["ver"] = str(getattr(m, "__version__", ""))
        except Exception as e:
            entry["note"] = "not installed (%s)" % type(e).__name__
        LIBS[pip_name] = entry
    return mods


# ------------------------------------------------------------------ psutil
PRIVATE = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|fe80|fc|fd)")
ODD_PATH = re.compile(r"(?i)\\temp\\|\\appdata\\local\\temp|\\downloads\\|\\users\\public\\|\\\$recycle\.bin")


def eng_psutil(mods):
    ps = mods.get("psutil")
    out = {}
    if not ps:
        return out
    t = time.time()
    try:
        out["percore"] = ps.cpu_percent(interval=1.0, percpu=True)
        f = ps.cpu_freq()
        out["freq"] = {"cur": round(f.current), "max": round(f.max)} if f else None
        vm, sw = ps.virtual_memory(), ps.swap_memory()
        out["ram"] = {"total": vm.total, "avail": vm.available, "pct": vm.percent, "swap_pct": sw.percent}
        out["boot"] = datetime.datetime.fromtimestamp(ps.boot_time()).strftime("%Y-%m-%d %H:%M")
        b = ps.sensors_battery()
        out["battery"] = {"pct": b.percent, "plugged": b.power_plugged, "secs": b.secsleft} if b else None
        try:
            tt = ps.sensors_temperatures()
            out["temps"] = {k: [round(x.current) for x in v] for k, v in tt.items()} if tt else {}
        except Exception:
            out["temps"] = {}
        odd, conns = [], []
        for p in ps.process_iter(["name", "exe", "pid"]):
            try:
                exe = p.info.get("exe") or ""
                if exe and ODD_PATH.search(exe):
                    odd.append({"name": p.info.get("name"), "exe": exe})
            except Exception:
                pass
        try:
            names = {}
            for c in ps.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr and not PRIVATE.match(c.raddr.ip):
                    try:
                        nm = names.setdefault(c.pid, ps.Process(c.pid).name())
                    except Exception:
                        nm = "pid %s" % c.pid
                    conns.append({"proc": nm, "ip": c.raddr.ip, "port": c.raddr.port})
        except Exception:
            pass
        out["odd_procs"] = odd[:15]
        out["conns"] = conns[:40]
        io = ps.disk_io_counters()
        out["disk_io"] = {"read_gb": round(io.read_bytes / 1e9, 1), "write_gb": round(io.write_bytes / 1e9, 1)} if io else None
        log("Python/psutil", "cpu, memory, processes, connections, battery", time.time() - t, True)
    except Exception as e:
        log("Python/psutil", "cpu, memory, processes", time.time() - t, False, type(e).__name__)
    return out


def eng_cpuinfo(mods):
    ci = mods.get("cpuinfo")
    if not ci:
        return {}
    t = time.time()
    try:
        i = ci.get_cpu_info()
        log("Python/py-cpuinfo", "get_cpu_info()", time.time() - t, True)
        return {"brand": i.get("brand_raw"), "l2": i.get("l2_cache_size"), "l3": i.get("l3_cache_size"),
                "bits": i.get("bits"), "avx2": "avx2" in (i.get("flags") or []), "vmx": any(x in (i.get("flags") or []) for x in ("vmx", "svm"))}
    except Exception as e:
        log("Python/py-cpuinfo", "get_cpu_info()", time.time() - t, False, type(e).__name__)
        return {}


def eng_wmi(mods):
    w = mods.get("wmi")
    if not (w and IS_WIN):
        return {}
    t = time.time()
    try:
        c = w.WMI()
        bios = c.Win32_BIOS()[0]
        bb = c.Win32_BaseBoard()[0]
        out = {"bios_ver": bios.SMBIOSBIOSVersion, "bios_serial": bios.SerialNumber, "board": "%s %s" % (bb.Manufacturer, bb.Product)}
        log("Python/wmi", "Win32_BIOS, Win32_BaseBoard", time.time() - t, True)
        return out
    except Exception as e:
        log("Python/wmi", "Win32_BIOS", time.time() - t, False, type(e).__name__)
        return {}


def eng_gpu(mods):
    nv = mods.get("pynvml")
    if not nv:
        return []
    t = time.time()
    res = []
    try:
        nv.nvmlInit()
        for i in range(nv.nvmlDeviceGetCount()):
            h = nv.nvmlDeviceGetHandleByIndex(i)
            name = nv.nvmlDeviceGetName(h)
            name = name.decode() if isinstance(name, bytes) else name
            mem = nv.nvmlDeviceGetMemoryInfo(h)
            res.append({"name": name, "temp": nv.nvmlDeviceGetTemperature(h, 0),
                        "load": nv.nvmlDeviceGetUtilizationRates(h).gpu, "vram_gb": round(mem.total / 1024 ** 3, 1)})
        nv.nvmlShutdown()
        log("Python/NVML", "NVIDIA GPU sensors", time.time() - t, True)
    except Exception as e:
        log("Python/NVML", "NVIDIA GPU sensors", time.time() - t, False, "no NVIDIA GPU" if res == [] else type(e).__name__)
    return res


def eng_serial(mods):
    lp = mods.get("serial.tools.list_ports")
    if not lp:
        return []
    t = time.time()
    try:
        r = [{"port": p.device, "desc": p.description} for p in lp.comports()]
        log("Python/pyserial", "list_ports.comports()", time.time() - t, True)
        return r
    except Exception as e:
        log("Python/pyserial", "list_ports.comports()", time.time() - t, False, type(e).__name__)
        return []


# ------------------------------------------------------------------ keyboard / input via ctypes
def eng_input():
    if not IS_WIN:
        return {}
    import ctypes
    u = ctypes.windll.user32
    t = time.time()
    seen = None
    for _ in range(4):                       # a key is "stuck" only if it is down in every sample
        down = {vk for vk in range(8, 255) if vk not in (1, 2, 4, 5, 6, 0x0D, 0x10, 0x11, 0x12) and (u.GetAsyncKeyState(vk) & 0x8000)}
        seen = down if seen is None else seen & down
        time.sleep(0.35)
    m = lambda i: u.GetSystemMetrics(i)
    out = {"kbd_type": u.GetKeyboardType(0), "kbd_fkeys": u.GetKeyboardType(2), "stuck": sorted(seen or []),
           "monitors": m(80), "screen": "%dx%d" % (m(0), m(1)), "mouse": m(19), "buttons": m(43), "wheel": m(75), "touch": m(94)}
    log("Python/ctypes", "user32 GetKeyboardType / GetAsyncKeyState / GetSystemMetrics", time.time() - t, True)
    return out


# ------------------------------------------------------------------ audio loopback test
def eng_audio(mods):
    sd, np = mods.get("sounddevice"), mods.get("numpy")
    if not (sd and np):
        return {"skipped": "sounddevice / numpy not installed"}
    import ftl_engines2 as e2
    with e2.Speakers(mods) as sp:
        out = _audio_core(mods, sd, np)
        if sp.was_muted is not None:
            out["was_muted"] = sp.was_muted; out["old_volume"] = round((sp.old_level or 0) * 100)
    return out


def _audio_core(mods, sd, np):
    t = time.time()
    out = {}
    try:
        devs = sd.query_devices()
        out["outputs"] = sum(1 for d in devs if d["max_output_channels"] > 0)
        out["inputs"] = sum(1 for d in devs if d["max_input_channels"] > 0)
        if not out["outputs"]:
            out["result"] = "no_output"; return out
        if not out["inputs"]:
            out["result"] = "no_input"; return out
        fs, dur = 44100, 1.2
        amb = sd.rec(int(0.5 * fs), samplerate=fs, channels=1, dtype="float32"); sd.wait()
        out["noise_rms"] = round(float(np.sqrt(np.mean(amb ** 2))), 5)
        tt = np.arange(int(fs * dur)) / fs
        tone = (0.5 * np.sin(2 * np.pi * 1000 * tt)).astype("float32").reshape(-1, 1)
        rec = sd.playrec(tone, samplerate=fs, channels=1, dtype="float32"); sd.wait()
        x = rec[:, 0] * np.hanning(len(rec))
        spec = np.abs(np.fft.rfft(x)); fr = np.fft.rfftfreq(len(x), 1 / fs)
        band = float(spec[(fr > 950) & (fr < 1050)].sum()); ratio = band / (float(spec.sum()) + 1e-12)
        out["tone_ratio"] = round(ratio, 3)
        out["peak_hz"] = int(fr[int(np.argmax(spec))])
        out["rec_rms"] = round(float(np.sqrt(np.mean(rec ** 2))), 5)
        out["result"] = "pass" if ratio >= 0.30 else "weak" if ratio >= 0.10 else "silent"
        log("Python/sounddevice", "play 1 kHz tone + record microphone (loopback)", time.time() - t, True)
    except Exception as e:
        out["result"] = "error"; out["error"] = type(e).__name__ + ": " + str(e)[:80]
        log("Python/sounddevice", "audio loopback", time.time() - t, False, type(e).__name__)
    return out


# ------------------------------------------------------------------ RAM pattern test + CPU benchmark
def eng_ramtest(mods, mb=128):
    np = mods.get("numpy")
    t = time.time()
    bad = 0
    try:
        if np:
            n = mb * 1024 * 1024 // 8
            a = np.empty(n, dtype=np.uint64)
            for pat in (0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 0x0, 0xFFFFFFFFFFFFFFFF):
                a.fill(np.uint64(pat)); bad += int(np.count_nonzero(a != np.uint64(pat)))
            ref = np.arange(n, dtype=np.uint64); a[:] = ref; bad += int(np.count_nonzero(a != ref))
            del a, ref
        else:
            b = bytearray(mb * 1024 * 1024)
            for pat in (0x55, 0xAA, 0x00, 0xFF):
                b[:] = bytes([pat]) * len(b)
                bad += len(b) - b.count(bytes([pat]))
        log("Python/numpy", "RAM pattern test %d MB" % mb, time.time() - t, True)
        return {"mb": mb, "errors": bad, "secs": round(time.time() - t, 1)}
    except MemoryError:
        log("Python/numpy", "RAM pattern test", time.time() - t, False, "MemoryError")
        return {"mb": mb, "errors": None, "secs": 0}


def eng_pybench():
    def work():
        t = time.perf_counter(); s = 0
        for i in range(1_500_000):
            s += (i * i) % 7
        return time.perf_counter() - t
    runs = [work() for _ in range(4)]
    log("Python", "CPU loop benchmark x4", sum(runs), True)
    return {"runs_ms": [round(r * 1000) for r in runs]}


# ------------------------------------------------------------------ C / C++ native probes
def _find_cc(lang):
    names = ["gcc", "clang", "tcc"] if lang == "c" else ["g++", "clang++"]
    for n in names:
        p = shutil.which(n)
        if p:
            return [p]
    try:                                    # alternative: the Zig compiler installed through pip ("pip install ziglang")
        import importlib.util
        if importlib.util.find_spec("ziglang"):
            return [sys.executable, "-m", "ziglang", "cc" if lang == "c" else "c++"]
    except Exception:
        pass
    return None


PROBES = [("c", "probe.c", "c"), ("cpp", "probe.cpp", "cpp"), ("cpuid", "cpuid.c", "c"), ("ramtest", "ramtest.cpp", "cpp"), ("disktest", "disktest.cpp", "cpp")]


def eng_native(fixed_roots=()):
    """Compile and run every C / C++ probe. fixed_roots: drive roots for the disk-integrity test."""
    res = {}
    tmp = tempfile.mkdtemp(prefix="ftl_")
    for key, src, lang in PROBES:
        path = os.path.join(BASE, "native", src)
        r = {"ran": False, "why": "", "data": {}}
        cc = _find_cc(lang)
        if not os.path.exists(path):
            r["why"] = "source file missing"
        elif not cc:
            r["why"] = "no %s compiler found (the launcher installs one; or run: pip install ziglang)" % ("C" if lang == "c" else "C++")
        else:
            exe = os.path.join(tmp, "probe_%s%s" % (key, ".exe" if IS_WIN else ""))
            cmd = cc + ["-O2", path, "-o", exe, "-D_WIN32_WINNT=0x0A00"]
            if lang == "cpp":
                cmd += ["-std=c++17", "-pthread"]
            if IS_WIN and lang == "c":
                cmd += ["-luser32"]
            sh(cmd, 240, "C compiler" if lang == "c" else "C++ compiler")
            if os.path.exists(exe):
                label = "C (native)" if lang == "c" else "C++ (native)"
                if key == "disktest":
                    r["data"] = {}; r["runs"] = []
                    for root in list(fixed_roots)[:3]:
                        out = sh([exe, os.path.join(root, "ftl_disktest.tmp")], 240, label)
                        d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
                        if d: d["root"] = root; r["runs"].append(d)
                    r["ran"] = bool(r["runs"]); r["why"] = "" if r["ran"] else "no drive could be tested"
                else:
                    out = sh([exe], 300, label)
                    for line in out.splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1); r["data"][k.strip()] = v.strip()
                    r["ran"] = bool(r["data"])
                    r["why"] = "" if r["ran"] else "program produced no output"
            else:
                r["why"] = "compile failed"
        res[key] = r
    shutil.rmtree(tmp, ignore_errors=True)
    return res


# ------------------------------------------------------------------ battery report (powercfg XML)
def _strip_ns(tag):
    return tag.split("}", 1)[-1]


def parse_battery_xml(text):
    out = {"batteries": [], "history": []}
    try:
        root = ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
    except Exception:
        return out
    for el in root.iter():
        tag = _strip_ns(el.tag).lower()
        if tag == "battery" and len(list(el)):
            b = {_strip_ns(c.tag): (c.text or "").strip() for c in el if not len(list(c))}
            if any(k.lower() in ("designcapacity", "fullchargecapacity") for k in b):
                out["batteries"].append(b)
        elif tag in ("historyentry", "usageentry"):
            at = {k.lower(): v for k, v in el.attrib.items()}
            full = at.get("fullchargecapacity") or at.get("fullchargedcapacity")
            if full is None:
                continue
            date = next((at[k] for k in ("localstartdate", "startdate", "timestamp", "start", "date") if k in at), "")
            try:
                out["history"].append({"date": date[:10], "full": float(full), "design": float(at.get("designcapacity", 0) or 0)})
            except ValueError:
                pass
    return out


def eng_battery_report():
    if not IS_WIN:
        return {}
    p = os.path.join(tempfile.gettempdir(), "ftl_battery.xml")
    sh(["powercfg", "/batteryreport", "/xml", "/output", p], 60, "CMD")
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            data = parse_battery_xml(fh.read())
        os.remove(p)
        return data
    except Exception:
        return {}


# ------------------------------------------------------------------ CMD tools
def eng_cmd(deep):
    out = {}
    out["ver"] = sh("ver", 10)
    out["systeminfo"] = sh("systeminfo", 90)
    out["driverquery"] = sh("driverquery /si /fo csv", 90)
    out["powercfg_a"] = sh("powercfg /a", 30)
    out["tasks_bad"] = sh("schtasks /query /fo csv /nh", 60)
    if deep:
        out["sfc"] = sh("sfc /verifyonly", 1200)
    return out


def unsigned_drivers(csv_text):
    bad = []
    for line in csv_text.splitlines()[1:]:
        cells = [c.strip('"') for c in line.split('","')]
        if len(cells) >= 4 and cells[2].strip().upper() in ("FALSE", "NO"):
            bad.append(cells[0].strip('"'))
    return bad


# ------------------------------------------------------------------ age of the laptop
def months_between(d1, d2):
    return round((d2 - d1).days / 30.44, 1)


def parse_date(s):
    for f in ("%Y-%m-%d", "%Y-%m-%d %H:%M"):
        try:
            return datetime.datetime.strptime(str(s)[:len(datetime.datetime.now().strftime(f))], f)
        except Exception:
            pass
    return None
