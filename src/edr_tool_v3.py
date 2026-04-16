#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║   MITRE ATT&CK ENTERPRISE EDR TOOL  v4.0                        ║
# ║   © 2025 Sudhya | decoding_cyberAttacks Project                 ║
# ║   All rights reserved — Proprietary & Confidential              ║
# ║   Linux + Windows | Enterprise Grade | MITRE ATT&CK Mapped      ║
# ╚══════════════════════════════════════════════════════════════════╝

# ══════════════════════════════════════════════════════════════
#  IMPORTS
# ══════════════════════════════════════════════════════════════
import os, sys, stat, grp, hashlib, json, re, time, signal
import platform, subprocess, threading, ipaddress, shutil, argparse
from datetime import datetime
from collections import deque, defaultdict
from getpass import getpass
from pathlib import Path

try:
    from tabulate import tabulate
except ImportError:
    print("[!] pip install tabulate --break-system-packages"); sys.exit(1)

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
except ImportError:
    print("[!] pip install colorama --break-system-packages"); sys.exit(1)

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False

# ══════════════════════════════════════════════════════════════
#  COLOUR ALIASES
# ══════════════════════════════════════════════════════════════
R  = Style.RESET_ALL
BL = "\033[5m"          # blink
H  = Fore.CYAN + Style.BRIGHT
W  = Fore.WHITE + Style.BRIGHT
DIM= Fore.WHITE

sys.stdout.reconfigure(encoding="utf-8")

# ══════════════════════════════════════════════════════════════
#  GLOBAL CONFIG  — edit these to customise
# ══════════════════════════════════════════════════════════════
CFG = {
    "report_dir":        "edr_reports",
    "sample_dir":        "sample_data",
    "attack_file":       "output/enterprise-attack.json",
    "lock_file":         "report_lock.json",
    "password":          "password@123",
    "lockout_sec":       60,
    "shared_group":      "sudo",          # Linux group that may READ reports
    "poll_interval":     5,               # seconds between process/net polls
    "log_buffer_size":   2000,
    "linux_log_paths": [
        "/var/log/auth.log", "/var/log/syslog",
        "/var/log/kern.log", "/var/log/messages",
        "/var/log/secure",   "/var/log/firewall.log",
        "/var/log/ids.log",  "logs/auth.log",
        "logs/firewall.log", "logs/ids.log",   # project-local logs
    ],
    "win_channels":  ["System", "Security", "Application"],
    "c2_ports":      {4444,5555,1337,31337,6666,6667,8888,9001},
    "svc_ports":     {21,22,23,3306,3389,5900,27017},
    "susp_exts":     {".exe",".bat",".ps1",".vbs",".js",".hta",
                      ".sh",".elf",".bin",".dll",".so",
                      ".encrypted",".locked",".crypt",".ransom"},
    "susp_procs":    {"mimikatz","meterpreter","nmap","netcat","nc",
                      "wce","pwdump","fgdump","lsadump","lazagne",
                      "psexec","wmiexec","crackmapexec","bloodhound"},
}

# ══════════════════════════════════════════════════════════════
#  MITRE QUICK-MAP  (keyword → TID, name, tactic)
# ══════════════════════════════════════════════════════════════
MMAP = {
    "failed password":        ("T1110","Brute Force",                    "Credential Access"),
    "authentication failure": ("T1110","Brute Force",                    "Credential Access"),
    "invalid user":           ("T1078","Valid Accounts",                  "Initial Access"),
    "sudo":                   ("T1548","Abuse Elevation Control",         "Privilege Escalation"),
    "su root":                ("T1548","Abuse Elevation Control",         "Privilege Escalation"),
    "chmod 777":              ("T1222","File Permission Modification",    "Defense Evasion"),
    "wget":                   ("T1105","Ingress Tool Transfer",           "Command & Control"),
    "curl":                   ("T1105","Ingress Tool Transfer",           "Command & Control"),
    "/bin/bash":              ("T1059","Command & Scripting Interpreter", "Execution"),
    "powershell":             ("T1059","Command & Scripting Interpreter", "Execution"),
    "cmd.exe":                ("T1059","Command & Scripting Interpreter", "Execution"),
    "mshta":                  ("T1218","System Binary Proxy Execution",   "Defense Evasion"),
    "base64":                 ("T1027","Obfuscated Files",                "Defense Evasion"),
    "mimikatz":               ("T1003","OS Credential Dumping",           "Credential Access"),
    "netcat":                 ("T1071","Application Layer Protocol",      "Command & Control"),
    "nc -":                   ("T1071","Application Layer Protocol",      "Command & Control"),
    "nmap":                   ("T1046","Network Service Discovery",       "Discovery"),
    "ransomware":             ("T1486","Data Encrypted for Impact",       "Impact"),
    "useradd":                ("T1136","Create Account",                  "Persistence"),
    "userdel":                ("T1531","Account Access Removal",          "Impact"),
    "crontab":                ("T1053","Scheduled Task/Job",              "Persistence"),
    "shadow":                 ("T1003","OS Credential Dumping",           "Credential Access"),
    ".encrypted":             ("T1486","Data Encrypted for Impact",       "Impact"),
    ".locked":                ("T1486","Data Encrypted for Impact",       "Impact"),
    "iptables -f":            ("T1562","Impair Defenses",                 "Defense Evasion"),
    "ufw disable":            ("T1562","Impair Defenses",                 "Defense Evasion"),
    "deny":                   ("T1562","Impair Defenses",                 "Defense Evasion"),
    "blocked":                ("T1562","Impair Defenses",                 "Defense Evasion"),
    "port scan":              ("T1046","Network Service Discovery",       "Discovery"),
    "syn flood":              ("T1498","Network Denial of Service",       "Impact"),
}

SUSP_KW = list(MMAP.keys()) + [
    "exploit","trojan","malware","metasploit",
    "reverse shell","bind shell","decode","obfuscat",
]

# ══════════════════════════════════════════════════════════════
#  SHARED STATE
# ══════════════════════════════════════════════════════════════
RAW_Q       = deque(maxlen=CFG["log_buffer_size"])
NORM_Q      = deque(maxlen=CFG["log_buffer_size"])
ALERT_BUF   = deque(maxlen=1000)
CORR_LIST   = []
ALERT_CNT   = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
SEEN_ALERTS = set()

RAW_LK   = threading.Lock()
NORM_LK  = threading.Lock()
ALERT_LK = threading.Lock()
CORR_LK  = threading.Lock()

_threads  = []
_observer = None
lock_state = {"locked_until": 0}
REPORT_PATH = ""   # set after dir creation


# ══════════════════════════════════════════════════════════════
#  MODULE 0 — SOURCE PROTECTION + FILE PERMISSIONS
# ══════════════════════════════════════════════════════════════

def protect_source():
    try:
        p = os.path.abspath(__file__)
        os.chmod(p, stat.S_IRWXU)   # chmod 700
        _info(f"Source protected → chmod 700  ({p})")
    except Exception as e:
        _warn(f"Source protection skipped: {e}")


def setup_report_dir() -> str:
    d = CFG["report_dir"]
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)  # 750
        gid = grp.getgrnam(CFG["shared_group"]).gr_gid
        os.chown(d, os.getuid(), gid)
        _info(f"Report dir → chmod 750  group:{CFG['shared_group']}  ({d}/)")
    except KeyError:
        _warn(f"Group '{CFG['shared_group']}' not found — dir created without group chown")
    except PermissionError:
        _warn("chown needs sudo — dir created, group ownership skipped")
    except Exception as e:
        _warn(f"Dir setup: {e}")
    path = os.path.join(d, "forensic_report.txt")
    return path


def lock_file(path: str):
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 640
    except Exception:
        pass


def print_perms(report_path: str):
    _head("📁 FILE PERMISSION SUMMARY")
    rows = [
        [os.path.abspath(__file__), "700", "Owner only (source code)"],
        [CFG["report_dir"]+"/",     "750", f"Owner + group:{CFG['shared_group']}"],
        [report_path,               "640", f"Owner rw, group:{CFG['shared_group']} r"],
    ]
    for path, perm, note in rows:
        try:
            actual = oct(stat.S_IMODE(os.stat(path).st_mode))
        except Exception:
            actual = "pending"
        mark = Fore.GREEN+"✅" if os.path.exists(path) else Fore.YELLOW+"⚠️ "
        print(f"  {mark}{R}  {Fore.CYAN}{perm}{R}  {path}  {Fore.YELLOW}({note}){R}")


# ══════════════════════════════════════════════════════════════
#  MITRE DATASET LOADER
# ══════════════════════════════════════════════════════════════

def load_mitre() -> dict:
    lookup = {}
    try:
        with open(CFG["attack_file"], "r", encoding="utf-8") as f:
            data = json.load(f)
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                tid = obj.get("external_references",[{}])[0].get("external_id","")
                if not tid:
                    continue
                lookup[tid] = {
                    "name":        obj.get("name","Unknown"),
                    "description": obj.get("description","")[:400],
                    "mitigations": _mitigations(tid),
                }
        _info(f"Loaded {len(lookup)} real MITRE ATT&CK techniques")
    except Exception as e:
        _warn(f"MITRE fallback active: {e}")
    return lookup


def _mitigations(tid: str) -> list:
    base = {
        "T1486": ["Deploy EDR/XDR solutions",
                  "Enable application allowlisting",
                  "Maintain offline immutable backups",
                  "Configure ransomware protection in AV",
                  "Monitor for mass file encryption events",
                  "Implement network segmentation"],
        "T1059": ["Constrain PowerShell to Constrained Language Mode",
                  "Enable Script Block Logging",
                  "Implement Least Privilege for scripting",
                  "Block Office apps from spawning shells",
                  "Audit command-line arguments via Sysmon",
                  "Enable ETW (Event Tracing for Windows)"],
        "T1070": ["Enable File Integrity Monitoring (FIM)",
                  "Configure log retention and forwarding",
                  "Deploy Sysmon with comprehensive ruleset",
                  "Implement tamper protection on security tools",
                  "Monitor Event ID 1102 (log clearing)",
                  "Use immutable cloud SIEM logging"],
        "T1021": ["Disable unnecessary remote services",
                  "Implement Just-In-Time admin access",
                  "Deploy Network Access Control (NAC)",
                  "Harden RDP with MFA + conditional access",
                  "Audit failed remote logon attempts",
                  "Monitor lateral movement patterns"],
        "T1110": ["Implement account lockout policies",
                  "Enable MFA on all remote access points",
                  "Monitor for repeated authentication failures",
                  "Deploy CAPTCHA on exposed login pages",
                  "Alert on >5 failed logins in 60 seconds",
                  "Use geofencing and IP reputation filtering"],
        "T1548": ["Enforce sudoers restrictions (NOPASSWD auditing)",
                  "Monitor /var/log/auth.log for sudo usage",
                  "Deploy PAM (Pluggable Auth Modules) controls",
                  "Implement privilege access management (PAM/CyberArk)",
                  "Alert on unexpected privilege escalation",
                  "Apply principle of least privilege"],
        "T1136": ["Monitor useradd/net user commands",
                  "Alert on new privileged account creation",
                  "Audit /etc/passwd and /etc/shadow changes",
                  "Implement account creation approval workflow",
                  "Use SIEM correlation for account provisioning",
                  "Review sudo group membership regularly"],
        "T1562": ["Enable firewall tamper alerting",
                  "Monitor iptables/ufw rule changes",
                  "Use immutable security tool configurations",
                  "Deploy host-based IDS (OSSEC/Wazuh)",
                  "Alert on AV/EDR service stop events",
                  "Implement defense-in-depth architecture"],
    }
    for key, mits in base.items():
        if key in tid:
            return mits
    return ["Keep systems patched and updated",
            "Deploy and maintain EDR/XDR solutions",
            "Apply Zero Trust Architecture principles",
            "Conduct regular security awareness training",
            "Perform periodic penetration testing",
            "Maintain Incident Response playbooks"]


# ══════════════════════════════════════════════════════════════
#  FILE CLASSIFIER
# ══════════════════════════════════════════════════════════════

def classify_file(fname: str, ml: dict) -> dict:
    fn = fname.lower()
    if fn.endswith((".exe",".bin")) or any(x in fn for x in ["rootkit","trojan","ransom","malware"]):
        tid, risk = "T1486", "DANGER"
    elif fn.endswith((".sh",".ps1",".bat",".vbs")) or "script" in fn:
        tid, risk = "T1059", "HIGH"
    elif fn.startswith(".") or "hidden" in fn:
        tid, risk = "T1070", "MEDIUM"
    elif any(x in fn for x in ["service","remote","ssh","rdp","vnc"]):
        tid, risk = "T1021", "MEDIUM"
    else:
        tid, risk = "N/A", "SAFE"

    if tid in ml:
        return {"tid":tid,"risk":risk,"tname":ml[tid]["name"],
                "desc":ml[tid]["description"],"mits":ml[tid]["mitigations"]}
    return {"tid":tid,"risk":risk,"tname":f"{tid} Generic",
            "desc":f"File shows characteristics of {tid}","mits":_mitigations(tid)}


def scan_directory(path: str, ml: dict) -> list:
    results = []
    if not os.path.isdir(path):
        _warn(f"scan_directory: '{path}' not found — skipping")
        return results
    for root, _, files in os.walk(path):
        for fname in files:
            fp  = os.path.join(root, fname)
            try:
                st  = os.stat(fp)
            except Exception:
                continue
            cl  = classify_file(fname, ml)
            sha = _sha256(fp)
            cvss_map = {"DANGER":9.8,"HIGH":8.1,"MEDIUM":6.5,"SAFE":0.0}
            score_map = {"DANGER":10,"HIGH":8,"MEDIUM":5,"SAFE":1}
            tactic_map = {"DANGER":"Impact","HIGH":"Execution",
                          "MEDIUM":"Defense Evasion","SAFE":"Reconnaissance"}
            results.append({
                "file":         fp,
                "size":         st.st_size,
                "modified":     datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "sha256":       sha,
                "risk":         cl["risk"],
                "risk_score":   score_map[cl["risk"]],
                "cvss":         cvss_map[cl["risk"]],
                "tactic":       tactic_map[cl["risk"]],
                "tid":          cl["tid"],
                "tname":        cl["tname"],
                "desc":         cl["desc"],
                "mits":         cl["mits"],
            })
    results.sort(key=lambda x: {"DANGER":0,"HIGH":1,"MEDIUM":2,"SAFE":3}[x["risk"]])
    return results


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except Exception:
        return "unreadable"
    return h.hexdigest()


# ══════════════════════════════════════════════════════════════
#  MODULE 1 — LOG AGGREGATION
#  Reads ALL sources → unified RAW_Q deque
# ══════════════════════════════════════════════════════════════

def _push_raw(source: str, raw: str, stype: str):
    with RAW_LK:
        RAW_Q.append({"ts": datetime.now().isoformat(timespec="seconds"),
                      "source": source, "stype": stype, "raw": raw})


def _tail_file(path: str):
    """Tail a log file (Linux). Reads project-local logs too."""
    if not os.path.exists(path):
        return
    _info(f"[Aggregator] Tailing → {path}")
    try:
        proc = subprocess.Popen(
            ["tail","-F","-n","50",path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            _push_raw(os.path.basename(path), line.strip(), "log")
    except Exception:
        pass


def _win_channel(ch: str):
    try:
        import win32evtlog, win32con
    except ImportError:
        _warn("[WinEvt] pip install pywin32"); return
    _info(f"[Aggregator] WinEvt → {ch}")
    h = win32evtlog.OpenEventLog(None, ch)
    fl = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ
    win32evtlog.ReadEventLog(h, fl, 0)
    while True:
        try:
            evs = win32evtlog.ReadEventLog(h, fl, 0)
            for ev in (evs or []):
                msg = str(ev.StringInserts) if ev.StringInserts else ""
                _push_raw(f"WinEvt/{ch}",
                          f"EID={ev.EventID} Src={ev.SourceName} {msg}", "log")
        except Exception:
            pass
        time.sleep(2)


def _proc_poller():
    if not PSUTIL_OK: return
    seen = set()
    _info("[Aggregator] Process poller active")
    while True:
        try:
            for p in psutil.process_iter(["pid","name","cmdline","username"]):
                try:
                    pid = p.info["pid"]
                    if pid in seen: continue
                    seen.add(pid)
                    nm  = (p.info["name"] or "").lower()
                    cmd = " ".join(p.info.get("cmdline") or [])
                    usr = p.info.get("username") or "unknown"
                    _push_raw("proc_monitor",
                              f"pid={pid} name={nm} user={usr} cmd={cmd[:150]}", "process")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        time.sleep(CFG["poll_interval"])


def _net_poller():
    if not PSUTIL_OK: return
    seen = set()
    _info("[Aggregator] Network monitor active")
    while True:
        try:
            for c in psutil.net_connections(kind="tcp"):
                if c.status != "ESTABLISHED" or not c.raddr: continue
                key = (c.laddr.port, c.raddr.ip, c.raddr.port)
                if key in seen: continue
                seen.add(key)
                _push_raw("net_monitor",
                          f"local={c.laddr.ip}:{c.laddr.port} "
                          f"remote={c.raddr.ip}:{c.raddr.port}", "network")
        except Exception:
            pass
        time.sleep(CFG["poll_interval"])


class _FSHandler(FileSystemEventHandler):
    def _p(self, et, path):
        _push_raw("filesystem", f"event={et} path={path}", "filesystem")
    def on_created(self,  e): self._p("CREATE", e.src_path)
    def on_modified(self, e): self._p("MODIFY",  e.src_path)
    def on_deleted(self,  e): self._p("DELETE", e.src_path)
    def on_moved(self,    e): self._p("MOVE",   e.dest_path)


def start_aggregation():
    global _observer
    os_ = platform.system()
    _head(f"📥 MODULE 1 — LOG AGGREGATION  [{os_}]")

    if os_ == "Linux":
        for p in CFG["linux_log_paths"]:
            t = threading.Thread(target=_tail_file, args=(p,), daemon=True)
            t.start(); _threads.append(t)
    elif os_ == "Windows":
        for ch in CFG["win_channels"]:
            t = threading.Thread(target=_win_channel, args=(ch,), daemon=True)
            t.start(); _threads.append(t)
    else:
        _warn(f"Unsupported OS: {os_}"); sys.exit(1)

    for fn in (_proc_poller, _net_poller):
        t = threading.Thread(target=fn, daemon=True)
        t.start(); _threads.append(t)

    if WATCHDOG_OK:
        dirs = ([os.path.expanduser("~"),"/tmp","/var/tmp",
                 os.path.abspath(CFG["sample_dir"]),
                 os.path.abspath("logs")]
                if os_ == "Linux"
                else [os.path.expanduser("~"),
                      os.environ.get("TEMP","C:\\Temp"), "C:\\Users\\Public"])
        handler = _FSHandler(); _observer = Observer()
        for d in dirs:
            if os.path.isdir(d):
                _observer.schedule(handler, d, recursive=True)
                _info(f"[Watchdog] Monitoring → {d}")
        _observer.start()

    _ok("Aggregation running — all sources feeding into unified queue\n")


# ══════════════════════════════════════════════════════════════
#  MODULE 2 — LOG NORMALISATION  (CEF-inspired)
#  Converts every raw event → standard NormEvent dict
# ══════════════════════════════════════════════════════════════

def _sev(raw: str, stype: str) -> str:
    low = raw.lower()
    if any(w in low for w in ["ransomware","mimikatz","exploit","metasploit",
                               "trojan",".encrypted",".locked","syn flood"]):
        return "CRITICAL"
    if any(w in low for w in ["sudo","su root","powershell","base64",
                               "reverse shell","useradd","crontab","shadow",
                               "ufw disable","iptables -f"]):
        return "HIGH"
    for kw in SUSP_KW:
        if kw in low:
            return "MEDIUM"
    if stype == "process" and any(s in low for s in CFG["susp_procs"]):
        return "HIGH"
    if stype == "network":
        for p in CFG["c2_ports"]:
            if str(p) in low:
                return "CRITICAL"
    return "LOW"


def _mhit(raw: str):
    low = raw.lower()
    for kw, info in MMAP.items():
        if kw in low:
            return info
    return None


def _xip(text: str):
    m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
    return m.group(1) if m else None


def normalise(raw: dict) -> dict:
    r   = raw.get("raw","")
    st  = raw.get("stype","log")
    sev = _sev(r, st)
    mh  = _mhit(r)
    return {
        "event_id":    f"EVT-{abs(hash(r+raw['ts']))%999999:06d}",
        "timestamp":   raw.get("ts", datetime.now().isoformat()),
        "severity":    sev,
        "source":      raw.get("source","unknown"),
        "stype":       st,
        "src_ip":      _xip(r),
        "message":     r[:200],
        "mitre_id":    mh[0] if mh else "N/A",
        "mitre_name":  mh[1] if mh else "N/A",
        "tactic":      mh[2] if mh else "N/A",
        "cef":         f"CEF:0|EDR-Tool|MitreEDR|4.0|{sev}|{r[:60]}|",
    }


def run_normalisation() -> int:
    with RAW_LK:
        batch = list(RAW_Q)
    count = 0
    for r in batch:
        n = normalise(r)
        with NORM_LK:
            NORM_Q.append(n)
        count += 1
    _save_json(os.path.join(CFG["report_dir"],"normalised_events.json"),
               list(NORM_Q))
    return count


# ══════════════════════════════════════════════════════════════
#  MODULE 3 — EVENT CORRELATION  (7 rules, time-windowed)
# ══════════════════════════════════════════════════════════════

def _win(secs=60):
    cut = time.time() - secs
    with NORM_LK:
        evs = list(NORM_Q)
    return [e for e in evs
            if datetime.fromisoformat(e["timestamp"]).timestamp() >= cut]


# Rule implementations
def _r_brute(evs):
    w = _win(60)
    by = defaultdict(int)
    for e in w:
        low = e["raw"] if "raw" in e else e["message"]
        if "failed password" in low.lower() or "authentication failure" in low.lower():
            by[e.get("src_ip","unknown")] += 1
    hits = {k:v for k,v in by.items() if v >= 5}
    return (True, f"IPs+counts: {dict(list(hits.items())[:3])}") if hits else (False,"")


def _r_priv(evs):
    w = _win(120)
    msgs = [e["message"].lower() for e in w]
    sudo = any("sudo" in m or "su root" in m for m in msgs)
    sens = any(x in m for m in msgs for x in ["/etc/shadow","/etc/passwd","sam","ntds"])
    if sudo and sens:
        return True,"sudo/su + sensitive file access in window"
    return False,""


def _r_ransom(evs):
    w = _win(120)
    enc = sum(1 for e in w if any(x in e["message"].lower()
              for x in [".encrypted",".locked",".crypt",".ransom"]))
    mod = sum(1 for e in w if "modify" in e["message"].lower() or "create" in e["message"].lower())
    if enc >= 1 and mod >= 5:
        return True,f"{enc} encrypted-ext events + {mod} file modifications"
    return False,""


def _r_c2(evs):
    w = _win(300)
    hits = []
    for e in w:
        for p in CFG["c2_ports"]:
            if str(p) in e["message"]:
                hits.append(f"{e.get('src_ip','?')}:{p}")
    if hits:
        return True,f"C2 ports: {list(set(hits))[:5]}"
    return False,""


def _r_persist(evs):
    w = _win(300)
    msgs = [e["message"].lower() for e in w]
    cron = any("crontab" in m for m in msgs)
    uadd = any("useradd" in m for m in msgs)
    if cron or uadd:
        d = []
        if cron: d.append("crontab modification")
        if uadd: d.append("new user created")
        return True," + ".join(d)
    return False,""


def _r_script(evs):
    w = _win(30)
    exts = [".sh",".ps1",".bat",".vbs",".hta"]
    hits = [e for e in w if "create" in e["message"].lower()
            and any(x in e["message"].lower() for x in exts)]
    if hits:
        return True,f"Script created: {hits[0]['message'][:80]}"
    return False,""


def _r_cred(evs):
    w = _win(120)
    sens = ["/etc/shadow","/etc/passwd","sam","ntds.dit","lsass"]
    hits = [e for e in w if any(s in e["message"].lower() for s in sens)]
    if hits:
        return True,f"Sensitive access: {hits[0]['message'][:80]}"
    return False,""


def _r_fw(evs):
    """Firewall / IDS log correlation — reads your project logs/"""
    w = _win(300)
    deny_cnt = sum(1 for e in w
                   if e.get("source","") in ("firewall.log","ids.log")
                   and ("deny" in e["message"].lower() or "block" in e["message"].lower()))
    if deny_cnt >= 10:
        return True,f"{deny_cnt} firewall DENY/BLOCK events in 5 min"
    return False,""


CORR_RULES = [
    {"id":"COR-001","name":"Brute Force Attack",
     "desc":"5+ auth failures in 60s","sev":"CRITICAL","tid":"T1110","tactic":"Credential Access","fn":_r_brute},
    {"id":"COR-002","name":"Privilege Escalation Sequence",
     "desc":"sudo + sensitive file access","sev":"HIGH","tid":"T1548","tactic":"Privilege Escalation","fn":_r_priv},
    {"id":"COR-003","name":"Ransomware Pattern",
     "desc":"Mass modify + .encrypted extension","sev":"CRITICAL","tid":"T1486","tactic":"Impact","fn":_r_ransom},
    {"id":"COR-004","name":"C2 Beacon Detected",
     "desc":"Outbound to C2 port","sev":"CRITICAL","tid":"T1071","tactic":"Command & Control","fn":_r_c2},
    {"id":"COR-005","name":"Persistence Mechanism",
     "desc":"Crontab edit or useradd","sev":"HIGH","tid":"T1053","tactic":"Persistence","fn":_r_persist},
    {"id":"COR-006","name":"Suspicious Script Execution",
     "desc":"Script file created < 30s","sev":"HIGH","tid":"T1059","tactic":"Execution","fn":_r_script},
    {"id":"COR-007","name":"Credential Harvesting",
     "desc":"/etc/shadow or SAM access","sev":"CRITICAL","tid":"T1003","tactic":"Credential Access","fn":_r_cred},
    {"id":"COR-008","name":"Firewall / IDS Flood",
     "desc":"10+ deny events in 5 min","sev":"HIGH","tid":"T1562","tactic":"Defense Evasion","fn":_r_fw},
]


def run_correlation() -> list:
    with NORM_LK:
        evs = list(NORM_Q)
    fired = []
    for rule in CORR_RULES:
        try:
            ok, detail = rule["fn"](evs)
            if ok:
                a = {"alert_id":   f"ALT-{abs(hash(rule['id']+detail))%99999:05d}",
                     "ts":         datetime.now().isoformat(timespec="seconds"),
                     "rule_id":    rule["id"],
                     "rule_name":  rule["name"],
                     "desc":       rule["desc"],
                     "severity":   rule["sev"],
                     "tid":        rule["tid"],
                     "tactic":     rule["tactic"],
                     "detail":     detail}
                fired.append(a)
                _print_corr(a)
        except Exception:
            pass
    with CORR_LK:
        CORR_LIST.extend(fired)
    _save_json(os.path.join(CFG["report_dir"],"correlated_alerts.json"), CORR_LIST)
    return fired


def _print_corr(a):
    col = Fore.RED+Style.BRIGHT if a["severity"]=="CRITICAL" else Fore.LIGHTRED_EX
    print(f"  {Fore.WHITE}{a['ts']}{R} {Fore.MAGENTA}[CORR]{R} "
          f"{col}[{a['severity']}]{R} {Fore.CYAN}{a['rule_id']}{R} "
          f"{a['rule_name']} — {a['detail'][:70]}")


# ══════════════════════════════════════════════════════════════
#  MODULE 4 — ALERT ENGINE  (dedup + colour output)
# ══════════════════════════════════════════════════════════════

def push_alert(source: str, sev: str, msg: str, mitre=None):
    key = f"{source}|{msg[:40]}"
    if key in SEEN_ALERTS:
        return
    SEEN_ALERTS.add(key)
    ts  = datetime.now().strftime("%H:%M:%S")
    col = {"CRITICAL":Fore.RED+Style.BRIGHT,"HIGH":Fore.LIGHTRED_EX,
           "MEDIUM":Fore.YELLOW,"LOW":Fore.GREEN}.get(sev, Fore.WHITE)
    tag = f" {Fore.CYAN}[{mitre[0]}·{mitre[2]}]{R}" if mitre else ""
    print(f"  {Fore.WHITE}{ts}{R} {Fore.MAGENTA}[{source}]{R} "
          f"{col}[{sev}]{R}{tag} {msg[:100]}")
    with ALERT_LK:
        ALERT_CNT[sev] = ALERT_CNT.get(sev,0) + 1
        ALERT_BUF.append({"ts":ts,"source":source,"sev":sev,
                          "msg":msg,"mitre":list(mitre) if mitre else None})


def _alert_worker():
    done = set()
    while True:
        with NORM_LK:
            evs = list(NORM_Q)
        for e in evs:
            eid = e.get("event_id")
            if eid in done: continue
            done.add(eid)
            if e["severity"] in ("CRITICAL","HIGH","MEDIUM"):
                m = (e["mitre_id"],e["mitre_name"],e["tactic"]) if e["mitre_id"]!="N/A" else None
                push_alert(e["source"], e["severity"], e["message"], m)
        time.sleep(3)


def start_alert_engine():
    _head("🚨 MODULE 4 — ALERT ENGINE")
    t = threading.Thread(target=_alert_worker, daemon=True)
    t.start(); _threads.append(t)
    _ok("Alert engine running — deduplicating + emitting real-time alerts\n")


def show_alert_summary():
    with ALERT_LK:
        cnt = dict(ALERT_CNT); buf = list(ALERT_BUF)
    _head("🚨 ALERT SUMMARY")
    print(f"  {Fore.RED+Style.BRIGHT}CRITICAL:{cnt.get('CRITICAL',0)}{R}  "
          f"{Fore.LIGHTRED_EX}HIGH:{cnt.get('HIGH',0)}{R}  "
          f"{Fore.YELLOW}MEDIUM:{cnt.get('MEDIUM',0)}{R}  "
          f"{Fore.GREEN}LOW:{cnt.get('LOW',0)}{R}  "
          f"(unique: {sum(cnt.values())})")
    top = [a for a in buf if a["sev"] in ("CRITICAL","HIGH")][-10:]
    if top:
        rows = [[a["ts"],a["source"],a["sev"],
                 a["mitre"][0] if a["mitre"] else "N/A",
                 a["msg"][:50]] for a in top]
        print(tabulate(rows, headers=["Time","Source","Severity","MITRE","Message"],
                       tablefmt="fancy_grid"))
    else:
        print(f"  {Fore.CYAN}No HIGH/CRITICAL alerts yet."
              f" Try: sudo python3 main.py{R}")


# ══════════════════════════════════════════════════════════════
#  MODULE 5 — UNIFIED FORENSIC REPORT  (5 sections)
# ══════════════════════════════════════════════════════════════

def write_report(scan: list, path: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with NORM_LK:  ne = list(NORM_Q)
    with CORR_LK:  ca = list(CORR_LIST)
    with ALERT_LK: ac = dict(ALERT_CNT); ab = list(ALERT_BUF)

    with open(path, "a", encoding="utf-8") as f:
        # Header
        f.write("\n\n" + "="*80 + "\n")
        f.write("  MITRE ATT&CK ENTERPRISE EDR FORENSIC REPORT  v4.0\n")
        f.write(f"  Scan Time  : {ts}\n")
        f.write(f"  Platform   : {platform.system()} {platform.release()}\n")
        f.write(f"  Hostname   : {platform.node()}\n")
        f.write(f"  Report     : {path}\n")
        f.write(f"  Permissions: chmod 640 (owner rw, group:{CFG['shared_group']} r)\n")
        f.write("="*80 + "\n\n")

        # S1: File scan
        f.write("[ SECTION 1 ] FILE SCAN — EXECUTIVE SUMMARY\n")
        f.write("="*80 + "\n\n")
        rows = []
        for i in scan:
            em = "DANGER" if i["risk"]=="DANGER" else "HIGH" if i["risk"]=="HIGH" \
                 else "MEDIUM" if i["risk"]=="MEDIUM" else "SAFE"
            rows.append([em, i["file"][-50:], i["risk"], f"{i['cvss']:.1f}", i["tid"]])
        f.write(tabulate(rows, headers=["","File","Risk","CVSS","MITRE"],
                         tablefmt="fancy_grid") + "\n\n")

        # S2: Detailed cases
        f.write("[ SECTION 2 ] DETAILED FORENSIC FILE ANALYSIS\n")
        f.write("="*80 + "\n\n")
        for idx, i in enumerate(scan, 1):
            f.write(f"CASE {idx}: {i['file']}\n")
            f.write("━"*80 + "\n")
            f.write(f"  Risk Level      : {i['risk']} ({i['risk_score']}/10)\n")
            f.write(f"  CVSS Score      : {i['cvss']:.1f}/10\n")
            f.write(f"  MITRE Technique : {i['tid']} — {i['tname']}\n")
            f.write(f"  Tactic          : {i['tactic']}\n")
            f.write(f"  File Size       : {i['size']:,} bytes\n")
            f.write(f"  Last Modified   : {i['modified']}\n")
            f.write(f"  SHA-256         : {i['sha256']}\n\n")
            f.write("  THREAT DESCRIPTION\n")
            f.write(f"  {i['desc']}\n\n")
            f.write("  MITRE-RECOMMENDED MITIGATIONS\n")
            f.write("  " + "─"*50 + "\n")
            for j, s in enumerate(i["mits"], 1):
                f.write(f"  {j:2d}. {s}\n")
            f.write("\n" + "━"*80 + "\n\n")

        # S3: Normalised events
        f.write("[ SECTION 3 ] NORMALISED EVENT LOG  (CEF format)\n")
        f.write("="*80 + "\n\n")
        non_low = [e for e in ne if e["severity"] != "LOW"]
        f.write(f"  Total events     : {len(ne)}\n")
        f.write(f"  Non-LOW events   : {len(non_low)}\n\n")
        for e in non_low[-100:]:
            f.write(f"  [{e['timestamp']}] [{e['severity']:8s}] "
                    f"[{e['source']:20s}] MITRE:{e['mitre_id']:8s} {e['tactic']}\n"
                    f"  → {e['message'][:100]}\n\n")
        if not non_low:
            f.write("  No suspicious events. Run with sudo for full log access.\n\n")

        # S4: Correlation
        f.write("[ SECTION 4 ] CORRELATION — ATTACK CHAIN ANALYSIS\n")
        f.write("="*80 + "\n\n")
        if ca:
            for a in ca:
                f.write(f"  [{a['severity']}] {a['rule_id']} — {a['rule_name']}\n")
                f.write(f"     MITRE  : {a['tid']} | Tactic: {a['tactic']}\n")
                f.write(f"     Detail : {a['detail']}\n")
                f.write(f"     Desc   : {a['desc']}\n\n")
        else:
            f.write("  No correlation rules triggered this session.\n\n")

        # S5: Alert summary
        f.write("[ SECTION 5 ] ALERT ENGINE SUMMARY\n")
        f.write("="*80 + "\n\n")
        f.write(f"  CRITICAL : {ac.get('CRITICAL',0)}\n")
        f.write(f"  HIGH     : {ac.get('HIGH',0)}\n")
        f.write(f"  MEDIUM   : {ac.get('MEDIUM',0)}\n")
        f.write(f"  LOW      : {ac.get('LOW',0)}\n\n")
        top = [a for a in ab if a["sev"] in ("CRITICAL","HIGH")][-30:]
        for a in top:
            m = a["mitre"][0] if a["mitre"] else "N/A"
            f.write(f"  [{a['ts']}] [{a['sev']}] [{a['source']}] "
                    f"{m} — {a['msg'][:80]}\n")

        f.write("\n" + "="*80 + "\n  END OF REPORT\n" + "="*80 + "\n")

    lock_file(path)
    _ok(f"Report saved → {path}")


# ══════════════════════════════════════════════════════════════
#  TERMINAL SCAN TABLE
# ══════════════════════════════════════════════════════════════

def display_scan_table(data: list):
    _head("🛡️  MITRE ATT&CK SCAN RESULTS")
    rows = []
    for i in data:
        if i["risk"] == "DANGER":
            rc = f"{BL}{Fore.RED}{Style.BRIGHT}🚨 DANGER{R}"
        elif i["risk"] == "HIGH":
            rc = f"{Fore.LIGHTRED_EX}⚠️  HIGH{R}"
        elif i["risk"] == "MEDIUM":
            rc = f"{Fore.YELLOW}🟡 MEDIUM{R}"
        else:
            rc = f"{Fore.GREEN}✅ SAFE{R}"
        sf = i["file"][-42:] if len(i["file"])>42 else i["file"]
        rows.append([sf, rc, f"{i['cvss']:.1f}", i["tid"]])
    print(tabulate(rows, headers=["File","Risk","CVSS","MITRE"],
                   tablefmt="fancy_grid", stralign="left", numalign="center"))


# ══════════════════════════════════════════════════════════════
#  LOCK + SIGNAL
# ══════════════════════════════════════════════════════════════

def _load_lock():
    global lock_state
    try:
        if os.path.exists(CFG["lock_file"]):
            with open(CFG["lock_file"]) as f:
                lock_state.update(json.load(f))
    except Exception:
        pass


def _save_lock():
    try:
        with open(CFG["lock_file"],"w") as f:
            json.dump(lock_state, f)
    except Exception:
        pass


def _locked():
    return time.time() < lock_state["locked_until"]


def _cleanup(sig, frame):
    print(f"\n{Fore.YELLOW}Shutting down...{R}")
    if _observer:
        _observer.stop(); _observer.join()
    _save_lock()
    sys.exit(0)


signal.signal(signal.SIGINT, _cleanup)


# ══════════════════════════════════════════════════════════════
#  SECURE REPORT VIEWER
# ══════════════════════════════════════════════════════════════

def open_report(path: str):
    _load_lock()
    if _locked():
        rem = int(lock_state["locked_until"] - time.time())
        print(f"\n{Fore.RED+Style.BRIGHT}🔒 LOCKED — {rem}s remaining{R}")
        while _locked():
            try:
                r = int(lock_state["locked_until"]-time.time())
                print(f"  ⏰ {r}s...  ", end="\r"); time.sleep(1)
            except KeyboardInterrupt:
                _save_lock(); return
        print(f"\n{Fore.GREEN}✅ Unlocked.{R}")

    if input("\nType 'open' to view report or Enter to exit: ").strip().lower() != "open":
        return

    for attempt in range(3):
        try:
            pw = getpass("Password: ")
        except KeyboardInterrupt:
            return
        if pw == CFG["password"]:
            print(f"\n{Fore.GREEN}✅ Access Granted!{R}\n")
            try:
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        t = line.strip()
                        if any(x in t for x in ["SECTION","FORENSIC REPORT","END OF REPORT"]):
                            print(Fore.CYAN+Style.BRIGHT+line+R, end="")
                        elif t.startswith("CASE "):
                            print(Fore.CYAN+Style.BRIGHT+line+R, end="")
                        elif "THREAT DESCRIPTION" in t:
                            print(Fore.LIGHTMAGENTA_EX+Style.BRIGHT+line+R, end="")
                        elif "MITIGATIONS" in t:
                            print(Fore.LIGHTMAGENTA_EX+Style.BRIGHT+line+R, end="")
                        elif re.match(r"^\s+\d+\.", t):
                            print(Fore.LIGHTGREEN_EX+line+R, end="")
                        elif ":" in line and not line.startswith("  "):
                            k,v = line.split(":",1)
                            print(f"{Fore.LIGHTYELLOW_EX+Style.BRIGHT}{k.strip()}{R}:{v}",end="")
                        else:
                            print(line, end="")
            except FileNotFoundError:
                print(f"{Fore.RED}❌ Report not found: {path}{R}")
            lock_state["locked_until"] = 0; _save_lock(); return
        else:
            left = 2 - attempt
            print(f"{Fore.RED}❌ Wrong password. {left} attempt(s) left.{R}")

    lock_state["locked_until"] = time.time() + CFG["lockout_sec"]
    _save_lock()
    print(f"\n{Fore.RED+Style.BRIGHT}🔒 Locked for {CFG['lockout_sec']}s.{R}")
    while _locked():
        try:
            r = int(lock_state["locked_until"]-time.time())
            print(f"  ⏰ {r}s...  ", end="\r"); time.sleep(1)
        except KeyboardInterrupt:
            return
    print(f"\n{Fore.GREEN}✅ Unlocked. Run again.{R}")


# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════

def _head(msg):  print(f"\n{Fore.CYAN+Style.BRIGHT}{msg}{R}")
def _info(msg):  print(f"  {Fore.CYAN}{msg}{R}")
def _ok(msg):    print(f"  {Fore.GREEN}✅ {msg}{R}")
def _warn(msg):  print(f"  {Fore.YELLOW}⚠️  {msg}{R}")

def _save_json(path: str, data):
    try:
        with open(path,"w",encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        lock_file(path)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════

BANNER = f"""
{Fore.CYAN+Style.BRIGHT}
  ███████╗██████╗ ██████╗     ████████╗ ██████╗  ██████╗ ██╗
  ██╔════╝██╔══██╗██╔══██╗       ██╔══╝██╔═══██╗██╔═══██╗██║
  █████╗  ██║  ██║██████╔╝       ██║   ██║   ██║██║   ██║██║
  ██╔══╝  ██║  ██║██╔══██╗       ██║   ██║   ██║██║   ██║██║
  ███████╗██████╔╝██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
  ╚══════╝╚═════╝ ╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{R}{Fore.WHITE}  MITRE ATT&CK Enterprise EDR Tool  v4.0
  © 2025 Sudhya | decoding_cyberAttacks
  Linux + Windows | 835 Techniques | Real-time Correlation{R}
"""


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

def main():
    # CLI arguments
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Enterprise EDR Tool v4.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE EXAMPLES:
  sudo python3 main.py                        # full scan (recommended)
  sudo python3 main.py --scan-dir /var/www    # scan custom directory
  sudo python3 main.py --skip-viewer          # no password prompt at end
  sudo python3 main.py --monitor-only         # live monitor only, no file scan
  python3 main.py --help
        """
    )
    parser.add_argument("--scan-dir",     default=CFG["sample_dir"],
                        help="Directory to scan (default: sample_data)")
    parser.add_argument("--skip-viewer",  action="store_true",
                        help="Skip the password-protected report viewer")
    parser.add_argument("--monitor-only", action="store_true",
                        help="Run live monitors only, no file scan")
    parser.add_argument("--duration",     type=int, default=0,
                        help="Auto-exit after N seconds (0 = wait for Ctrl+C)")
    args = parser.parse_args()

    # ── Detect OS ─────────────────────────────────────────────
    os_ = platform.system()
    if os_ not in ("Linux","Windows"):
        print(f"{Fore.RED}[!] Unsupported OS: {os_}. Linux/Windows only.{R}")
        sys.exit(1)

    _load_lock()
    print(BANNER)
    print(f"  {Fore.CYAN}Platform  : {os_} {platform.release()}{R}")
    print(f"  {Fore.CYAN}Hostname  : {platform.node()}{R}")
    print(f"  {Fore.CYAN}Scan dir  : {args.scan_dir}{R}")
    print(f"  {Fore.CYAN}Run as    : {os.environ.get('USER','unknown')}{R}\n")

    # ── Step 0: Permissions ───────────────────────────────────
    _head("🔐 STEP 0 — SOURCE + FILE PROTECTION")
    protect_source()
    global REPORT_PATH
    REPORT_PATH = setup_report_dir()
    print_perms(REPORT_PATH)

    # ── Step 1: MITRE ─────────────────────────────────────────
    _head("🧠 STEP 1 — LOADING MITRE ATT&CK DATASET")
    ml = load_mitre()

    # ── Step 2: Aggregation ───────────────────────────────────
    start_aggregation()

    # ── Step 3: Alert engine ──────────────────────────────────
    start_alert_engine()

    # ── Step 4: File scan ─────────────────────────────────────
    if not args.monitor_only:
        _head(f"📂 STEP 4 — SCANNING  {args.scan_dir}/")
        scan = scan_directory(args.scan_dir, ml)
        if scan:
            display_scan_table(scan)
        else:
            _warn(f"No files found in '{args.scan_dir}'")
            scan = []
    else:
        scan = []

    # ── Step 5: Wait / auto-exit ──────────────────────────────
    if args.duration > 0:
        _info(f"Monitoring for {args.duration}s then auto-reporting...")
        time.sleep(args.duration)
    else:
        _info("Live monitors running. Press Ctrl+C at any time to generate report.")
        try:
            while True:
                time.sleep(10)
                # mini stats every 60s
        except (KeyboardInterrupt, SystemExit):
            print()

    # ── Step 6: Normalisation ─────────────────────────────────
    _head("📐 STEP 5 — NORMALISATION")
    n = run_normalisation()
    _ok(f"{n} events normalised → CEF format → "
        f"{CFG['report_dir']}/normalised_events.json")

    # ── Step 7: Correlation ───────────────────────────────────
    _head("🔗 STEP 6 — CORRELATION & ANALYSIS")
    fired = run_correlation()
    if fired:
        print(f"  {Fore.RED}⚡ {len(fired)} correlation rule(s) triggered!{R}")
    else:
        _ok("No attack chains detected in this session")

    # ── Step 8: Alert summary ─────────────────────────────────
    show_alert_summary()

    # ── Step 9: Write report ──────────────────────────────────
    _head("📄 STEP 7 — WRITING FORENSIC REPORT")
    write_report(scan, REPORT_PATH)
    print_perms(REPORT_PATH)

    # ── Step 10: Secure viewer ────────────────────────────────
    if not args.skip_viewer:
        open_report(REPORT_PATH)

    # ── Cleanup ───────────────────────────────────────────────
    if _observer:
        _observer.stop(); _observer.join()
    _save_lock()
    print(f"\n{Fore.GREEN}✅ EDR session complete.{R}\n")


if __name__ == "__main__":
    main()
