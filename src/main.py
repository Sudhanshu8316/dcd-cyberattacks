# ============================ SOURCE CODE PROTECTION ============================
# This source code is proprietary and confidential.
# Unauthorized copying, distribution, or modification is strictly prohibited.

import os
import sys
import stat
import grp
import pwd
import hashlib
import json
import re
import time
import signal
import platform
import subprocess
import threading
import ipaddress
from datetime import datetime
from collections import deque, defaultdict
from getpass import getpass
from tabulate import tabulate
from colorama import Fore, Style, init

# ── Optional imports ──────────────────────────────────────────
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False
    print("[!] pip install psutil --break-system-packages")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False
    print("[!] pip install watchdog --break-system-packages")

# ── Encoding & colours ───────────────────────────────────────
sys.stdout.reconfigure(encoding='utf-8')
init(autoreset=True)

BLINK  = "\033[5m"
RESET  = Style.RESET_ALL
H      = Fore.CYAN + Style.BRIGHT           # heading
STEP   = Fore.LIGHTGREEN_EX
SEC    = Fore.CYAN + Style.BRIGHT
FB     = Fore.CYAN + Style.BRIGHT
FL     = Fore.LIGHTYELLOW_EX + Style.BRIGHT
EXP    = Fore.LIGHTMAGENTA_EX + Style.BRIGHT
MIT    = Fore.LIGHTMAGENTA_EX + Style.BRIGHT
WARN   = Fore.LIGHTRED_EX + Style.BRIGHT

# ── File paths ────────────────────────────────────────────────
REPORT_FILE      = "forensic_report.txt"
LOCK_FILE        = "report_lock.json"
NORM_LOG_FILE    = "normalised_events.json"
CORR_LOG_FILE    = "correlated_alerts.json"
ATTACK_FILE      = "output/enterprise-attack.json"
PASSWORD         = "password@123"
LOCKOUT_DURATION = 60

# ── Shared folder settings ────────────────────────────────────
# Change SHARED_GROUP to any existing Linux group (e.g. "sudo", "analysts")
SHARED_GROUP     = "sudo"
REPORT_DIR       = "edr_reports"

lock_state = {"locked_until": 0}


# ══════════════════════════════════════════════════════════════
#  MODULE 0 — SOURCE CODE SELF-PROTECTION
# ══════════════════════════════════════════════════════════════

def protect_source_code():
    """
    Locks down THIS script file so only the owner can read it.
    Removes read/write/execute for group and others.
    Call once at startup.
    """
    try:
        script_path = os.path.abspath(__file__)
        # chmod 700: owner rwx, group ---, others ---
        os.chmod(script_path, stat.S_IRWXU)
        print(f"  {Fore.GREEN}[+] Source protected: chmod 700 → {script_path}{RESET}")
    except Exception as e:
        print(f"  {Fore.YELLOW}[!] Could not protect source: {e}{RESET}")


def setup_report_directory():
    """
    Creates a shared report directory with controlled group permissions.
    Only owner + SHARED_GROUP members can read reports.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)
    try:
        # chmod 750: owner rwx, group r-x, others ---
        os.chmod(REPORT_DIR, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

        # Change group ownership to SHARED_GROUP
        gid = grp.getgrnam(SHARED_GROUP).gr_gid
        uid = os.getuid()
        os.chown(REPORT_DIR, uid, gid)
        print(f"  {Fore.GREEN}[+] Report dir: {REPORT_DIR}/ → group:{SHARED_GROUP} chmod 750{RESET}")
    except KeyError:
        print(f"  {Fore.YELLOW}[!] Group '{SHARED_GROUP}' not found — skipping chown (dir still created){RESET}")
    except PermissionError:
        print(f"  {Fore.YELLOW}[!] chown needs sudo — dir created without group ownership{RESET}")
    except Exception as e:
        print(f"  {Fore.YELLOW}[!] Dir setup warning: {e}{RESET}")

    # Return full path to report file inside the directory
    return os.path.join(REPORT_DIR, REPORT_FILE)


def set_report_permissions(report_path: str):
    """
    Sets forensic_report.txt to chmod 640:
    owner rw-, group r--, others ---
    """
    try:
        os.chmod(report_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        print(f"  {Fore.GREEN}[+] Report permissions: chmod 640 → {report_path}{RESET}")
    except Exception as e:
        print(f"  {Fore.YELLOW}[!] Could not set report permissions: {e}{RESET}")


def display_permission_summary(report_path: str):
    """Show a human-readable permission summary in the terminal."""
    print(f"\n{H}📁 FILE PERMISSION SUMMARY{RESET}")
    items = [
        (os.path.abspath(__file__), "Source code (700)", "Owner only"),
        (REPORT_DIR,                "Report folder (750)", f"Owner + group:{SHARED_GROUP}"),
        (report_path,               "Forensic report (640)", f"Owner rw, group:{SHARED_GROUP} r"),
    ]
    for path, perm, access in items:
        exists = "✅" if os.path.exists(path) else "⚠️ "
        try:
            s      = oct(stat.S_IMODE(os.stat(path).st_mode))
            actual = f"actual:{s}"
        except Exception:
            actual = "not yet created"
        print(f"  {exists} {Fore.CYAN}{perm}{RESET}  {Fore.YELLOW}{access}{RESET}  ({actual})")


# ══════════════════════════════════════════════════════════════
#  MODULE 1 — LOG AGGREGATION
#  Collects raw events from ALL sources into one unified queue
# ══════════════════════════════════════════════════════════════

RAW_LOG_QUEUE  = deque(maxlen=2000)   # raw events from all sources
AGG_LOCK       = threading.Lock()
_log_threads   = []
_observer      = None

LOG_SUSPICIOUS_KEYWORDS = [
    "failed password", "authentication failure", "invalid user",
    "sudo", "su root", "chmod 777", "wget", "curl",
    "/bin/bash", "cmd.exe", "powershell", "mshta",
    "ransomware", "trojan", "malware", "exploit",
    "mimikatz", "metasploit", "nmap", "netcat", "nc -",
    "base64", "decode", "reverse shell", "bind shell",
    "useradd", "userdel", "passwd", "shadow", "crontab",
    "iptables", "ufw", "firewall", "tcpdump", "wireshark",
]

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "meterpreter", "nmap", "netcat", "nc",
    "wce", "pwdump", "fgdump", "gsecdump", "lsadump",
    "psexec", "wmiexec", "smbexec", "crackmapexec",
    "lazagne", "bloodhound", "sharphound",
}

SUSPICIOUS_PORTS   = {4444, 5555, 1337, 31337, 6666, 6667, 8888, 9001}
REMOTE_SVC_PORTS   = {21, 22, 23, 3389, 5900}
LINUX_LOG_PATHS    = ["/var/log/syslog", "/var/log/auth.log",
                      "/var/log/messages", "/var/log/secure", "/var/log/kern.log"]
WINDOWS_CHANNELS   = ["System", "Security", "Application"]
SUSPICIOUS_EXTS    = {".exe",".bat",".ps1",".vbs",".js",".hta",
                      ".sh",".elf",".bin",".dll",".so",
                      ".encrypted",".locked",".crypt",".ransom"}


def _agg_push(source: str, raw_msg: str, source_type: str = "log"):
    """Push one raw event into the aggregation queue."""
    with AGG_LOCK:
        RAW_LOG_QUEUE.append({
            "collected_at": datetime.now().isoformat(timespec="seconds"),
            "source":       source,
            "source_type":  source_type,   # log | process | network | filesystem
            "raw":          raw_msg,
        })


def _linux_tail(path: str):
    if not os.path.exists(path):
        return
    print(f"  {Fore.CYAN}[Aggregator] Tailing → {path}{RESET}")
    try:
        proc = subprocess.Popen(["tail", "-F", "-n", "30", path],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            _agg_push(os.path.basename(path), line.strip(), "log")
    except Exception:
        pass


def _windows_channel(channel: str):
    try:
        import win32evtlog, win32con
    except ImportError:
        print(f"  {Fore.RED}[WinEvt] pip install pywin32{RESET}")
        return
    print(f"  {Fore.CYAN}[Aggregator] WinEvt → {channel}{RESET}")
    hand  = win32evtlog.OpenEventLog(None, channel)
    flags = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ
    win32evtlog.ReadEventLog(hand, flags, 0)
    while True:
        try:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            for ev in (events or []):
                msg = str(ev.StringInserts) if ev.StringInserts else ""
                _agg_push(f"WinEvt/{channel}",
                          f"EventID={ev.EventID} Src={ev.SourceName} {msg}", "log")
        except Exception:
            pass
        time.sleep(2)


def _proc_poller():
    if not PSUTIL_OK:
        return
    seen = set()
    print(f"  {Fore.CYAN}[Aggregator] Process poller active{RESET}")
    while True:
        try:
            for p in psutil.process_iter(["pid", "name", "cmdline", "username"]):
                try:
                    pid = p.info["pid"]
                    if pid in seen:
                        continue
                    seen.add(pid)
                    name    = (p.info["name"] or "").lower()
                    cmdline = " ".join(p.info.get("cmdline") or [])
                    user    = p.info.get("username") or "unknown"
                    _agg_push("process_monitor",
                              f"pid={pid} name={name} user={user} cmd={cmdline[:120]}",
                              "process")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        time.sleep(5)


def _net_poller():
    if not PSUTIL_OK:
        return
    seen = set()
    print(f"  {Fore.CYAN}[Aggregator] Network monitor active{RESET}")
    while True:
        try:
            for c in psutil.net_connections(kind="tcp"):
                if c.status != "ESTABLISHED" or not c.raddr:
                    continue
                key = (c.laddr.port, c.raddr.ip, c.raddr.port)
                if key in seen:
                    continue
                seen.add(key)
                _agg_push("network_monitor",
                          f"local={c.laddr.ip}:{c.laddr.port} "
                          f"remote={c.raddr.ip}:{c.raddr.port} status={c.status}",
                          "network")
        except Exception:
            pass
        time.sleep(5)


class _FSHandler(FileSystemEventHandler):
    def _push(self, etype, path):
        _agg_push("filesystem", f"event={etype} path={path}", "filesystem")
    def on_created(self,  e): self._push("CREATE",  e.src_path)
    def on_modified(self, e): self._push("MODIFY",  e.src_path)
    def on_deleted(self,  e): self._push("DELETE",  e.src_path)
    def on_moved(self,    e): self._push("MOVE",    e.dest_path)


def start_aggregation():
    global _observer
    detected = platform.system()
    if detected not in ("Linux", "Windows"):
        print(f"{Fore.RED}[!] Unsupported OS: {detected}. Linux/Windows only.{RESET}")
        sys.exit(1)

    print(f"\n{H}📥 MODULE 1 — LOG AGGREGATION  [{detected}]{RESET}")

    if detected == "Linux":
        for p in LINUX_LOG_PATHS:
            t = threading.Thread(target=_linux_tail, args=(p,), daemon=True)
            t.start(); _log_threads.append(t)
    else:
        for ch in WINDOWS_CHANNELS:
            t = threading.Thread(target=_windows_channel, args=(ch,), daemon=True)
            t.start(); _log_threads.append(t)

    for fn in (_proc_poller, _net_poller):
        t = threading.Thread(target=fn, daemon=True)
        t.start(); _log_threads.append(t)

    if WATCHDOG_OK:
        dirs = ([os.path.expanduser("~"), "/tmp", "/var/tmp"]
                if detected == "Linux"
                else [os.path.expanduser("~"),
                      os.environ.get("TEMP","C:\\Temp"), "C:\\Users\\Public"])
        handler = _FSHandler(); _observer = Observer()
        for d in dirs:
            if os.path.isdir(d):
                _observer.schedule(handler, d, recursive=True)
                print(f"  {Fore.CYAN}[Aggregator] Watching → {d}{RESET}")
        _observer.start()

    print(f"  {Fore.GREEN}✅ Aggregation running — all sources feeding into unified queue{RESET}\n")


# ══════════════════════════════════════════════════════════════
#  MODULE 2 — LOG NORMALISATION  (CEF-inspired standard format)
#  Converts every raw event into a structured NormalisedEvent dict
# ══════════════════════════════════════════════════════════════

NORM_EVENTS    = deque(maxlen=2000)
NORM_LOCK      = threading.Lock()

# MITRE tag lookup for normaliser
MITRE_QUICK = {
    "failed password":        ("T1110", "Brute Force",                    "Credential Access"),
    "authentication failure": ("T1110", "Brute Force",                    "Credential Access"),
    "invalid user":           ("T1078", "Valid Accounts",                  "Initial Access"),
    "sudo":                   ("T1548", "Abuse Elevation Control",         "Privilege Escalation"),
    "su root":                ("T1548", "Abuse Elevation Control",         "Privilege Escalation"),
    "chmod 777":              ("T1222", "File & Dir Permissions Mod",      "Defense Evasion"),
    "wget":                   ("T1105", "Ingress Tool Transfer",           "Command & Control"),
    "curl":                   ("T1105", "Ingress Tool Transfer",           "Command & Control"),
    "/bin/bash":              ("T1059", "Command & Scripting Interpreter", "Execution"),
    "powershell":             ("T1059", "Command & Scripting Interpreter", "Execution"),
    "cmd.exe":                ("T1059", "Command & Scripting Interpreter", "Execution"),
    "mshta":                  ("T1218", "System Binary Proxy Execution",   "Defense Evasion"),
    "base64":                 ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    "mimikatz":               ("T1003", "OS Credential Dumping",           "Credential Access"),
    "netcat":                 ("T1071", "Application Layer Protocol",      "Command & Control"),
    "nc -":                   ("T1071", "Application Layer Protocol",      "Command & Control"),
    "nmap":                   ("T1046", "Network Service Discovery",       "Discovery"),
    "ransomware":             ("T1486", "Data Encrypted for Impact",       "Impact"),
    "useradd":                ("T1136", "Create Account",                  "Persistence"),
    "userdel":                ("T1531", "Account Access Removal",          "Impact"),
    "crontab":                ("T1053", "Scheduled Task/Job",              "Persistence"),
    "shadow":                 ("T1003", "OS Credential Dumping",           "Credential Access"),
    ".encrypted":             ("T1486", "Data Encrypted for Impact",       "Impact"),
    ".locked":                ("T1486", "Data Encrypted for Impact",       "Impact"),
}


def _extract_ip(text: str):
    """Extract first IPv4 address found in text."""
    m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
    return m.group(1) if m else None


def _classify_severity(raw: str, source_type: str) -> str:
    low = raw.lower()
    if any(w in low for w in ["ransomware","mimikatz","exploit","metasploit","trojan",".encrypted",".locked"]):
        return "CRITICAL"
    if any(w in low for w in ["sudo","su root","powershell","base64","reverse shell","mimikatz",
                               "useradd","crontab","shadow"]):
        return "HIGH"
    if any(kw in low for kw in LOG_SUSPICIOUS_KEYWORDS):
        return "MEDIUM"
    if source_type in ("process", "network", "filesystem"):
        name = low
        if any(s in name for s in SUSPICIOUS_PROCESS_NAMES):
            return "HIGH"
        if "4444" in name or "1337" in name or "31337" in name:
            return "CRITICAL"
    return "LOW"


def _get_mitre(raw: str):
    low = raw.lower()
    for kw, info in MITRE_QUICK.items():
        if kw in low:
            return info
    return None


def normalise_event(raw_event: dict) -> dict:
    """
    Convert a raw aggregated event into CEF-inspired standard format:
    timestamp, event_id, severity, source, source_type,
    src_ip, message, mitre_id, mitre_name, tactic, raw
    """
    raw       = raw_event.get("raw", "")
    src_type  = raw_event.get("source_type", "log")
    severity  = _classify_severity(raw, src_type)
    mitre     = _get_mitre(raw)
    src_ip    = _extract_ip(raw)

    return {
        "event_id":    f"EVT-{int(time.time()*1000) % 999999:06d}",
        "timestamp":   raw_event.get("collected_at", datetime.now().isoformat()),
        "severity":    severity,
        "source":      raw_event.get("source", "unknown"),
        "source_type": src_type,
        "src_ip":      src_ip,
        "message":     raw[:200],
        "mitre_id":    mitre[0] if mitre else "N/A",
        "mitre_name":  mitre[1] if mitre else "N/A",
        "tactic":      mitre[2] if mitre else "N/A",
        "raw":         raw,
        # CEF standard fields
        "cef_version":    "CEF:0",
        "device_vendor":  "EDR-Tool",
        "device_product": "MitreEDR",
        "device_version": "3.0",
    }


def run_normalisation_pass():
    """Process everything in RAW_LOG_QUEUE, normalise, push to NORM_EVENTS."""
    normalised_count = 0
    with AGG_LOCK:
        raw_batch = list(RAW_LOG_QUEUE)

    for raw_ev in raw_batch:
        norm = normalise_event(raw_ev)
        with NORM_LOCK:
            NORM_EVENTS.append(norm)
        normalised_count += 1

    # Save normalised log to JSON
    with NORM_LOCK:
        snapshot = list(NORM_EVENTS)

    norm_path = os.path.join(REPORT_DIR, NORM_LOG_FILE)
    try:
        with open(norm_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        set_report_permissions(norm_path)
    except Exception:
        pass

    return normalised_count


# ══════════════════════════════════════════════════════════════
#  MODULE 3 — EVENT CORRELATION & ANALYSIS
#  Links related events to detect attack chains and patterns
# ══════════════════════════════════════════════════════════════

CORR_ALERTS = []
CORR_LOCK   = threading.Lock()


# Correlation rules — each rule checks a window of normalised events
CORRELATION_RULES = [
    {
        "rule_id":   "COR-001",
        "name":      "Brute Force Attack",
        "desc":      "5+ failed authentication events within 60 seconds from same source",
        "severity":  "CRITICAL",
        "mitre_id":  "T1110",
        "tactic":    "Credential Access",
        "check": lambda events: _rule_brute_force(events),
    },
    {
        "rule_id":   "COR-002",
        "name":      "Privilege Escalation Sequence",
        "desc":      "sudo or su root followed by sensitive file access within 120 seconds",
        "severity":  "HIGH",
        "mitre_id":  "T1548",
        "tactic":    "Privilege Escalation",
        "check": lambda events: _rule_priv_esc(events),
    },
    {
        "rule_id":   "COR-003",
        "name":      "Ransomware Pattern",
        "desc":      "Mass file modification + encrypted extension creation detected",
        "severity":  "CRITICAL",
        "mitre_id":  "T1486",
        "tactic":    "Impact",
        "check": lambda events: _rule_ransomware(events),
    },
    {
        "rule_id":   "COR-004",
        "name":      "C2 Beacon Detected",
        "desc":      "Outbound connection to known C2 port (4444/1337/31337)",
        "severity":  "CRITICAL",
        "mitre_id":  "T1071",
        "tactic":    "Command & Control",
        "check": lambda events: _rule_c2_beacon(events),
    },
    {
        "rule_id":   "COR-005",
        "name":      "Persistence Mechanism",
        "desc":      "Crontab edit or new user account creation detected",
        "severity":  "HIGH",
        "mitre_id":  "T1053",
        "tactic":    "Persistence",
        "check": lambda events: _rule_persistence(events),
    },
    {
        "rule_id":   "COR-006",
        "name":      "Suspicious Script Execution",
        "desc":      "New .sh / .ps1 / .bat file created then executed within 30 seconds",
        "severity":  "HIGH",
        "mitre_id":  "T1059",
        "tactic":    "Execution",
        "check": lambda events: _rule_script_exec(events),
    },
    {
        "rule_id":   "COR-007",
        "name":      "Credential Harvesting",
        "desc":      "Access to /etc/shadow, /etc/passwd, or SAM hive detected",
        "severity":  "CRITICAL",
        "mitre_id":  "T1003",
        "tactic":    "Credential Access",
        "check": lambda events: _rule_cred_harvest(events),
    },
]


def _time_window(events, seconds=60):
    """Return events within last N seconds."""
    cutoff = time.time() - seconds
    return [e for e in events
            if datetime.fromisoformat(e["timestamp"]).timestamp() >= cutoff]


def _rule_brute_force(events):
    window  = _time_window(events, 60)
    by_ip   = defaultdict(int)
    for e in window:
        low = e["raw"].lower()
        if "failed password" in low or "authentication failure" in low:
            ip = e.get("src_ip") or "unknown"
            by_ip[ip] += 1
    triggered = {ip: cnt for ip, cnt in by_ip.items() if cnt >= 5}
    if triggered:
        return True, f"Sources: {dict(list(triggered.items())[:3])}"
    return False, ""


def _rule_priv_esc(events):
    window = _time_window(events, 120)
    has_sudo = any("sudo" in e["raw"].lower() or "su root" in e["raw"].lower()
                   for e in window)
    has_sensitive = any(x in e["raw"].lower()
                        for e in window
                        for x in ["/etc/shadow", "/etc/passwd", "sam", "ntds"])
    if has_sudo and has_sensitive:
        return True, "sudo/su root + sensitive file access in same window"
    return False, ""


def _rule_ransomware(events):
    window = _time_window(events, 120)
    enc_count = sum(1 for e in window
                    if any(x in e["raw"].lower()
                           for x in [".encrypted", ".locked", ".crypt", ".ransom"]))
    mod_count = sum(1 for e in window
                    if "modify" in e["raw"].lower() or "create" in e["raw"].lower())
    if enc_count >= 1 and mod_count >= 5:
        return True, f"{enc_count} encrypted extension events + {mod_count} file modifications"
    return False, ""


def _rule_c2_beacon(events):
    window = _time_window(events, 300)
    hits   = []
    for e in window:
        raw = e["raw"]
        for port in SUSPICIOUS_PORTS:
            if str(port) in raw:
                ip = e.get("src_ip") or "unknown"
                hits.append(f"{ip}:{port}")
    if hits:
        return True, f"C2 ports observed: {list(set(hits))[:5]}"
    return False, ""


def _rule_persistence(events):
    window = _time_window(events, 300)
    has_cron    = any("crontab" in e["raw"].lower() for e in window)
    has_useradd = any("useradd" in e["raw"].lower() for e in window)
    if has_cron or has_useradd:
        detail = []
        if has_cron:    detail.append("crontab modification")
        if has_useradd: detail.append("new user account created")
        return True, " + ".join(detail)
    return False, ""


def _rule_script_exec(events):
    window = _time_window(events, 30)
    exts   = [".sh", ".ps1", ".bat", ".vbs"]
    created   = [e for e in window if "create" in e["raw"].lower()
                 and any(x in e["raw"].lower() for x in exts)]
    if created:
        return True, f"Script created: {created[0]['raw'][:80]}"
    return False, ""


def _rule_cred_harvest(events):
    window    = _time_window(events, 120)
    sensitive = ["/etc/shadow", "/etc/passwd", "sam", "ntds.dit", "lsass"]
    hits      = [e for e in window
                 if any(s in e["raw"].lower() for s in sensitive)]
    if hits:
        return True, f"Sensitive access: {hits[0]['raw'][:80]}"
    return False, ""


def run_correlation():
    """
    Run all correlation rules against the normalised event pool.
    Returns list of triggered correlation alerts.
    """
    with NORM_LOCK:
        events = list(NORM_EVENTS)

    triggered = []
    for rule in CORRELATION_RULES:
        try:
            fired, detail = rule["check"](events)
            if fired:
                alert = {
                    "alert_id":   f"ALT-{int(time.time()*1000) % 99999:05d}",
                    "timestamp":  datetime.now().isoformat(timespec="seconds"),
                    "rule_id":    rule["rule_id"],
                    "rule_name":  rule["name"],
                    "description":rule["desc"],
                    "severity":   rule["severity"],
                    "mitre_id":   rule["mitre_id"],
                    "tactic":     rule["tactic"],
                    "detail":     detail,
                    "event_count":len(events),
                }
                triggered.append(alert)
                _print_corr_alert(alert)
        except Exception:
            pass

    with CORR_LOCK:
        CORR_ALERTS.extend(triggered)

    # Persist to JSON
    corr_path = os.path.join(REPORT_DIR, CORR_LOG_FILE)
    try:
        with open(corr_path, "w", encoding="utf-8") as f:
            json.dump(CORR_ALERTS, f, indent=2)
        set_report_permissions(corr_path)
    except Exception:
        pass

    return triggered


def _print_corr_alert(alert: dict):
    col = Fore.RED + Style.BRIGHT if alert["severity"] == "CRITICAL" else Fore.LIGHTRED_EX
    print(
        f"  {Fore.WHITE}{alert['timestamp']}{RESET} "
        f"{Fore.MAGENTA}[CORRELATION]{RESET} "
        f"{col}[{alert['severity']}]{RESET} "
        f"{Fore.CYAN}{alert['rule_id']}{RESET} "
        f"{alert['rule_name']} — {alert['detail'][:70]}"
    )


# ══════════════════════════════════════════════════════════════
#  MODULE 4 — ALERTING ENGINE
#  Deduplicates, prioritises, and displays actionable alerts
# ══════════════════════════════════════════════════════════════

ALERT_COUNTS = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
ALERT_BUF    = deque(maxlen=500)
ALERT_LOCK   = threading.Lock()
_seen_alerts = set()   # deduplication by (source + message[:40])


def push_alert(source: str, severity: str, message: str, mitre=None):
    """
    Central alert emitter. Deduplicates, colours output,
    and stores into ALERT_BUF.
    """
    dedup_key = f"{source}|{message[:40]}"
    if dedup_key in _seen_alerts:
        return
    _seen_alerts.add(dedup_key)

    ts  = datetime.now().strftime("%H:%M:%S")
    col = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH":     Fore.LIGHTRED_EX,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.GREEN,
    }.get(severity, Fore.WHITE)

    tag = f" {Fore.CYAN}[{mitre[0]} · {mitre[2]}]{RESET}" if mitre else ""
    print(f"  {Fore.WHITE}{ts}{RESET} {Fore.MAGENTA}[{source}]{RESET} "
          f"{col}[{severity}]{RESET}{tag} {message[:100]}")

    with ALERT_LOCK:
        ALERT_COUNTS[severity] = ALERT_COUNTS.get(severity, 0) + 1
        ALERT_BUF.append({
            "ts": ts, "source": source, "severity": severity,
            "message": message, "mitre": list(mitre) if mitre else None,
        })


def alert_worker():
    """
    Background thread: reads NORM_EVENTS and pushes alerts
    for anything MEDIUM severity or above.
    """
    processed = set()
    while True:
        with NORM_LOCK:
            events = list(NORM_EVENTS)
        for ev in events:
            eid = ev.get("event_id")
            if eid in processed:
                continue
            processed.add(eid)
            if ev["severity"] in ("CRITICAL", "HIGH", "MEDIUM"):
                mitre = None
                if ev["mitre_id"] != "N/A":
                    mitre = (ev["mitre_id"], ev["mitre_name"], ev["tactic"])
                push_alert(ev["source"], ev["severity"], ev["message"], mitre)
        time.sleep(3)


def start_alert_engine():
    print(f"\n{H}🚨 MODULE 4 — ALERT ENGINE  [active]{RESET}")
    t = threading.Thread(target=alert_worker, daemon=True, name="AlertWorker")
    t.start()
    _log_threads.append(t)
    print(f"  {Fore.GREEN}✅ Alert engine running — deduplicating and emitting alerts{RESET}\n")


def display_alert_summary():
    with ALERT_LOCK:
        counts = dict(ALERT_COUNTS)
        alerts = list(ALERT_BUF)

    total = sum(counts.values())
    print(f"\n{H}🚨 ALERT ENGINE SUMMARY{RESET}")
    print(
        f"  {Fore.RED + Style.BRIGHT}CRITICAL:{counts.get('CRITICAL',0)}  "
        f"{Fore.LIGHTRED_EX}HIGH:{counts.get('HIGH',0)}  "
        f"{Fore.YELLOW}MEDIUM:{counts.get('MEDIUM',0)}  "
        f"{Fore.GREEN}LOW:{counts.get('LOW',0)}{RESET}  "
        f"(total unique: {total})"
    )

    notable = [a for a in alerts if a["severity"] in ("CRITICAL", "HIGH")][-10:]
    if notable:
        rows = []
        for a in notable:
            m = a["mitre"][0] if a["mitre"] else "N/A"
            rows.append([a["ts"], a["source"], a["severity"], m, a["message"][:50]])
        print(tabulate(rows,
                       headers=["Time","Source","Severity","MITRE","Message"],
                       tablefmt="fancy_grid"))
    else:
        print(f"  {Fore.CYAN}No CRITICAL/HIGH alerts yet. Try: sudo python edr_tool_v3.py{RESET}")


# ══════════════════════════════════════════════════════════════
#  MODULE 5 — REPORTING ENGINE
#  Combines file scan + normalised events + correlation alerts
#  into one unified forensic report
# ══════════════════════════════════════════════════════════════

def write_full_report(scan_data: list, report_path: str):
    """Write the complete unified forensic report."""
    ts             = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity_order = {"DANGER":0, "HIGH":1, "MEDIUM":2, "SAFE":3}
    scan_data.sort(key=lambda x: severity_order[x["risk"]])

    with NORM_LOCK:
        norm_events = list(NORM_EVENTS)
    with CORR_LOCK:
        corr_alerts = list(CORR_ALERTS)
    with ALERT_LOCK:
        alert_counts = dict(ALERT_COUNTS)

    with open(report_path, "a", encoding="utf-8") as f:

        # ── Header ────────────────────────────────────────────
        f.write("\n\n" + "="*80 + "\n")
        f.write("🛡️  MITRE ATT&CK ENHANCED FORENSIC REPORT  v3.0\n")
        f.write(f"  Scan Time  : {ts}\n")
        f.write(f"  Platform   : {platform.system()} {platform.release()}\n")
        f.write(f"  Report Dir : {REPORT_DIR}/\n")
        f.write(f"  Permissions: chmod 640 (owner rw, group:{SHARED_GROUP} r)\n")
        f.write("="*80 + "\n\n")

        # ── Section 1: File Scan Summary ─────────────────────
        f.write("[ SECTION 1 ] FILE SCAN — EXECUTIVE SUMMARY\n")
        f.write("="*80 + "\n\n")
        rows = []
        for item in scan_data:
            emoji = ("🚨" if item["risk"]=="DANGER" else "⚠️"
                     if item["risk"]=="HIGH" else "🟡"
                     if item["risk"]=="MEDIUM" else "✅")
            rows.append([emoji, item["file"][-50:], item["risk"],
                         f"{item['cvss']:.1f}", item["technique_id"]])
        f.write(tabulate(rows, headers=["","File","Risk","CVSS","MITRE"],
                         tablefmt="fancy_grid") + "\n\n")

        # ── Section 2: Detailed File Cases ───────────────────
        f.write("[ SECTION 2 ] DETAILED FORENSIC FILE ANALYSIS\n")
        f.write("="*80 + "\n\n")
        for idx, item in enumerate(scan_data, 1):
            f.write(f"🔍 CASE {idx}: {item['file']}\n")
            f.write("━"*80 + "\n")
            f.write(f"  Risk Level      : {item['risk']} ({item['risk_score']}/10)\n")
            f.write(f"  CVSS Score      : {item['cvss']:.1f}/10\n")
            f.write(f"  MITRE Technique : {item['technique_id']} — {item['technique_name']}\n")
            f.write(f"  Tactic          : {item['tactic']}\n")
            f.write(f"  File Size       : {item['size']:,} bytes\n")
            f.write(f"  Last Modified   : {item['last_modified']}\n")
            f.write(f"  SHA-256         : {item['sha256']}\n\n")
            f.write("  📋 THREAT DESCRIPTION\n")
            f.write(f"  {item['explanation']}\n\n")
            f.write("  🛡️  MITRE-RECOMMENDED MITIGATIONS\n")
            f.write("  " + "─"*50 + "\n")
            for i, step in enumerate(item["mitigation_steps"], 1):
                f.write(f"  {i:2d}. {step}\n")
            f.write("\n" + "━"*80 + "\n\n")

        # ── Section 3: Normalised Events ─────────────────────
        f.write("[ SECTION 3 ] NORMALISED EVENT LOG  (CEF format)\n")
        f.write("="*80 + "\n\n")
        non_low = [e for e in norm_events if e["severity"] != "LOW"]
        if non_low:
            f.write(f"  Total normalised events : {len(norm_events)}\n")
            f.write(f"  Non-LOW events shown    : {len(non_low)}\n\n")
            for e in non_low[-50:]:   # last 50 non-low events
                f.write(
                    f"  [{e['timestamp']}] [{e['severity']:8s}] "
                    f"[{e['source']:20s}] "
                    f"MITRE:{e['mitre_id']:8s} "
                    f"TACTIC:{e['tactic']}\n"
                    f"  → {e['message'][:100]}\n\n"
                )
        else:
            f.write("  No non-LOW events captured. Run with sudo for full log access.\n\n")

        # ── Section 4: Correlation Alerts ────────────────────
        f.write("[ SECTION 4 ] CORRELATION ENGINE — ATTACK CHAIN ANALYSIS\n")
        f.write("="*80 + "\n\n")
        if corr_alerts:
            for a in corr_alerts:
                f.write(f"  ⚡ [{a['severity']}] {a['rule_id']} — {a['rule_name']}\n")
                f.write(f"     MITRE : {a['mitre_id']} | Tactic: {a['tactic']}\n")
                f.write(f"     Detail: {a['detail']}\n")
                f.write(f"     Desc  : {a['description']}\n\n")
        else:
            f.write("  No correlation rules triggered in this session.\n\n")

        # ── Section 5: Alert Summary ──────────────────────────
        f.write("[ SECTION 5 ] ALERT ENGINE SUMMARY\n")
        f.write("="*80 + "\n\n")
        f.write(f"  CRITICAL : {alert_counts.get('CRITICAL',0)}\n")
        f.write(f"  HIGH     : {alert_counts.get('HIGH',0)}\n")
        f.write(f"  MEDIUM   : {alert_counts.get('MEDIUM',0)}\n")
        f.write(f"  LOW      : {alert_counts.get('LOW',0)}\n\n")

        with ALERT_LOCK:
            top_alerts = [a for a in ALERT_BUF
                          if a["severity"] in ("CRITICAL","HIGH")][-20:]
        for a in top_alerts:
            m = a["mitre"][0] if a["mitre"] else "N/A"
            f.write(f"  [{a['ts']}] [{a['severity']}] [{a['source']}] {m} — {a['message'][:80]}\n")

        f.write("\n" + "="*80 + "\n")
        f.write("END OF REPORT\n")
        f.write("="*80 + "\n")

    set_report_permissions(report_path)


def display_terminal_table(data):
    rows = []
    for item in data:
        rc = (f"{BLINK}{Fore.RED}{Style.BRIGHT}🚨 DANGER{RESET}" if item["risk"]=="DANGER" else
              f"{Fore.LIGHTRED_EX}⚠️  HIGH{RESET}"              if item["risk"]=="HIGH"   else
              f"{Fore.YELLOW}🟡 MEDIUM{RESET}"                   if item["risk"]=="MEDIUM" else
              f"{Fore.GREEN}✅ SAFE{RESET}")
        sf = item["file"][-40:] if len(item["file"])>40 else item["file"]
        rows.append([sf, rc, f"{item['cvss']:.1f}", item["technique_id"]])
    print(f"\n{Fore.CYAN}{Style.BRIGHT}🛡️  FILE SCAN RESULTS{RESET}\n")
    print(tabulate(rows, headers=["File","Risk","CVSS","MITRE"],
                   tablefmt="fancy_grid", stralign="left", numalign="center"))


# ══════════════════════════════════════════════════════════════# MITRE DATA LOADER# ══════════════════════════════════════════════════════════════

def load_mitre():
    lookup = {}
    try:
        with open(ATTACK_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                tid = obj.get("external_references",[{}])[0].get("external_id")
                if not tid:
                    continue
                lookup[tid] = {
                    "name":        obj.get("name","Unknown"),
                    "description": obj.get("description","No description")[:400],
                    "mitigations": _mitigations(tid),
                }
        print(f"  {Fore.GREEN}✅ Loaded {len(lookup)} MITRE techniques{RESET}")
    except Exception as e:
        print(f"  {Fore.YELLOW}⚠️  MITRE fallback: {e}{RESET}")
    return lookup


def _mitigations(tid):
    if "T1486" in tid:
        return ["Deploy EDR/XDR solutions","Enable application allowlisting",
                "Maintain offline encrypted backups","Configure ransomware protection",
                "Monitor for mass file encryption events","Implement network segmentation"]
    if "T1059" in tid:
        return ["Constrain PowerShell to Constrained Language Mode",
                "Enable Script Block Logging","Implement Least Privilege",
                "Block Office macros","Audit command line arguments",
                "Enable ETW logging"]
    if "T1070" in tid:
        return ["Enable file integrity monitoring","Configure log retention",
                "Deploy Sysmon","Implement tamper protection",
                "Monitor Event ID 1102 (log clearing)","Use immutable cloud logging"]
    if "T1021" in tid:
        return ["Disable unnecessary remote services","Use JIT admin access",
                "Deploy NAC policies","Harden RDP with MFA",
                "Audit failed logon attempts","Monitor for lateral movement"]
    return ["Keep systems patched","Deploy EDR/XDR","Apply Zero Trust principles",
            "Conduct security training","Perform red team exercises",
            "Maintain IR playbooks"]


def classify_file(filename, mitre_lookup):
    fn  = filename.lower()
    if fn.endswith((".exe",".bin")) or any(x in fn for x in ["rootkit","trojan","ransom"]):
        tid, risk = "T1486", "DANGER"
    elif fn.endswith(".sh") or "script" in fn:
        tid, risk = "T1059", "HIGH"
    elif fn.startswith(".") or "hidden" in fn:
        tid, risk = "T1070", "MEDIUM"
    elif any(x in fn for x in ["service","remote","ssh","rdp"]):
        tid, risk = "T1021", "MEDIUM"
    else:
        tid, risk = "N/A", "SAFE"

    if tid in mitre_lookup:
        md = mitre_lookup[tid]
        return risk, tid, md["name"], md["description"], md["mitigations"]
    return risk, tid, f"{tid} Generic", f"Characteristics of {tid}", _mitigations(tid)


def scan_directory(path, mitre_lookup):
    results = []
    for root, _, files in os.walk(path):
        for fname in files:
            fp   = os.path.join(root, fname)
            st   = os.stat(fp)
            risk, tid, tname, expl, mits = classify_file(fname, mitre_lookup)
            h    = hashlib.sha256()
            with open(fp, "rb") as fh:
                for chunk in iter(lambda: fh.read(4096), b""):
                    h.update(chunk)
            results.append({
                "file":             fp,
                "size":             st.st_size,
                "last_modified":    datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "sha256":           h.hexdigest(),
                "risk":             risk,
                "risk_score":       {"DANGER":10,"HIGH":8,"MEDIUM":5,"SAFE":1}[risk],
                "cvss":             {"DANGER":9.8,"HIGH":8.1,"MEDIUM":6.5,"SAFE":0.0}[risk],
                "tactic":           ("Impact" if risk=="DANGER" else "Execution" if risk=="HIGH"
                                     else "Defense Evasion" if risk=="MEDIUM" else "Reconnaissance"),
                "technique_id":     tid,
                "technique_name":   tname,
                "explanation":      expl,
                "mitigation_steps": mits,
            })
    return results


#══════════════════════════════════════════════════════════════# LOCK + SIGNAL#══════════════════════════════════════════════════════════════

def load_lock():
    global lock_state
    try:
        if os.path.exists(LOCK_FILE):
            with open(LOCK_FILE) as f:
                lock_state.update(json.load(f))
    except Exception:
        pass

def save_lock():
    try:
        with open(LOCK_FILE,"w") as f:
            json.dump(lock_state, f)
    except Exception:
        pass

def is_locked():
    return time.time() < lock_state["locked_until"]

def _cleanup(sig, frame):
    print(f"\n{Fore.YELLOW}Shutting down...{RESET}")
    if _observer:
        _observer.stop(); _observer.join()
    save_lock()
    sys.exit(0)

signal.signal(signal.SIGINT, _cleanup)


#══════════════════════════════════════════════════════════════SECURE REPORT VIEWER #══════════════════════════════════════════════════════════════

def open_report(report_path: str):
    load_lock()
    if is_locked():
        rem = int(lock_state["locked_until"] - time.time())
        print(f"\n{Fore.RED}{Style.BRIGHT}🔒 LOCKED — wait {rem}s{RESET}")
        while is_locked():
            try:
                r = int(lock_state["locked_until"] - time.time())
                print(f"  ⏰ {r}s remaining...  ", end="\r"); time.sleep(1)
            except KeyboardInterrupt:
                save_lock(); return
        print(f"\n{Fore.GREEN}✅ Unlocked.{RESET}")

    choice = input("\nType 'open' to view report or Enter to exit: ").strip().lower()
    if choice != "open":
        return

    for attempt in range(3):
        try:
            pw = getpass("Password: ")
        except KeyboardInterrupt:
            return
        if pw == PASSWORD:
            print(f"\n{Fore.GREEN}✅ Access Granted!{RESET}\n")
            try:
                with open(report_path, encoding="utf-8") as f:
                    for line in f:
                        t = line.strip()
                        if any(x in t for x in ["SECTION","FORENSIC REPORT","END OF REPORT"]):
                            print(SEC + line + RESET, end="")
                        elif t.startswith("🔍 CASE"):
                            print(FB + line + RESET, end="")
                        elif "THREAT DESCRIPTION" in t:
                            print(EXP + line + RESET, end="")
                        elif "MITIGATIONS" in t:
                            print(MIT + line + RESET, end="")
                        elif t.startswith(tuple(f"{i}." for i in range(1,20))):
                            parts = line.split(".",1)
                            print(f"{STEP}{parts[0]}.{RESET}{parts[1]}", end="")
                        elif ":" in line and not line.startswith("  "):
                            k, v = line.split(":",1)
                            print(f"{FL}{k.strip()}{RESET}:{v}", end="")
                        else:
                            print(line, end="")
            except FileNotFoundError:
                print(f"{Fore.RED}❌ Report not found: {report_path}{RESET}")
            lock_state["locked_until"] = 0; save_lock(); return
        else:
            left = 2 - attempt
            print(f"{Fore.RED}❌ Wrong password. {left} attempt(s) left.{RESET}")

    lock_state["locked_until"] = time.time() + LOCKOUT_DURATION
    save_lock()
    print(f"\n{Fore.RED}{Style.BRIGHT}🔒 Locked for {LOCKOUT_DURATION}s.{RESET}")
    while is_locked():
        try:
            r = int(lock_state["locked_until"] - time.time())
            print(f"  ⏰ {r}s remaining...  ", end="\r"); time.sleep(1)
        except KeyboardInterrupt:
            return
    print(f"\n{Fore.GREEN}✅ Unlocked.{RESET}")


# ══════════════════════════════════════════════════════════════MAIN══════════════════════════════════════════════════════════════

def main():
    load_lock()

    # ── Banner ────────────────────────────────────────────────
    print(f"\n{H}{'='*60}{RESET}")
    print(f"{H}  🛡️  MITRE ATT&CK EDR TOOL  v3.0{RESET}")
    print(f"{H}  Platform : {platform.system()} {platform.release()}{RESET}")
    print(f"{H}{'='*60}{RESET}\n")

    # ── Step 0: Source protection + directory setup ───────────
    print(f"{H}🔐 STEP 0 — SOURCE CODE & FILE PROTECTION{RESET}")
    protect_source_code()
    report_path = setup_report_directory()
    display_permission_summary(report_path)

    # ── Step 1: Load MITRE ────────────────────────────────────
    print(f"\n{H}🧠 LOADING MITRE ATT&CK DATASET{RESET}")
    mitre_lookup = load_mitre()

    # ── Step 2: Start aggregation (all log sources) ───────────
    start_aggregation()

    # ── Step 3: Start alert engine ────────────────────────────
    start_alert_engine()

    # ── Step 4: Scan files ────────────────────────────────────
    print(f"{H}📂 SCANNING sample_data/{RESET}")
    scan_data = scan_directory("sample_data", mitre_lookup)
    display_terminal_table(scan_data)

    # ── Step 5: Normalisation pass ────────────────────────────
    print(f"\n{H}📐 MODULE 2 — NORMALISATION PASS{RESET}")
    n = run_normalisation_pass()
    print(f"  {Fore.GREEN}✅ {n} raw events normalised to CEF format → {REPORT_DIR}/{NORM_LOG_FILE}{RESET}")

    # ── Step 6: Correlation ───────────────────────────────────
    print(f"\n{H}🔗 MODULE 3 — CORRELATION & ANALYSIS{RESET}")
    corr = run_correlation()
    if corr:
        print(f"  {Fore.RED}⚡ {len(corr)} correlation rule(s) fired!{RESET}")
    else:
        print(f"  {Fore.GREEN}✅ No attack chains detected in this window{RESET}")

    # ── Step 7: Alert summary ─────────────────────────────────
    display_alert_summary()

    # ── Step 8: Write unified report ─────────────────────────
    print(f"\n{H}📄 MODULE 5 — WRITING UNIFIED FORENSIC REPORT{RESET}")
    write_full_report(scan_data, report_path)
    print(f"  {Fore.GREEN}✅ Report saved → {report_path}{RESET}")
    display_permission_summary(report_path)

    # ── Step 9: Secure viewer ─────────────────────────────────
    open_report(report_path)

    # ── Cleanup ───────────────────────────────────────────────
    if _observer:
        _observer.stop(); _observer.join()
    save_lock()


if __name__ == "__main__":
    main()
