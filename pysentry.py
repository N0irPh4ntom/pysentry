#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PySentry - a lightweight, educational malware / virus scanner with a Tkinter GUI.

WHAT IT DOES
------------
  * Hashes files (SHA-256) and matches them against a local signature database.
  * Applies heuristic rules: double extensions, autorun.inf, executables in
    temp folders, masquerading process names, etc.
  * Inspects Windows Run / RunOnce registry keys and Startup folders.
  * Inspects Linux ~/.config/autostart .desktop launchers (parses Exec=).
  * Inspects the running process list for suspicious paths / names.
  * Inspects the hosts file for suspicious redirects (including the classic
    AV-blocking trick of pointing AV/update domains at 127.0.0.1).
  * Quarantines detected files (XOR-obfuscated so they can't be run) and can
    restore or permanently delete them.
  * Exports a JSON/TXT report.

WHAT IT IS NOT
--------------
This is a *learning / utility* tool. It is NOT a replacement for a real
anti-malware product. It has no kernel driver, no behavioural engine, no
cloud lookup, and no zero-day detection. Use it alongside (not instead of)
Windows Defender / ClamAV / etc.

Requires: Python 3.8+. Tkinter ships with the standard python.org installers.
On Debian/Ubuntu:  sudo apt install python3-tk
Optional:  pip install psutil   (better process enumeration)

CHANGELOG
---------
  1.2.1
    - FIX: startup crash on the Findings tab.  Treeview.tag_configure()
      accepts options only as keyword arguments, but the dark-theme code
      was unpacking the (bg, fg) tuples positionally, raising
      "TypeError: tag_configure() takes from 2 to 3 positional arguments
      but 4 were given".  Now unpacks into background=/foreground=.
  1.2.0
    - NEW: full dark theme — deep navy background, teal accent buttons,
      dark-blue panels, colour-coded severity rows that remain readable
      on the dark background.  Applied to every tab, the detail dialog
      and all text/log widgets.
  1.1.0
    - FIX: hosts-file scanner now flags AV/update domains redirected to
      loopback addresses (the classic "block Windows Update" trick) instead
      of silently skipping those lines.
    - FIX: report "host" field was always empty on Windows due to an
      operator-precedence bug in the ternary expression.
    - FIX: Linux ~/.config/autostart/*.desktop files are now parsed for
      their Exec= target, instead of only hashing the .desktop file itself.
    - HARDEN: quarantine XOR chunk size is now an explicit constant so
      encrypt and decrypt can never drift apart.
    - PERF: findings from the worker queue are batched before touching the
      Treeview / Log widgets, so large scans no longer stall the GUI.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "Tkinter is not available.\n"
        "  Windows/macOS: reinstall Python from python.org (tick 'tcl/tk').\n"
        "  Debian/Ubuntu: sudo apt install python3-tk\n"
    )
    raise SystemExit(1)


# --------------------------------------------------------------------------- #
#  Configuration & constants
# --------------------------------------------------------------------------- #

APP_NAME = "PySentry"
APP_VERSION = "1.2.1"

BASE_DIR = Path.home() / ".pysentry"
QUARANTINE_DIR = BASE_DIR / "quarantine"
REPORT_DIR = BASE_DIR / "reports"
SIG_FILE = BASE_DIR / "signatures.json"

MAX_HASH_BYTES = 128 * 1024 * 1024      # don't hash files bigger than this
MAX_FILES = 300_000                     # safety cap while enumerating
XOR_KEY = b"PySentry-Quarantine-Key-v1"

# Chunk size used by the quarantine stream cipher.  Encrypt and decrypt MUST
# use the same value — that's why it is a single named constant rather than
# a magic number duplicated in two places.
QUARANTINE_CHUNK_SIZE = 1 << 20         # 1 MiB

# Directories that are pointless / very slow to walk
SKIP_DIRS = {
    "$recycle.bin", "system volume information", "winsxs", "node_modules",
    ".git", "__pycache__", "venv", ".venv", "site-packages", "dist-info",
    "temp internet files", "installer", "assembly",
}

SEVERITY_ORDER = {"malware": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# --------------------------------------------------------------------------- #
#  Dark theme palette — deep navy background, teal accent
# --------------------------------------------------------------------------- #

COLORS = {
    # surfaces
    "bg":            "#0a1929",   # window background (deep navy)
    "bg_alt":        "#102a43",   # panels, toolbars, headings (navy panel)
    "bg_input":      "#0d2137",   # list / text widget background
    "bg_hover":      "#1b3a5c",   # hovered row / tab

    # text
    "fg":            "#d9e2ec",   # primary text (soft off-white)
    "fg_muted":      "#829ab1",   # secondary / hint text

    # borders
    "border":        "#1f4e79",   # subtle blue border
    "border_focus":  "#14b8a6",   # teal focus ring

    # accent (teal)
    "accent":        "#14b8a6",   # primary teal
    "accent_hover":  "#2dd4bf",   # lighter teal (hover)
    "accent_active": "#0d9488",   # darker teal (pressed)
    "accent_fg":     "#04202a",   # text on top of teal buttons

    # selection in lists
    "select_bg":     "#14b8a6",
    "select_fg":     "#04202a",

    # severity rows (background, foreground) — tuned for dark UI
    "sev_malware":   ("#4a1525", "#ff8fa3"),
    "sev_high":      ("#4a2516", "#ffb380"),
    "sev_medium":    ("#453b12", "#ffe580"),
    "sev_low":       ("#153354", "#8ec9ff"),
    "sev_info":      ("#1f2c3d", "#a7b6c8"),
}


DEFAULT_SIGNATURES = {
    "version": 1,
    "updated": "2024-01-01",
    "comment": (
        "Add your own SHA-256 hashes to 'hashes_sha256'. "
        "Patterns are Python regular expressions matched against the file name."
    ),

    # sha256 -> display name
    "hashes_sha256": {
        # EICAR standard antivirus test string (COMPLETELY HARMLESS).
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
            "EICAR-Test-File (harmless AV test string)",
    },

    "suspicious_process_patterns": [
        {
            "pattern": r"^(svch0st|scvhost|scvhosst|lsas[sz]|csrs?s|crsss|"
                       r"winl0gon|winlogon|taskh0st|explorer|runtimebr0ker|"
                       r"smss|services)\.exe$",
            "name": "Process name masquerading as a Windows system process",
            "severity": "medium",
        },
    ],

    "suspicious_file_patterns": [
        {
            "pattern": r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpe?g|png|gif|bmp|"
                       r"txt|rtf|csv|mp3|mp4|avi|mkv|zip|rar|7z|iso|dwg)"
                       r"\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|wsh|"
                       r"hta|ps1|psm1|lnk|jar|msi|reg)$",
            "name": "Double file extension (fake document icon)",
            "severity": "high",
        },
        {
            "pattern": r"\.(exe|scr|bat|cmd|vbs|js|ps1|hta)\.(txt|log|dat|tmp|bak|cfg)$",
            "name": "Executable disguised behind a data-file extension",
            "severity": "high",
        },
        {
            "pattern": r"^autorun\.inf$",
            "name": "autorun.inf (removable-media auto-run file)",
            "severity": "medium",
        },
        {
            "pattern": r"^(invoice|receipt|order|payment|shipping|resume|cv|"
                       r"photo|image|document|scan)[-_ ]?\d*\.(exe|scr|js|vbs|hta|lnk)$",
            "name": "Social-engineering lure file name",
            "severity": "medium",
        },
    ],

    # Files with these extensions get extra scrutiny inside temp folders
    "risky_extensions": [
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".msi",
        ".jar", ".lnk", ".reg", ".dll", ".sys", ".hta",
    ],

    # Hostnames that should never be redirected by the hosts file
    "sensitive_domains": [
        "microsoft.com", "windowsupdate.com", "windowsdefender", "live.com",
        "kaspersky", "avast", "avg.com", "malwarebytes", "norton", "mcafee",
        "bitdefender", "eset", "sophos", "virustotal", "clamav",
        "paypal", "bank", "chase", "wellsfargo", "hsbc", "barclays",
    ],
}


# --------------------------------------------------------------------------- #
#  Small helpers
# --------------------------------------------------------------------------- #

def ensure_dirs() -> None:
    for d in (BASE_DIR, QUARANTINE_DIR, REPORT_DIR):
        d.mkdir(parents=True, exist_ok=True)


def env_path(var: str) -> Path | None:
    value = os.environ.get(var)
    return Path(value) if value else None


def sha256_file(path: str, max_bytes: int = MAX_HASH_BYTES) -> str | None:
    """Return the SHA-256 of a file, or None if unreadable / too large."""
    h = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return None
                h.update(chunk)
    except (OSError, PermissionError):
        return None
    return h.hexdigest()


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """Fast XOR using big-int arithmetic (much quicker than a Python loop)."""
    if not data:
        return data
    k = (key * (len(data) // len(key) + 1))[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(k, "big")).to_bytes(
        len(data), "big"
    )


def _stream_xor(src: Path, dst: Path) -> None:
    """Stream-XOR a file.  Uses QUARANTINE_CHUNK_SIZE on both sides."""
    with open(src, "rb") as f_in, open(dst, "wb") as f_out:
        while True:
            chunk = f_in.read(QUARANTINE_CHUNK_SIZE)
            if not chunk:
                break
            f_out.write(_xor_bytes(chunk, XOR_KEY))


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024


# --------------------------------------------------------------------------- #
#  Signature database
# --------------------------------------------------------------------------- #

def load_signatures() -> dict:
    ensure_dirs()
    if not SIG_FILE.exists():
        SIG_FILE.write_text(
            json.dumps(DEFAULT_SIGNATURES, indent=2), encoding="utf-8"
        )

    user_data: dict = {}
    try:
        user_data = json.loads(SIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass

    merged = json.loads(json.dumps(DEFAULT_SIGNATURES))  # deep copy
    for key, value in user_data.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


# --------------------------------------------------------------------------- #
#  Finding model
# --------------------------------------------------------------------------- #

class Finding:
    __slots__ = ("severity", "category", "title", "detail", "path")

    def __init__(self, severity: str, category: str, title: str,
                 detail: str = "", path: str = ""):
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.path = path

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "path": self.path,
        }


# --------------------------------------------------------------------------- #
#  Quarantine vault
# --------------------------------------------------------------------------- #

def load_quarantine_index() -> list:
    ensure_dirs()
    idx = QUARANTINE_DIR / "index.json"
    if not idx.exists():
        return []
    try:
        return json.loads(idx.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_quarantine_index(entries: list) -> None:
    ensure_dirs()
    (QUARANTINE_DIR / "index.json").write_text(
        json.dumps(entries, indent=2), encoding="utf-8"
    )


def quarantine_file(path: str, finding: Finding | None = None) -> dict:
    """Move a file into the vault, XOR-obfuscated so it cannot execute."""
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(path)

    ensure_dirs()
    size = src.stat().st_size
    digest = sha256_file(str(src)) or hashlib.sha256(str(src).encode()).hexdigest()
    qid = f"{digest[:16]}-{int(time.time())}"
    dest = QUARANTINE_DIR / f"{qid}.quar"

    _stream_xor(src, dest)
    try:
        src.unlink()
    except OSError:
        dest.unlink(missing_ok=True)
        raise

    entry = {
        "id": qid,
        "original_path": str(src),
        "quarantined_at": datetime.now().isoformat(timespec="seconds"),
        "sha256": digest,
        "size": size,
        "detection": finding.title if finding else "Manual quarantine",
    }

    entries = load_quarantine_index()
    entries.append(entry)
    save_quarantine_index(entries)
    return entry


def restore_quarantined(entry: dict) -> None:
    src = QUARANTINE_DIR / f"{entry['id']}.quar"
    dest = Path(entry["original_path"])
    if not src.exists():
        raise FileNotFoundError(str(src))
    dest.parent.mkdir(parents=True, exist_ok=True)
    _stream_xor(src, dest)
    src.unlink()

    entries = [e for e in load_quarantine_index() if e["id"] != entry["id"]]
    save_quarantine_index(entries)


def delete_quarantined(entry: dict) -> None:
    (QUARANTINE_DIR / f"{entry['id']}.quar").unlink(missing_ok=True)
    entries = [e for e in load_quarantine_index() if e["id"] != entry["id"]]
    save_quarantine_index(entries)


# --------------------------------------------------------------------------- #
#  Process enumeration
# --------------------------------------------------------------------------- #

def _win_processes() -> list[tuple[int, str, str]]:
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    psapi = ctypes.WinDLL("psapi")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    buf = (wintypes.DWORD * 8192)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcesses(ctypes.byref(buf), ctypes.sizeof(buf),
                               ctypes.byref(needed)):
        return []

    count = needed.value // ctypes.sizeof(wintypes.DWORD)
    results: list[tuple[int, str, str]] = []

    for i in range(count):
        pid = buf[i]
        if pid == 0:
            continue
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                      False, pid)
        if not handle:
            continue
        try:
            size = wintypes.DWORD(32768)
            path_buf = ctypes.create_unicode_buffer(size.value)
            if kernel32.QueryFullProcessImageNameW(
                handle, 0, path_buf, ctypes.byref(size)
            ):
                p = path_buf.value
                results.append((pid, os.path.basename(p), p))
        finally:
            kernel32.CloseHandle(handle)
    return results


def _posix_processes() -> list[tuple[int, str, str]]:
    results = []
    proc = Path("/proc")
    if not proc.is_dir():
        return results
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            exe = os.readlink(entry / "exe")
        except OSError:
            continue
        results.append((int(entry.name), os.path.basename(exe), exe))
    return results


def list_processes() -> list[tuple[int, str, str]]:
    """Return [(pid, name, exe_path), ...] using the best method available."""
    try:
        import psutil  # type: ignore
        out = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            info = proc.info
            out.append((info.get("pid", 0), info.get("name") or "",
                        info.get("exe") or ""))
        return out
    except ImportError:
        pass

    try:
        if os.name == "nt":
            return _win_processes()
        return _posix_processes()
    except Exception:
        return []


# --------------------------------------------------------------------------- #
#  Scan engine  (runs on a worker thread)
# --------------------------------------------------------------------------- #

class ScanEngine:
    def __init__(self, sigdb: dict, events: queue.Queue,
                 stop_event: threading.Event):
        self.sig = sigdb
        self.events = events
        self.stop = stop_event
        self.stats = {"files": 0, "hashed": 0, "skipped": 0, "errors": 0}
        self._name_rules = []
        for rule in self.sig.get("suspicious_file_patterns", []):
            try:
                self._name_rules.append(
                    (re.compile(rule["pattern"], re.I),
                     rule["name"], rule.get("severity", "medium"))
                )
            except re.error:
                continue
        self._proc_rules = []
        for rule in self.sig.get("suspicious_process_patterns", []):
            try:
                self._proc_rules.append(
                    (re.compile(rule["pattern"], re.I),
                     rule["name"], rule.get("severity", "medium"))
                )
            except re.error:
                continue

    # -- plumbing ---------------------------------------------------------- #

    def emit(self, kind: str, payload=None) -> None:
        self.events.put((kind, payload))

    def finding(self, f: Finding) -> None:
        self.emit("finding", f)

    # -- entry point ------------------------------------------------------- #

    def run(self, roots: list[Path], label: str) -> None:
        try:
            self.emit("status", f"Starting {label}…")
            self._scan_startup()
            self._scan_processes()
            self._scan_hosts()
            if roots:
                self._scan_files(roots)
            self.emit("done", dict(self.stats))
        except Exception as exc:  # keep the GUI alive no matter what
            self.emit("error", f"{type(exc).__name__}: {exc}")
            self.emit("done", dict(self.stats))

    # -- file scanning ----------------------------------------------------- #

    def _scan_files(self, roots: list[Path]) -> None:
        self.emit("status", "Enumerating files…")
        self.emit("mode", "indeterminate")

        targets: list[str] = []
        for root in roots:
            if self.stop.is_set():
                break
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                if self.stop.is_set():
                    break
                dirnames[:] = [
                    d for d in dirnames
                    if d.lower() not in SKIP_DIRS and not d.startswith(".")
                ]
                for name in filenames:
                    targets.append(os.path.join(dirpath, name))
                    if len(targets) >= MAX_FILES:
                        break
                if len(targets) >= MAX_FILES:
                    break

        self.emit("mode", "determinate")
        total = len(targets) or 1
        self.emit("status", f"Scanning {len(targets):,} files…")

        for index, path in enumerate(targets):
            if self.stop.is_set():
                break
            self.stats["files"] += 1
            self._check_file(path, category="File scan")

            if index % 40 == 0:
                self.emit("progress", (index + 1) / total * 100)
            if index % 200 == 0:
                self.emit(
                    "status",
                    f"Scanning {index + 1:,}/{len(targets):,} — "
                    f"{os.path.basename(path)[:60]}",
                )

        self.emit("progress", 100)

    def _check_file(self, path: str, category: str = "File") -> None:
        """Hash + name-heuristic check on a single file."""
        name = os.path.basename(path)
        lower = name.lower()

        # 1) name-based heuristics
        for regex, rule_name, severity in self._name_rules:
            if regex.search(lower):
                self.finding(Finding(
                    severity, category, rule_name,
                    f"File name matched rule: {rule_name}\nFull path: {path}",
                    path,
                ))

        # 2) hash-based signature lookup
        try:
            if not os.path.isfile(path):
                return
            size = os.path.getsize(path)
        except OSError:
            self.stats["errors"] += 1
            return

        if size > MAX_HASH_BYTES:
            self.stats["skipped"] += 1
            return

        digest = sha256_file(path)
        if digest is None:
            self.stats["errors"] += 1
            return
        self.stats["hashed"] += 1

        signature = self.sig.get("hashes_sha256", {}).get(digest)
        if signature:
            self.finding(Finding(
                "malware", category, f"Signature match: {signature}",
                f"SHA-256: {digest}\nSize: {human_size(size)}\nPath: {path}",
                path,
            ))

    # -- startup / persistence --------------------------------------------- #

    def _scan_startup(self) -> None:
        self.emit("status", "Checking startup locations…")

        # Windows registry Run keys
        if os.name == "nt":
            try:
                import winreg
                run_keys = [
                    (winreg.HKEY_CURRENT_USER,
                     r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER,
                     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE,
                     r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE,
                     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE,
                     r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
                ]
                for hive, subkey in run_keys:
                    try:
                        with winreg.OpenKey(hive, subkey) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                except OSError:
                                    break
                                i += 1
                                self._inspect_startup_entry(
                                    f"{subkey}\\{name}", str(value)
                                )
                    except OSError:
                        continue
            except ImportError:
                pass

        # Startup folders (Windows) and autostart (Linux)
        startup_dirs: list[Path] = []
        if os.name == "nt":
            appdata = env_path("APPDATA")
            programdata = env_path("ProgramData")
            if appdata:
                startup_dirs.append(
                    appdata / "Microsoft/Windows/Start Menu/Programs/Startup"
                )
            if programdata:
                startup_dirs.append(
                    programdata / "Microsoft/Windows/Start Menu/Programs/Startup"
                )
        else:
            startup_dirs.append(Path.home() / ".config/autostart")

        for directory in startup_dirs:
            if not directory.is_dir():
                continue
            for item in directory.iterdir():
                # Linux autostart entries are .desktop launchers whose real
                # executable lives on the Exec= line — parse that instead of
                # treating the .desktop file itself as the payload.
                if item.suffix.lower() == ".desktop":
                    exec_cmd = self._parse_desktop_file(item)
                    if exec_cmd:
                        self._inspect_startup_entry(
                            f"Startup: {item.name}", exec_cmd
                        )
                        continue
                    # Fall through: no Exec= found, hash the file itself.
                self._inspect_startup_entry(
                    f"Startup folder: {directory.name}", str(item)
                )

    @staticmethod
    def _parse_desktop_file(path: Path) -> str | None:
        """Extract the command line from a .desktop file's Exec= entry."""
        try:
            content = path.read_text(errors="ignore")
        except OSError:
            return None

        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("exec="):
                cmd = line[5:].strip()
                # Strip freedesktop field codes (%U, %F, %i, %c, %k, …).
                cmd = re.sub(r"\s+%[a-zA-Z]", "", cmd).strip()
                return cmd or None
        return None

    def _inspect_startup_entry(self, source: str, command: str) -> None:
        """Check the target of a startup entry."""
        # Extract the executable path from the command line
        cleaned = command.strip()
        if cleaned.startswith('"'):
            end = cleaned.find('"', 1)
            exe = cleaned[1:end] if end > 1 else cleaned.strip('"')
        else:
            exe = cleaned.split(" ")[0]

        exe_path = Path(exe)
        if not exe_path.is_file():
            return

        # Hash check
        self._check_file(str(exe_path), category="Startup")

        # Location check
        temp_dirs = [
            env_path("TEMP"), env_path("TMP"), env_path("APPDATA"),
            env_path("LOCALAPPDATA"), Path("/tmp"),
        ]
        exe_lower = str(exe_path).lower()
        for tmp in temp_dirs:
            if tmp and str(tmp).lower() in exe_lower:
                self.finding(Finding(
                    "medium", "Startup",
                    "Startup entry launches from a temporary folder",
                    f"Source : {source}\nCommand: {command}",
                    str(exe_path),
                ))
                break

    # -- running processes -------------------------------------------------- #

    def _scan_processes(self) -> None:
        self.emit("status", "Checking running processes…")
        processes = list_processes()
        if not processes:
            return

        temp_dirs = [
            env_path("TEMP"), env_path("TMP"), env_path("APPDATA"),
            env_path("LOCALAPPDATA"), Path("/tmp"), Path("/var/tmp"),
        ]
        temp_strings = [
            os.path.normcase(str(d)) for d in temp_dirs if d
        ]
        risky = tuple(self.sig.get("risky_extensions", ()))

        for pid, name, path in processes:
            if self.stop.is_set():
                return
            if not name:
                continue

            lower_name = name.lower()

            for regex, rule_name, severity in self._proc_rules:
                if regex.match(lower_name):
                    self.finding(Finding(
                        severity, "Process", rule_name,
                        f"PID {pid} — {name}\nPath: {path or 'unknown'}",
                        path,
                    ))

            if path:
                norm = os.path.normcase(path)
                if norm.endswith(risky) and any(
                    norm.startswith(t) for t in temp_strings
                ):
                    self.finding(Finding(
                        "medium", "Process",
                        "Executable running from a temporary folder",
                        f"PID {pid} — {name}\nPath: {path}",
                        path,
                    ))

    # -- hosts file --------------------------------------------------------- #

    def _scan_hosts(self) -> None:
        self.emit("status", "Checking hosts file…")
        if os.name == "nt":
            windir = env_path("windir") or Path("C:/Windows")
            hosts = windir / "System32/drivers/etc/hosts"
        else:
            hosts = Path("/etc/hosts")

        if not hosts.is_file():
            return

        try:
            lines = hosts.read_text(errors="ignore").splitlines()
        except OSError:
            return

        sensitive = [s.lower() for s in self.sig.get("sensitive_domains", [])]
        loopback = ("127.0.0.1", "0.0.0.0", "::1", "localhost")
        redirects = 0

        for lineno, raw in enumerate(lines, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, hostname = parts[0], parts[1].lower()

            # Sensitive-domain check runs REGARDLESS of the destination IP.
            # Pointing an AV/update domain at 127.0.0.1 is the classic way
            # malware blocks Windows Update / Defender.  Only the descriptive
            # info message below is limited to non-loopback redirects.
            if any(domain in hostname for domain in sensitive):
                is_loopback = ip in loopback
                extra = (
                    "This entry points to a loopback address, which is the "
                    "classic way malware blocks antivirus / update domains."
                    if is_loopback else
                    "This entry points to a non-loopback address."
                )
                self.finding(Finding(
                    "high", "Hosts file",
                    "Security-related domain redirected in hosts file",
                    f"{hosts}:{lineno}\n{raw.strip()}\n\n{extra}",
                    str(hosts),
                ))

            if ip in loopback:
                continue

            redirects += 1

        if redirects:
            self.finding(Finding(
                "info", "Hosts file",
                f"{redirects} hostname(s) redirected to a non-loopback address",
                f"File: {hosts}\n"
                "Some malware redirects security/update domains via the hosts "
                "file to block updates. Review the entries if you did not add "
                "them yourself.",
                str(hosts),
            ))


# --------------------------------------------------------------------------- #
#  Scan targets
# --------------------------------------------------------------------------- #

def dedupe_paths(paths: list[Path]) -> list[Path]:
    """Remove duplicates and paths nested inside other paths."""
    unique: list[Path] = []
    seen = set()
    for p in paths:
        try:
            rp = p.resolve()
        except OSError:
            continue
        key = os.path.normcase(str(rp))
        if key in seen:
            continue
        seen.add(key)
        unique.append(rp)

    result = []
    for p in sorted(unique, key=lambda x: len(str(x))):
        p_str = os.path.normcase(str(p))
        if any(os.path.normcase(str(q)).startswith(p_str + os.sep) for q in result):
            continue
        result.append(p)
    return result


def quick_scan_targets() -> list[Path]:
    home = Path.home()
    candidates: list[Path] = []

    if os.name == "nt":
        candidates += [
            env_path("TEMP"), env_path("TMP"), env_path("APPDATA"),
            env_path("LOCALAPPDATA"), env_path("ProgramData"),
            home / "Downloads", home / "Desktop", home / "Documents",
            (env_path("windir") or Path("C:/Windows")) / "Temp",
        ]
    else:
        candidates += [
            Path("/tmp"), Path("/var/tmp"),
            home / "Downloads", home / "Desktop",
            home / ".config/autostart",
        ]

    return dedupe_paths([c for c in candidates if c and c.exists()])


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #

class ScannerApp(tk.Tk):

    def __init__(self) -> None:
        super().__init__()

        ensure_dirs()
        self.title(f"{APP_NAME} {APP_VERSION} — Malware Scanner")
        self.geometry("1120x720")
        self.minsize(940, 580)
        self.configure(bg=COLORS["bg"])

        self.sigdb = load_signatures()
        self.events: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.findings: list[Finding] = []
        self.item_map: dict[str, Finding] = {}
        self.q_entries: list[dict] = []

        self._build_style()
        self._build_toolbar()
        self._build_status()
        self._build_notebook()
        self._build_summary()

        self._refresh_quarantine()
        self._load_signature_view()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._poll_events)

        if not is_admin() and os.name == "nt":
            self.log("Note: running without administrator rights — some "
                     "locations (other users' profiles, protected system "
                     "folders) will be skipped.")

    # -- styling ------------------------------------------------------------ #

    def _build_style(self) -> None:
        """Apply the dark navy + teal theme to every ttk widget."""
        style = ttk.Style(self)
        # 'clam' is the most themeable built-in theme — required for the
        # colours below to actually take effect.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # ---- global defaults ------------------------------------------ #
        style.configure(
            ".",
            background=COLORS["bg"],
            foreground=COLORS["fg"],
            fieldbackground=COLORS["bg_input"],
            bordercolor=COLORS["border"],
            darkcolor=COLORS["bg_alt"],
            lightcolor=COLORS["bg_alt"],
            troughcolor=COLORS["bg_input"],
            focuscolor=COLORS["border_focus"],
            selectbackground=COLORS["select_bg"],
            selectforeground=COLORS["select_fg"],
            font=("Segoe UI", 9),
        )

        # ---- frames & labels ------------------------------------------ #
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Card.TFrame", background=COLORS["bg_alt"])

        style.configure("TLabel",
                        background=COLORS["bg"],
                        foreground=COLORS["fg"])
        style.configure("Head.TLabel",
                        background=COLORS["bg"],
                        foreground=COLORS["accent"],
                        font=("Segoe UI", 10, "bold"))
        style.configure("Muted.TLabel",
                        background=COLORS["bg"],
                        foreground=COLORS["fg_muted"])

        # ---- buttons (teal) ------------------------------------------- #
        style.configure(
            "TButton",
            background=COLORS["accent"],
            foreground=COLORS["accent_fg"],
            bordercolor=COLORS["accent"],
            focuscolor=COLORS["accent_hover"],
            padding=(12, 6),
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map(
            "TButton",
            background=[
                ("pressed", COLORS["accent_active"]),
                ("active",  COLORS["accent_hover"]),
                ("disabled", COLORS["bg_alt"]),
            ],
            foreground=[
                ("disabled", COLORS["fg_muted"]),
                ("!disabled", COLORS["accent_fg"]),
            ],
            bordercolor=[
                ("pressed", COLORS["accent_active"]),
                ("active",  COLORS["accent_hover"]),
                ("disabled", COLORS["bg_alt"]),
            ],
        )

        # ---- notebook ------------------------------------------------- #
        style.configure("TNotebook",
                        background=COLORS["bg"],
                        borderwidth=0,
                        tabmargins=(0, 6, 0, 0))
        style.configure(
            "TNotebook.Tab",
            background=COLORS["bg_alt"],
            foreground=COLORS["fg_muted"],
            padding=(18, 8),
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", COLORS["bg_input"]),
                ("active",   COLORS["bg_hover"]),
            ],
            foreground=[
                ("selected", COLORS["accent"]),
                ("active",   COLORS["fg"]),
            ],
        )

        # ---- treeview ------------------------------------------------- #
        style.configure(
            "Treeview",
            background=COLORS["bg_input"],
            fieldbackground=COLORS["bg_input"],
            foreground=COLORS["fg"],
            bordercolor=COLORS["border"],
            rowheight=24,
            font=("Segoe UI", 9),
        )
        style.map(
            "Treeview",
            background=[("selected", COLORS["select_bg"])],
            foreground=[("selected", COLORS["select_fg"])],
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["bg_alt"],
            foreground=COLORS["accent"],
            relief="flat",
            padding=(8, 6),
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Treeview.Heading",
            background=[("active", COLORS["bg_hover"])],
            foreground=[("active", COLORS["accent_hover"])],
        )

        # ---- progressbar --------------------------------------------- #
        style.configure(
            "TProgressbar",
            background=COLORS["accent"],
            troughcolor=COLORS["bg_input"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["accent"],
            darkcolor=COLORS["accent_active"],
            thickness=14,
        )

        # ---- scrollbars ---------------------------------------------- #
        for orient in ("Vertical", "Horizontal"):
            style.configure(
                f"{orient}.TScrollbar",
                background=COLORS["bg_alt"],
                troughcolor=COLORS["bg_input"],
                bordercolor=COLORS["bg_input"],
                arrowcolor=COLORS["fg_muted"],
                gripcount=0,
                relief="flat",
            )
            style.map(
                f"{orient}.TScrollbar",
                background=[
                    ("pressed", COLORS["accent_active"]),
                    ("active",  COLORS["accent"]),
                ],
                arrowcolor=[("active", COLORS["accent_fg"])],
            )

        # ---- separator ------------------------------------------------ #
        style.configure("TSeparator", background=COLORS["border"])

    @staticmethod
    def _text_widget_opts() -> dict:
        """Common options for tk.Text / ScrolledText widgets (dark theme)."""
        return dict(
            background=COLORS["bg_input"],
            foreground=COLORS["fg"],
            insertbackground=COLORS["accent"],
            selectbackground=COLORS["select_bg"],
            selectforeground=COLORS["select_fg"],
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=COLORS["border"],
            highlightcolor=COLORS["border_focus"],
            font=("Consolas", 9),
        )

    # -- construction ------------------------------------------------------- #

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(10, 10, 10, 6))
        bar.pack(fill="x")

        self.btn_quick = ttk.Button(bar, text="⚡ Quick Scan",
                                    command=self.start_quick_scan)
        self.btn_folder = ttk.Button(bar, text="📁 Scan Folder…",
                                     command=self.start_folder_scan)
        self.btn_full = ttk.Button(bar, text="💽 Full System Scan",
                                   command=self.start_full_scan)
        self.btn_stop = ttk.Button(bar, text="⏹ Stop", state="disabled",
                                   command=self.stop_scan)
        self.btn_report = ttk.Button(bar, text="📄 Export Report",
                                     command=self.export_report)

        self.btn_quick.pack(side="left", padx=(0, 6))
        self.btn_folder.pack(side="left", padx=6)
        self.btn_full.pack(side="left", padx=6)
        self.btn_stop.pack(side="left", padx=6)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=10)
        self.btn_report.pack(side="left")

        ttk.Button(bar, text="✖ Clear Results",
                   command=self.clear_results).pack(side="right")

    def _build_status(self) -> None:
        frame = ttk.Frame(self, padding=(10, 0, 10, 6))
        frame.pack(fill="x")

        self.progress = ttk.Progressbar(frame, mode="determinate",
                                        maximum=100)
        self.progress.pack(fill="x")

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(frame, textvariable=self.status_var,
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))

    def _build_notebook(self) -> None:
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(4, 6))

        self._build_findings_tab()
        self._build_quarantine_tab()
        self._build_signature_tab()
        self._build_log_tab()

    def _build_findings_tab(self) -> None:
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Findings  ")

        columns = ("severity", "category", "title", "path")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings",
                                 selectmode="browse")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("category", text="Category")
        self.tree.heading("title", text="Detection")
        self.tree.heading("path", text="Location")
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("category", width=110, anchor="center")
        self.tree.column("title", width=380)
        self.tree.column("path", width=470)

        # Dark-theme-friendly severity rows (bg, fg pairs from COLORS).
        # tag_configure() accepts options ONLY as keyword arguments — the
        # previous `tag_configure(tag, *pair)` form raised
        #   TypeError: tag_configure() takes from 2 to 3 positional arguments
        #   but 4 were given
        # because it passed background/foreground positionally.
        for tag, key in (
            ("malware", "sev_malware"),
            ("high",    "sev_high"),
            ("medium",  "sev_medium"),
            ("low",     "sev_low"),
            ("info",    "sev_info"),
        ):
            bg, fg = COLORS[key]
            self.tree.tag_configure(tag, background=bg, foreground=fg)

        vsb = ttk.Scrollbar(frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self._on_finding_double_click)

        ttk.Label(
            frame,
            text="Double-click a row for details and quarantine options.",
            style="Muted.TLabel",
        ).place(relx=0.01, rely=0.985, anchor="sw")

    def _build_quarantine_tab(self) -> None:
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Quarantine  ")

        top = ttk.Frame(frame, padding=(0, 4))
        top.pack(fill="x")
        ttk.Button(top, text="↩ Restore Selected",
                   command=self.restore_selected).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="🗑 Delete Permanently",
                   command=self.delete_selected).pack(side="left", padx=6)
        ttk.Button(top, text="🔄 Refresh",
                   command=self._refresh_quarantine).pack(side="left", padx=6)

        columns = ("date", "name", "original", "size", "detection")
        self.q_tree = ttk.Treeview(frame, columns=columns, show="headings",
                                   selectmode="browse")
        for col, text, width in (
            ("date", "Quarantined", 150),
            ("name", "File", 180),
            ("original", "Original location", 380),
            ("size", "Size", 90),
            ("detection", "Detection", 240),
        ):
            self.q_tree.heading(col, text=text)
            self.q_tree.column(col, width=width)

        vsb = ttk.Scrollbar(frame, orient="vertical",
                            command=self.q_tree.yview)
        self.q_tree.configure(yscrollcommand=vsb.set)
        self.q_tree.pack(side="left", fill="both", expand=True, pady=(4, 0))
        vsb.pack(side="right", fill="y", pady=(4, 0))

    def _build_signature_tab(self) -> None:
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Signatures  ")

        top = ttk.Frame(frame, padding=(0, 4))
        top.pack(fill="x")
        ttk.Button(top, text="🔄 Reload from disk",
                   command=self._reload_signatures).pack(side="left")
        ttk.Button(top, text="📂 Open signature folder",
                   command=self._open_sig_folder).pack(side="left", padx=6)
        ttk.Label(
            top,
            text=f"   ({SIG_FILE})",
            style="Muted.TLabel",
        ).pack(side="left")

        self.sig_view = ScrolledText(frame, wrap="none", height=20,
                                     **self._text_widget_opts())
        self.sig_view.pack(fill="both", expand=True, pady=(4, 0))

    def _build_log_tab(self) -> None:
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Log  ")
        self.log_view = ScrolledText(frame, wrap="word", height=20,
                                     state="disabled",
                                     **self._text_widget_opts())
        self.log_view.pack(fill="both", expand=True)

    def _build_summary(self) -> None:
        bar = ttk.Frame(self, padding=(10, 4, 10, 8))
        bar.pack(fill="x")
        self.summary_var = tk.StringVar(value="No scan run yet.")
        ttk.Label(bar, textvariable=self.summary_var,
                  style="Head.TLabel").pack(side="left")

    # -- logging ------------------------------------------------------------ #

    def log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_view.configure(state="normal")
        self.log_view.insert("end", f"[{stamp}] {message}\n")
        self.log_view.see("end")
        self.log_view.configure(state="disabled")

    def _log_lines(self, lines: list[str]) -> None:
        """Append many log lines in a single widget state toggle."""
        if not lines:
            return
        self.log_view.configure(state="normal")
        for line in lines:
            self.log_view.insert("end", line + "\n")
        self.log_view.see("end")
        self.log_view.configure(state="disabled")

    # -- scanning control --------------------------------------------------- #

    def _set_scanning(self, scanning: bool) -> None:
        state = "disabled" if scanning else "normal"
        for btn in (self.btn_quick, self.btn_folder, self.btn_full,
                    self.btn_report):
            btn.configure(state=state)
        self.btn_stop.configure(state="normal" if scanning else "disabled")

    def _start_scan(self, roots: list[Path], label: str) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(APP_NAME, "A scan is already running.")
            return

        self.stop_event.clear()
        self._set_scanning(True)
        self.progress.configure(mode="determinate", value=0)
        self.status_var.set(f"Starting {label}…")
        self.log(f"=== {label} started ===")
        if roots:
            for r in roots:
                self.log(f"  target: {r}")

        engine = ScanEngine(self.sigdb, self.events, self.stop_event)

        def work() -> None:
            engine.run(roots, label)

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def start_quick_scan(self) -> None:
        targets = quick_scan_targets()
        if not targets:
            messagebox.showwarning(APP_NAME, "No scannable folders found.")
            return
        self._start_scan(targets, "Quick Scan")

    def start_folder_scan(self) -> None:
        folder = filedialog.askdirectory(title="Choose a folder to scan")
        if not folder:
            return
        self._start_scan([Path(folder)], f"Folder Scan ({folder})")

    def start_full_scan(self) -> None:
        if os.name == "nt":
            drive = os.environ.get("SystemDrive", "C:") + os.sep
        else:
            drive = "/"
        if not messagebox.askyesno(
            APP_NAME,
            f"Full scan of {drive}\n\n"
            "This hashes every readable file and can take a long time "
            "(tens of minutes on a large drive).\n\nContinue?",
        ):
            return
        self._start_scan([Path(drive)], f"Full System Scan ({drive})")

    def stop_scan(self) -> None:
        self.stop_event.set()
        self.status_var.set("Stopping…")
        self.log("Stop requested — finishing current file.")

    # -- event pump --------------------------------------------------------- #

    def _poll_events(self) -> None:
        """Drain the worker queue, batching findings before touching widgets."""
        pending: list[Finding] = []
        try:
            while True:
                kind, payload = self.events.get_nowait()

                if kind == "finding":
                    pending.append(payload)
                    continue

                # Any non-finding event flushes pending findings first so
                # the visual ordering in the Findings tab matches reality.
                if pending:
                    self._add_findings_batch(pending)
                    pending = []

                self._handle_event(kind, payload)
        except queue.Empty:
            pass

        if pending:
            self._add_findings_batch(pending)

        self.after(80, self._poll_events)

    def _handle_event(self, kind: str, payload) -> None:
        if kind == "status":
            self.status_var.set(payload)

        elif kind == "progress":
            self.progress.configure(mode="determinate", value=payload)

        elif kind == "mode":
            if payload == "indeterminate":
                self.progress.configure(mode="indeterminate")
                self.progress.start(14)
            else:
                self.progress.stop()
                self.progress.configure(mode="determinate", value=0)

        elif kind == "finding":
            # Defensive fallback — normally intercepted in _poll_events.
            self._add_findings_batch([payload])

        elif kind == "error":
            self.log(f"ERROR: {payload}")

        elif kind == "done":
            self.progress.stop()
            self.progress.configure(mode="determinate", value=100)
            self._set_scanning(False)
            self._finish_scan(payload)

    def _add_findings_batch(self, findings: list[Finding]) -> None:
        """Insert several findings at once — one log-widget state toggle."""
        if not findings:
            return

        # Treeview inserts must run on the main thread (we are on it).
        for finding in findings:
            self.findings.append(finding)
            location = finding.path or ""
            if len(location) > 90:
                location = "…" + location[-89:]
            item = self.tree.insert(
                "", "end",
                values=(finding.severity.upper(), finding.category,
                        finding.title, location),
                tags=(finding.severity,),
            )
            self.item_map[item] = finding

        # Log entries are appended in one batch to avoid re-toggling the
        # widget state for every single finding (which is what used to stall
        # the GUI on scans with thousands of heuristic hits).
        stamp = datetime.now().strftime("%H:%M:%S")
        lines = [
            f"[{stamp}] [{f.severity.upper()}] {f.title} — "
            f"{f.path or f.category}"
            for f in findings
        ]
        self._log_lines(lines)

    def _finish_scan(self, stats: dict) -> None:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        threats = counts.get("malware", 0)
        suspects = sum(counts.get(s, 0) for s in ("high", "medium", "low"))

        self.summary_var.set(
            f"Files scanned: {stats.get('files', 0):,}  |  "
            f"Hashed: {stats.get('hashed', 0):,}  |  "
            f"Malware: {threats}  |  Suspicious: {suspects}  |  "
            f"Info: {counts.get('info', 0)}"
        )
        self.status_var.set("Scan complete.")
        self.log(
            f"=== Scan finished: {stats.get('files', 0):,} files, "
            f"{threats} malware, {suspects} suspicious, "
            f"{stats.get('errors', 0)} errors ==="
        )

    # -- finding details ---------------------------------------------------- #

    def _on_finding_double_click(self, _event) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        finding = self.item_map.get(selection[0])
        if finding:
            self._show_finding_dialog(finding)

    def _show_finding_dialog(self, finding: Finding) -> None:
        win = tk.Toplevel(self)
        win.title("Detection details")
        win.geometry("680x420")
        win.transient(self)
        win.configure(bg=COLORS["bg"])
        win.minsize(520, 320)

        # Severity pill — colour-coded to match the row tag in the tree.
        sev_bg, sev_fg = {
            "malware": COLORS["sev_malware"],
            "high":    COLORS["sev_high"],
            "medium":  COLORS["sev_medium"],
            "low":     COLORS["sev_low"],
            "info":    COLORS["sev_info"],
        }.get(finding.severity, COLORS["sev_info"])

        header_wrap = tk.Frame(win, bg=COLORS["bg"], padx=12, pady=12)
        header_wrap.pack(fill="x")

        pill = tk.Label(
            header_wrap,
            text=f" {finding.severity.upper()} ",
            bg=sev_bg, fg=sev_fg,
            font=("Segoe UI", 9, "bold"),
            padx=8, pady=2,
        )
        pill.pack(side="left")

        tk.Label(
            header_wrap,
            text=finding.title,
            bg=COLORS["bg"],
            fg=COLORS["accent"],
            font=("Segoe UI", 10, "bold"),
            anchor="w", justify="left",
        ).pack(side="left", padx=(10, 0))

        body = ScrolledText(win, wrap="word", **self._text_widget_opts())
        body.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        body.insert("1.0",
                    f"Severity : {finding.severity}\n"
                    f"Category : {finding.category}\n"
                    f"Detection: {finding.title}\n"
                    f"Location : {finding.path or '(n/a)'}\n"
                    f"{'-' * 70}\n\n{finding.detail}\n")
        body.configure(state="disabled")

        buttons = ttk.Frame(win, padding=(12, 0, 12, 12))
        buttons.pack(fill="x")

        def do_quarantine() -> None:
            try:
                quarantine_file(finding.path, finding)
            except Exception as exc:
                messagebox.showerror(APP_NAME, f"Quarantine failed:\n{exc}")
                return
            self.log(f"Quarantined: {finding.path}")
            self._refresh_quarantine()
            messagebox.showinfo(APP_NAME, "File moved to quarantine.")
            win.destroy()

        if finding.path and os.path.isfile(finding.path):
            ttk.Button(buttons, text="🔒 Quarantine file",
                       command=do_quarantine).pack(side="left")

            def open_folder() -> None:
                folder = os.path.dirname(finding.path)
                try:
                    if os.name == "nt":
                        os.startfile(folder)  # type: ignore[attr-defined]
                    elif sys.platform == "darwin":
                        os.system(f'open "{folder}"')
                    else:
                        os.system(f'xdg-open "{folder}"')
                except Exception as exc:
                    messagebox.showerror(APP_NAME, str(exc))

            ttk.Button(buttons, text="📂 Open containing folder",
                       command=open_folder).pack(side="left", padx=6)

        ttk.Button(buttons, text="Close", command=win.destroy).pack(
            side="right"
        )

    # -- quarantine tab ----------------------------------------------------- #

    def _refresh_quarantine(self) -> None:
        for row in self.q_tree.get_children():
            self.q_tree.delete(row)
        self.q_entries = load_quarantine_index()
        for entry in self.q_entries:
            name = os.path.basename(entry.get("original_path", ""))
            self.q_tree.insert(
                "", "end", iid=entry["id"],
                values=(
                    entry.get("quarantined_at", ""),
                    name,
                    entry.get("original_path", ""),
                    human_size(entry.get("size", 0)),
                    entry.get("detection", ""),
                ),
            )

    def _selected_quarantine_entry(self) -> dict | None:
        selection = self.q_tree.selection()
        if not selection:
            messagebox.showinfo(APP_NAME, "Select an item first.")
            return None
        target_id = selection[0]
        for entry in self.q_entries:
            if entry["id"] == target_id:
                return entry
        return None

    def restore_selected(self) -> None:
        entry = self._selected_quarantine_entry()
        if not entry:
            return
        if not messagebox.askyesno(
            APP_NAME,
            f"Restore this file to:\n{entry['original_path']}?\n\n"
            "Only restore files you trust. The file will be usable again.",
        ):
            return
        try:
            restore_quarantined(entry)
            self.log(f"Restored: {entry['original_path']}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Restore failed:\n{exc}")
        self._refresh_quarantine()

    def delete_selected(self) -> None:
        entry = self._selected_quarantine_entry()
        if not entry:
            return
        if not messagebox.askyesno(
            APP_NAME,
            f"Permanently delete the quarantined copy of:\n"
            f"{entry['original_path']}?\n\nThis cannot be undone.",
        ):
            return
        try:
            delete_quarantined(entry)
            self.log(f"Deleted from quarantine: {entry['original_path']}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Delete failed:\n{exc}")
        self._refresh_quarantine()

    # -- signatures tab ----------------------------------------------------- #

    def _load_signature_view(self) -> None:
        self.sig_view.configure(state="normal")
        self.sig_view.delete("1.0", "end")
        self.sig_view.insert("1.0", json.dumps(self.sigdb, indent=2))
        self.sig_view.configure(state="disabled")

    def _reload_signatures(self) -> None:
        self.sigdb = load_signatures()
        self._load_signature_view()
        self.log("Signature database reloaded.")
        messagebox.showinfo(APP_NAME, "Signatures reloaded from disk.")

    def _open_sig_folder(self) -> None:
        try:
            if os.name == "nt":
                os.startfile(BASE_DIR)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f'open "{BASE_DIR}"')
            else:
                os.system(f'xdg-open "{BASE_DIR}"')
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    # -- reports ------------------------------------------------------------ #

    def export_report(self) -> None:
        if not self.findings:
            messagebox.showinfo(APP_NAME, "Nothing to export — no findings.")
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default = REPORT_DIR / f"pysentry-report-{stamp}.json"
        path = filedialog.asksaveasfilename(
            title="Save scan report",
            initialdir=str(REPORT_DIR),
            initialfile=default.name,
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("Text report", "*.txt")],
        )
        if not path:
            return

        try:
            if path.lower().endswith(".txt"):
                lines = [
                    f"{APP_NAME} {APP_VERSION} scan report",
                    f"Generated: {datetime.now().isoformat(timespec='seconds')}",
                    f"Findings : {len(self.findings)}",
                    "=" * 72,
                    "",
                ]
                for f in self.findings:
                    lines += [
                        f"[{f.severity.upper()}] {f.title}",
                        f"  Category: {f.category}",
                        f"  Path    : {f.path}",
                        f"  Detail  : {f.detail.replace(chr(10), ' | ')}",
                        "",
                    ]
                Path(path).write_text("\n".join(lines), encoding="utf-8")
            else:
                # FIX (1.1.0): the previous expression
                #   A or B if cond else C
                # parsed as (A or B) if cond else C, so on Windows (no
                # os.uname) it collapsed to "" regardless of COMPUTERNAME.
                host = os.environ.get("COMPUTERNAME") or (
                    os.uname().nodename if hasattr(os, "uname") else ""
                )
                payload = {
                    "app": APP_NAME,
                    "version": APP_VERSION,
                    "generated": datetime.now().isoformat(timespec="seconds"),
                    "host": host,
                    "summary": {
                        "total": len(self.findings),
                        "malware": sum(1 for f in self.findings
                                       if f.severity == "malware"),
                        "high": sum(1 for f in self.findings
                                    if f.severity == "high"),
                        "medium": sum(1 for f in self.findings
                                      if f.severity == "medium"),
                    },
                    "findings": [f.to_dict() for f in self.findings],
                }
                Path(path).write_text(
                    json.dumps(payload, indent=2), encoding="utf-8"
                )
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not write report:\n{exc}")
            return

        self.log(f"Report written to {path}")
        messagebox.showinfo(APP_NAME, f"Report saved to:\n{path}")

    # -- misc --------------------------------------------------------------- #

    def clear_results(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(APP_NAME, "Stop the running scan first.")
            return
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.findings.clear()
        self.item_map.clear()
        self.summary_var.set("No scan run yet.")
        self.progress.configure(value=0)
        self.status_var.set("Ready.")
        self.log("Results cleared.")

    def _on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno(APP_NAME, "A scan is running. Quit?"):
                return
            self.stop_event.set()
        self.destroy()


# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    app = ScannerApp()
    app.log(f"{APP_NAME} {APP_VERSION} started.")
    app.log(f"Signature file: {SIG_FILE}")
    app.log(f"Quarantine    : {QUARANTINE_DIR}")
    app.mainloop()


if __name__ == "__main__":
    main()
