# PySentry - Malware Scanner

A lightweight, educational malware scanner with a dark-themed GUI, written in pure Python. No dependencies beyond the standard library (Tkinter ships with Python).

Scans files against a local SHA-256 signature database, applies heuristic rules, and checks common persistence and network-hijack locations. Includes a quarantine vault and JSON/TXT report export.

Not a real antivirus. No kernel driver, no behavioural engine, no cloud lookup, no unpacking. Use alongside Windows Defender / ClamAV, not instead of them.

Features
Three scan modes — Quick (common user folders), Folder (pick any directory), Full System (whole drive)

Signature scanning — SHA-256 hash lookup against an editable JSON signature database (ships with the EICAR test hash so you can verify detection works)

Heuristic rules — double file extensions (.pdf.exe), executables disguised as data files, autorun.inf, social-engineering lure names

Persistence checks — Windows Run / RunOnce registry keys, Windows Startup folders, Linux ~/.config/autostart/*.desktop files (parses Exec=)

Process inspection — flags processes whose names masquerade as Windows system binaries, or that run from temp directories

Hosts file check — detects AV / update domains redirected by malware (including the classic 127.0.0.1 windowsupdate.com trick)

Quarantine vault — detected files are moved and XOR-obfuscated so they can't execute; restore or permanently delete from the GUI

Reports — export findings as JSON or plain text

Dark UI — deep navy background, teal accents, colour-coded severity rows

Requirements
Python 3.8+

Tkinter (included with python.org installers; on Debian/Ubuntu: sudo apt install python3-tk)

Optional: pip install psutil for more accurate process enumeration on Windows

Usage
Run it
bash
python pysentry.py
Typical workflow
Click ⚡ Quick Scan to check your Downloads, Desktop, Documents, temp folders, and startup entries.

Review the Findings tab. Rows are colour-coded by severity (malware / high / medium / low / info).

Double-click a row for full details.

If it's something you don't trust, click 🔒 Quarantine file in the details dialog.

Use the Quarantine tab to review, restore, or permanently delete vaulted files.

Click 📄 Export Report to save results as JSON or .txt.

Other scan options
📁 Scan Folder… — pick any directory

💽 Full System Scan — hash every readable file on the drive (slow, confirm the prompt)

⏹ Stop — interrupt a running scan at any time

Adding your own signatures
Edit ~/.pysentry/signatures.json (the Signatures tab has a button to open that folder):

Add hashes under hashes_sha256:

json
"hashes_sha256": {
  "abc123...": "Name of the threat"
}
Add filename regexes under suspicious_file_patterns

Add process-name regexes under suspicious_process_patterns

Add AV/update domains under sensitive_domains

Click 🔄 Reload from disk in the Signatures tab to apply without restarting.

Verifying it works
Create a file on your Desktop named eicar.com containing exactly this line:

text
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
Run a Quick Scan — the file should appear as a MALWARE finding. Quarantine it, then restore it from the Quarantine tab to confirm the round-trip works.

Where files are stored
Path	Contents
~/.pysentry/signatures.json	Signature database
~/.pysentry/quarantine/	Obfuscated quarantined files + index.json
~/.pysentry/reports/	Exported scan reports
Known limitations
Detection is only as good as the signatures you feed it — heuristics miss renamed or packed malware

Files larger than 128 MB are skipped during hashing

Without administrator / root rights, many system locations are silently skipped

Not tamper-protected — anyone with write access to ~/.pysentry/ can modify the quarantine

No digital signature verification of scanned executables

No memory scanning, no YARA, no unpacking, no rootkit detection
