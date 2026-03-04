# 🛡️ HardNix — System Hardening Auditor

> A comprehensive Linux security auditing tool for red teamers, pentesters, and security engineers.

![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)
![Version](https://img.shields.io/badge/Version-1.0.0-red)

```
  _  _              _ _  _ _
 | || |__ _ _ _ __| | \| (_)_ __
 | __ / _` | '_/ _` | .` | \ \ /
 |_||_\__,_|_| \__,_|_|\_|_/_\_\
```

HardNix performs **100+ automated security checks** across 12 modules and produces a scored, graded report in terminal, JSON, or HTML format. It's built for speed, portability, and depth — no dependencies beyond standard Linux tools.

---

## ✨ Features

- **12 security modules** covering the entire attack surface
- **Scoring system** (0–100) with letter grades (A → F)
- **Severity levels**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Three output formats**: terminal (colored), JSON, HTML (dark theme)
- **Zero dependencies** — pure Bash, uses only standard Linux tools
- **GTFOBins-aware** SUID/capability detection
- **Container escape vector** detection (Docker, AppArmor, Seccomp)
- **Root privilege awareness** — gracefully skips checks that require root

---

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/hardnix.git
cd hardnix
chmod +x hardnix.sh
```

---

## 🚀 Usage

```bash
# Full audit (requires root for complete coverage)
sudo ./hardnix.sh

# Run specific modules only
sudo ./hardnix.sh -m ssh,kernel,users

# Verbose (show passing checks too)
sudo ./hardnix.sh -v

# Save as JSON report
sudo ./hardnix.sh -f json -o /tmp/reports

# Generate HTML report
sudo ./hardnix.sh -f html

# No color (for piping / CI)
sudo ./hardnix.sh -n | tee audit.txt
```

---

## 🔬 Modules

| Module       | Checks | Description |
|--------------|--------|-------------|
| `kernel`     | 15     | Kernel parameters, ASLR, kptr_restrict, Spectre/Meltdown mitigations, NX bit |
| `ssh`        | 18     | SSH daemon config: root login, password auth, ciphers, MACs, timeouts |
| `users`      | 11     | UID 0 accounts, empty passwords, sudo NOPASSWD, home dir permissions |
| `fs`         | 11     | Mount options (noexec/nosuid), world-writable files, /etc/shadow permissions |
| `network`    | 17     | IP forwarding, SYN cookies, reverse path filtering, firewall status |
| `services`   | 4      | Dangerous daemons (telnet, FTP, rsh), excessive enabled services |
| `pam`        | 4      | Password quality, account lockout, nullok, resource limits |
| `containers` | 7      | Docker socket, docker group, rootless mode, AppArmor/SELinux, Seccomp |
| `crypto`     | 5      | TLS cipher policies, SSLv2/3, GRUB password, SSH host key strength |
| `logging`    | 5      | auditd, syslog, auth log permissions, logrotate |
| `suid`       | 5      | SUID/SGID binaries, dangerous capabilities, GTFOBins-exploitable bins |
| `cron`       | 5      | World-writable cron dirs, suspicious root crontab, at.allow policy |

---

## 📊 Scoring

HardNix produces a **0–100 score** based on failed check severity:

| Severity | Points Deducted |
|----------|-----------------|
| CRITICAL | -10 pts |
| HIGH     | -5 pts |
| MEDIUM   | -2 pts |
| LOW      | -1 pt |

**Grades:**

| Score  | Grade |
|--------|-------|
| 90–100 | A — Hardened |
| 75–89  | B — Good |
| 60–74  | C — Fair |
| 40–59  | D — Weak |
| 0–39   | F — Critical Risk |

---

## 📸 Output Examples

### Terminal
```
━━━  SSH DAEMON  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ❌ [CRITICAL ] [S-001]    Root login disabled
     ↳ PermitRootLogin = yes
  ✅ [HIGH     ] [S-002]    Password authentication disabled
  ❌ [HIGH     ] [S-014]    Weak SSH ciphers configured
     ↳ Weak cipher: arcfour,3des-cbc,...
```

### JSON
```json
{
  "meta": { "tool": "HardNix", "hostname": "prod-server", ... },
  "score": 62,
  "grade": "C — Fair",
  "stats": { "total": 107, "passed": 79, "failed": 22, "warnings": 6 },
  "findings": [
    { "module": "ssh", "id": "S-001", "severity": "CRITICAL", "status": "FAIL",
      "title": "Root login disabled", "detail": "PermitRootLogin = yes" }
  ]
}
```

### HTML
A dark-themed, self-contained HTML report grouped by module with color-coded severity badges.

---

## 🔒 Ethical Use

HardNix is intended for:
- **Authorized** security assessments of systems you own or have written permission to audit
- Internal hardening reviews and compliance checks
- Red team recon on scoped engagements
- CTF and lab environments

**Never run this tool against systems you do not have authorization to test.**

---

## 🤝 Contributing

Contributions welcome! To add a new check:

1. Open the relevant module in `modules/`
2. Call `record_check "<module>" "<ID>" "<SEVERITY>" "<PASS|FAIL|WARN>" "<title>" "<detail>"`
3. Follow the `SEVERITY` conventions: CRITICAL / HIGH / MEDIUM / LOW / INFO
4. Open a PR with a description of what the check detects and why it matters

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

## 🙏 References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [STIG Viewer](https://public.cyber.mil/stigs/downloads/)
- [GTFOBins](https://gtfobins.github.io/)
- [Linux Kernel Self-Protection Project](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
- [lynis](https://cisofy.com/lynis/) — inspiration for modular approach
