#!/usr/bin/env bash
# Module: logging

audit_logging() {
  print_section "LOGGING & AUDIT"

  # auditd running?
  if systemctl is-active --quiet auditd 2>/dev/null; then
    record_check "logging" "L-001" "HIGH" "PASS" "auditd is running" ""
  else
    record_check "logging" "L-001" "HIGH" "FAIL" "auditd is NOT running" \
      "Install & enable: apt install auditd && systemctl enable --now auditd"
  fi

  # auditd rules present?
  if command -v auditctl &>/dev/null; then
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | grep -cv "^-a\|^No\|^List" || echo "0")
    if [[ "$rule_count" -gt 5 ]]; then
      record_check "logging" "L-002" "HIGH" "PASS" "auditd has $rule_count active rules" ""
    else
      record_check "logging" "L-002" "HIGH" "WARN" "auditd has few or no rules ($rule_count)" \
        "Consider CIS or STIG audit rule sets"
    fi
  fi

  # syslog running
  local syslog_active=false
  for svc in rsyslog syslog syslog-ng; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      record_check "logging" "L-003" "MEDIUM" "PASS" "Syslog daemon running ($svc)" ""
      syslog_active=true
      break
    fi
  done
  $syslog_active || record_check "logging" "L-003" "MEDIUM" "FAIL" "No syslog daemon running" \
    "Enable rsyslog or syslog-ng for centralized logging"

  # /var/log/auth.log or /var/log/secure exists and recent
  for logfile in /var/log/auth.log /var/log/secure; do
    if [[ -f "$logfile" ]]; then
      local log_perms
      log_perms=$(stat -c "%a" "$logfile")
      if [[ "$log_perms" -le 640 ]]; then
        record_check "logging" "L-004" "MEDIUM" "PASS" "Auth log permissions secure ($logfile)" "$log_perms"
      else
        record_check "logging" "L-004" "MEDIUM" "FAIL" "Auth log permissions too open ($logfile)" \
          "$log_perms — should be 640 or stricter"
      fi
    fi
  done

  # logrotate configured
  if [[ -f /etc/logrotate.conf ]] || [[ -d /etc/logrotate.d ]]; then
    record_check "logging" "L-005" "LOW" "PASS" "logrotate configuration present" ""
  else
    record_check "logging" "L-005" "LOW" "WARN" "logrotate not configured" \
      "Logs may grow unbounded — configure logrotate"
  fi
}

# =============================================================================
# Module: pam
# =============================================================================
audit_pam() {
  print_section "PAM CONFIGURATION"

  # pam_pwquality or pam_cracklib for password quality
  if grep -rq "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null; then
    record_check "pam" "P-001" "HIGH" "PASS" "Password quality module (pwquality/cracklib) active in PAM" ""
  else
    record_check "pam" "P-001" "HIGH" "FAIL" "No password quality enforcement in PAM" \
      "Add pam_pwquality.so to /etc/pam.d/common-password"
  fi

  # pam_tally2 or pam_faillock (account lockout on failed logins)
  if grep -rqE "pam_tally2|pam_faillock" /etc/pam.d/ 2>/dev/null; then
    record_check "pam" "P-002" "HIGH" "PASS" "Account lockout on failed logins configured (pam_tally2/faillock)" ""
  else
    record_check "pam" "P-002" "HIGH" "FAIL" "No account lockout policy in PAM" \
      "Add pam_faillock.so to /etc/pam.d/common-auth to lock accounts after failed attempts"
  fi

  # pam_limits (resource limits)
  if grep -rq "pam_limits" /etc/pam.d/ 2>/dev/null; then
    record_check "pam" "P-003" "MEDIUM" "PASS" "pam_limits module active (resource limits enforced)" ""
  else
    record_check "pam" "P-003" "MEDIUM" "WARN" "pam_limits not configured in PAM" \
      "Enable resource limits via pam_limits.so"
  fi

  # nullok in PAM (allows empty passwords)
  if grep -rq "nullok" /etc/pam.d/ 2>/dev/null; then
    record_check "pam" "P-004" "CRITICAL" "FAIL" "PAM configured with 'nullok' (empty passwords allowed)" \
      "Remove nullok from pam.d configs to require passwords"
  else
    record_check "pam" "P-004" "CRITICAL" "PASS" "PAM does not allow empty passwords (no nullok)" ""
  fi
}

# =============================================================================
# Module: crypto
# =============================================================================
audit_crypto() {
  print_section "CRYPTOGRAPHY"

  # Update-crypto-policies (RHEL/Fedora)
  if command -v update-crypto-policies &>/dev/null; then
    local policy
    policy=$(update-crypto-policies --show 2>/dev/null || echo "UNKNOWN")
    if [[ "$policy" == "DEFAULT" || "$policy" == "FUTURE" ]]; then
      record_check "crypto" "CR-001" "HIGH" "PASS" "System crypto policy: $policy" ""
    else
      record_check "crypto" "CR-001" "HIGH" "WARN" "System crypto policy is non-standard: $policy" \
        "LEGACY policy may allow weak ciphers (SSLv3, RC4, etc.)"
    fi
  fi

  # SSL/TLS — check for SSLv2/SSLv3 in common configs
  for conf in /etc/nginx/nginx.conf /etc/apache2/sites-enabled/*.conf /etc/httpd/conf/httpd.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qiE "SSLv2|SSLv3" "$conf" 2>/dev/null; then
      record_check "crypto" "CR-002" "CRITICAL" "FAIL" "SSLv2/SSLv3 enabled in $conf" \
        "Deprecated protocols allow POODLE/DROWN attacks"
    else
      record_check "crypto" "CR-002" "CRITICAL" "PASS" "No SSLv2/SSLv3 in $conf" ""
    fi
  done

  # Weak cipher check in common tls configs
  for conf in /etc/nginx/nginx.conf /etc/apache2/sites-enabled/*.conf; do
    [[ -f "$conf" ]] || continue
    if grep -qiE "(RC4|DES|EXPORT|NULL|anon|MD5)" "$conf" 2>/dev/null; then
      record_check "crypto" "CR-003" "HIGH" "FAIL" "Weak TLS ciphers in $conf" \
        "RC4/DES/EXPORT ciphers detected — remove from cipher suite"
    fi
  done

  # GRUB password set?
  if [[ -f /boot/grub/grub.cfg ]] || [[ -f /boot/grub2/grub.cfg ]]; then
    local grub_cfg
    grub_cfg=$(ls /boot/grub/grub.cfg /boot/grub2/grub.cfg 2>/dev/null | head -1)
    if grep -q "password_pbkdf2\|password " "$grub_cfg" 2>/dev/null; then
      record_check "crypto" "CR-004" "MEDIUM" "PASS" "GRUB bootloader password is configured" ""
    else
      record_check "crypto" "CR-004" "MEDIUM" "WARN" "GRUB bootloader password not set" \
        "Without GRUB password, physical access allows single-user mode bypass"
    fi
  fi

  # /etc/ssh/ssh_host_* key strength
  for keyfile in /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_ecdsa_key; do
    if [[ -f "$keyfile" ]]; then
      local bits
      bits=$(ssh-keygen -l -f "$keyfile" 2>/dev/null | awk '{print $1}')
      if echo "$keyfile" | grep -q "rsa" && [[ -n "$bits" && "$bits" -lt 3072 ]]; then
        record_check "crypto" "CR-005" "HIGH" "WARN" "SSH RSA host key < 3072 bits" \
          "$keyfile: ${bits} bits (recommend 4096+)"
      else
        record_check "crypto" "CR-005" "HIGH" "PASS" "SSH host key strength adequate" \
          "$keyfile: ${bits:-unknown} bits"
      fi
    fi
  done
}

# =============================================================================
# Module: cron
# =============================================================================
audit_cron() {
  print_section "CRON & SCHEDULED TASKS"

  # World-writable cron directories
  for crondir in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.hourly /etc/cron.monthly; do
    [[ -d "$crondir" ]] || continue
    local perms
    perms=$(stat -c "%a" "$crondir")
    if [[ "$perms" -gt 755 ]]; then
      record_check "cron" "CR-001" "HIGH" "FAIL" "Cron directory $crondir has excessive permissions" \
        "Permissions: $perms — world/group writable cron paths allow persistence"
    else
      record_check "cron" "CR-001" "HIGH" "PASS" "Cron directory $crondir permissions OK" "$perms"
    fi
  done

  # Root crontab — check for downloads, wget, curl, base64 (common malware IOCs)
  local root_cron
  root_cron=$(crontab -l -u root 2>/dev/null || cat /var/spool/cron/crontabs/root 2>/dev/null || echo "")
  if [[ -n "$root_cron" ]]; then
    if echo "$root_cron" | grep -qiE "(wget|curl|base64|nc |netcat|/tmp/|bash -i|/dev/tcp)"; then
      record_check "cron" "CR-002" "CRITICAL" "FAIL" "Suspicious commands in root crontab" \
        "$(echo "$root_cron" | grep -iE "wget|curl|base64|nc |netcat|/tmp/" | head -3 | tr '\n' ';')"
    else
      record_check "cron" "CR-002" "CRITICAL" "PASS" "Root crontab has no obviously suspicious commands" ""
    fi
  else
    record_check "cron" "CR-002" "CRITICAL" "PASS" "No root crontab entries found" ""
  fi

  # /etc/crontab permissions
  if [[ -f /etc/crontab ]]; then
    local crontab_perms
    crontab_perms=$(stat -c "%a %U" /etc/crontab)
    if echo "$crontab_perms" | grep -q "^644 root\|^640 root\|^600 root"; then
      record_check "cron" "CR-003" "HIGH" "PASS" "/etc/crontab permissions correct" "$crontab_perms"
    else
      record_check "cron" "CR-003" "HIGH" "FAIL" "/etc/crontab permissions incorrect" \
        "$crontab_perms — should be 644 or stricter, owned by root"
    fi
  fi

  # Check cron.d scripts for world-writable
  local ww_cron
  ww_cron=$(find /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.hourly /etc/cron.monthly \
    -type f -perm -002 2>/dev/null)
  if [[ -n "$ww_cron" ]]; then
    record_check "cron" "CR-004" "CRITICAL" "FAIL" "World-writable cron scripts detected" \
      "$ww_cron"
  else
    record_check "cron" "CR-004" "CRITICAL" "PASS" "No world-writable cron scripts found" ""
  fi

  # at.allow / at.deny
  if [[ -f /etc/at.allow ]]; then
    record_check "cron" "CR-005" "MEDIUM" "PASS" "at.allow exists — 'at' access restricted" ""
  else
    record_check "cron" "CR-005" "MEDIUM" "WARN" "No /etc/at.allow — all users may use 'at'" \
      "Create /etc/at.allow with allowed users only"
  fi
}
