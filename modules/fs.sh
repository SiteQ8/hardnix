#!/usr/bin/env bash
# Module: fs — Filesystem permissions and mount hardening

audit_fs() {
  print_section "FILESYSTEM"

  # /tmp noexec, nosuid, nodev
  for opt in noexec nosuid nodev; do
    if mount | grep -E "\s/tmp\s" | grep -q "$opt"; then
      record_check "fs" "FS-001" "HIGH" "PASS" "/tmp mounted with $opt" ""
    else
      record_check "fs" "FS-001" "HIGH" "FAIL" "/tmp NOT mounted with $opt" \
        "Mount /tmp with $opt to prevent code execution from /tmp"
    fi
  done

  # /var/tmp noexec
  if mount | grep -E "\s/var/tmp\s" | grep -q "noexec"; then
    record_check "fs" "FS-002" "MEDIUM" "PASS" "/var/tmp mounted noexec" ""
  else
    record_check "fs" "FS-002" "MEDIUM" "WARN" "/var/tmp may not be noexec" \
      "Consider separate noexec mount for /var/tmp"
  fi

  # /home nosuid, nodev
  for opt in nosuid nodev; do
    if mount | grep -E "\s/home\s" | grep -q "$opt"; then
      record_check "fs" "FS-003" "MEDIUM" "PASS" "/home mounted with $opt" ""
    else
      record_check "fs" "FS-003" "MEDIUM" "WARN" "/home may not have $opt mount option" \
        "Recommended: mount /home with nosuid,nodev"
    fi
  done

  # World-writable files (not sticky bit, not /proc /sys /dev /run)
  if [[ $EUID -eq 0 ]]; then
    local ww_files
    ww_files=$(find / -xdev -maxdepth 8 -type f -perm -002 \
      ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" \
      2>/dev/null | head -20)
    if [[ -n "$ww_files" ]]; then
      record_check "fs" "FS-004" "HIGH" "FAIL" "World-writable files found outside /proc/sys/dev" \
        "$(echo "$ww_files" | head -5 | tr '\n' ' ') ..."
    else
      record_check "fs" "FS-004" "HIGH" "PASS" "No world-writable files found" ""
    fi
  else
    record_check "fs" "FS-004" "HIGH" "WARN" "Skipped world-writable file scan (needs root)" ""
  fi

  # World-writable directories without sticky bit
  local ww_dirs
  ww_dirs=$(find /etc /var /usr -xdev -type d -perm -002 ! -perm -1000 2>/dev/null | head -10)
  if [[ -n "$ww_dirs" ]]; then
    record_check "fs" "FS-005" "HIGH" "FAIL" "World-writable directories without sticky bit" \
      "$(echo "$ww_dirs" | tr '\n' ' ')"
  else
    record_check "fs" "FS-005" "HIGH" "PASS" "No unprotected world-writable directories in /etc /var /usr" ""
  fi

  # /etc/passwd permissions
  local passwd_perms
  passwd_perms=$(stat -c "%a" /etc/passwd 2>/dev/null)
  if [[ "$passwd_perms" == "644" ]]; then
    record_check "fs" "FS-006" "HIGH" "PASS" "/etc/passwd permissions correct (644)" ""
  else
    record_check "fs" "FS-006" "HIGH" "FAIL" "/etc/passwd permissions incorrect" \
      "Permissions: $passwd_perms (expected 644)"
  fi

  # /etc/shadow permissions
  local shadow_perms
  shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
  if [[ "$shadow_perms" == "640" || "$shadow_perms" == "600" || "$shadow_perms" == "000" ]]; then
    record_check "fs" "FS-007" "CRITICAL" "PASS" "/etc/shadow permissions correct ($shadow_perms)" ""
  else
    record_check "fs" "FS-007" "CRITICAL" "FAIL" "/etc/shadow has excessive permissions" \
      "Permissions: $shadow_perms (expected 640 or stricter)"
  fi

  # /etc/sudoers permissions
  local sudoers_perms
  sudoers_perms=$(stat -c "%a" /etc/sudoers 2>/dev/null)
  if [[ "$sudoers_perms" == "440" || "$sudoers_perms" == "400" ]]; then
    record_check "fs" "FS-008" "HIGH" "PASS" "/etc/sudoers permissions correct ($sudoers_perms)" ""
  else
    record_check "fs" "FS-008" "HIGH" "FAIL" "/etc/sudoers permissions incorrect" \
      "Permissions: $sudoers_perms (expected 440)"
  fi

  # Unowned files
  local unowned
  unowned=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null \
    ! -path "/proc/*" ! -path "/sys/*" | head -10)
  if [[ -n "$unowned" ]]; then
    record_check "fs" "FS-009" "MEDIUM" "WARN" "Unowned files/directories detected" \
      "$(echo "$unowned" | head -5 | tr '\n' ' ')"
  else
    record_check "fs" "FS-009" "MEDIUM" "PASS" "No unowned files found" ""
  fi

  # /etc writable by non-root?
  local etc_owner
  etc_owner=$(stat -c "%U:%G %a" /etc 2>/dev/null)
  if echo "$etc_owner" | grep -q "^root:root 755"; then
    record_check "fs" "FS-010" "HIGH" "PASS" "/etc owned by root:root with 755" "$etc_owner"
  else
    record_check "fs" "FS-010" "HIGH" "WARN" "/etc ownership or permissions unexpected" "$etc_owner"
  fi

  # /boot read-only or restricted?
  if mount | grep -E "\s/boot\s" | grep -q "ro"; then
    record_check "fs" "FS-011" "MEDIUM" "PASS" "/boot is mounted read-only" ""
  else
    record_check "fs" "FS-011" "MEDIUM" "WARN" "/boot is not mounted read-only" \
      "Consider mounting /boot ro to protect bootloader"
  fi
}
