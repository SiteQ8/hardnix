#!/usr/bin/env bash
# Module: users — User account, sudo, and privilege audit

audit_users() {
  print_section "USERS & PRIVILEGES"

  # UID 0 accounts (other than root)
  local uid0_accounts
  uid0_accounts=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
  if [[ -n "$uid0_accounts" ]]; then
    record_check "users" "U-001" "CRITICAL" "FAIL" "Non-root accounts with UID 0 detected" \
      "Accounts: $uid0_accounts"
  else
    record_check "users" "U-001" "CRITICAL" "PASS" "No unexpected UID 0 accounts" ""
  fi

  # Accounts with empty passwords
  local empty_pass
  empty_pass=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") && $1 != "" {print $1}' /etc/shadow 2>/dev/null || echo "")
  if [[ -n "$empty_pass" ]]; then
    record_check "users" "U-002" "CRITICAL" "FAIL" "Accounts with empty/locked passwords" \
      "Accounts: $empty_pass"
  else
    record_check "users" "U-002" "CRITICAL" "PASS" "No accounts with empty passwords" ""
  fi

  # Accounts with shell but no password hash (password set to '*' or '!')
  local no_pass_shell
  no_pass_shell=$(awk -F: 'NR==FNR{a[$1]=$2;next} $7!~/nologin|false|sync/ && a[$1]~/^\*|^!/{print $1}' \
    /etc/shadow /etc/passwd 2>/dev/null || echo "")
  if [[ -n "$no_pass_shell" ]]; then
    record_check "users" "U-003" "HIGH" "WARN" "Shell accounts with locked passwords (verify)" \
      "Accounts: $no_pass_shell — ensure not accessible via key-only"
  else
    record_check "users" "U-003" "HIGH" "PASS" "No shell accounts with locked passwords needing review" ""
  fi

  # Sudoers — NOPASSWD entries
  local nopasswd
  nopasswd=$(grep -rE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "")
  if [[ -n "$nopasswd" ]]; then
    record_check "users" "U-004" "HIGH" "FAIL" "NOPASSWD sudo entries found" \
      "$(echo "$nopasswd" | head -5 | tr '\n' ';')"
  else
    record_check "users" "U-004" "HIGH" "PASS" "No NOPASSWD sudo entries" ""
  fi

  # Sudo ALL=(ALL) ALL (unlimited sudo)
  local sudo_all
  sudo_all=$(grep -rE "^\s*[^#].*ALL\s*=\s*\(ALL\)\s*ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo "")
  if [[ -n "$sudo_all" ]]; then
    record_check "users" "U-005" "HIGH" "WARN" "Unrestricted sudo (ALL:ALL) granted" \
      "$(echo "$sudo_all" | tr '\n' ';')"
  else
    record_check "users" "U-005" "HIGH" "PASS" "No unrestricted ALL:ALL sudo grants" ""
  fi

  # visudo secure path
  local secure_path
  secure_path=$(grep "secure_path" /etc/sudoers 2>/dev/null || echo "")
  if [[ -z "$secure_path" ]]; then
    record_check "users" "U-006" "MEDIUM" "WARN" "sudo secure_path not configured" \
      "Without secure_path, sudo inherits user's PATH — potential hijack vector"
  else
    record_check "users" "U-006" "MEDIUM" "PASS" "sudo secure_path configured" "$secure_path"
  fi

  # Check for world-writable home directories
  local ww_homes=()
  while IFS= read -r home; do
    [[ -d "$home" ]] && [[ "$(stat -c '%a' "$home" 2>/dev/null)" =~ [2367]$ ]] && ww_homes+=("$home")
  done < <(awk -F: '$3 >= 1000 && $6 != "/dev/null" {print $6}' /etc/passwd 2>/dev/null)
  if [[ ${#ww_homes[@]} -gt 0 ]]; then
    record_check "users" "U-007" "HIGH" "FAIL" "World-writable home directories found" \
      "${ww_homes[*]}"
  else
    record_check "users" "U-007" "HIGH" "PASS" "No world-writable home directories" ""
  fi

  # Password aging policy
  local max_days
  max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
  if [[ -z "$max_days" || "$max_days" -gt 90 ]]; then
    record_check "users" "U-008" "MEDIUM" "WARN" "Password max age not enforced (>90 days or unset)" \
      "PASS_MAX_DAYS = ${max_days:-unset} in /etc/login.defs"
  else
    record_check "users" "U-008" "MEDIUM" "PASS" "Password max age configured" "PASS_MAX_DAYS = $max_days"
  fi

  # MIN password length
  local min_len
  min_len=$(grep "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
  if [[ -z "$min_len" || "$min_len" -lt 12 ]]; then
    record_check "users" "U-009" "MEDIUM" "WARN" "Minimum password length not enforced (< 12)" \
      "PASS_MIN_LEN = ${min_len:-unset}"
  else
    record_check "users" "U-009" "MEDIUM" "PASS" "Minimum password length configured" "PASS_MIN_LEN = $min_len"
  fi

  # Accounts with interactive shell that shouldn't have one
  local svc_with_shell
  svc_with_shell=$(awk -F: '$3 > 0 && $3 < 1000 && $7 !~ /nologin|false|sync|halt|shutdown/ {print $1 " ("$7")"}' \
    /etc/passwd 2>/dev/null || echo "")
  if [[ -n "$svc_with_shell" ]]; then
    record_check "users" "U-010" "HIGH" "WARN" "System/service accounts with interactive shells" \
      "$(echo "$svc_with_shell" | head -5 | tr '\n' ' ')"
  else
    record_check "users" "U-010" "HIGH" "PASS" "No system accounts with interactive shells" ""
  fi

  # Root account password directly usable (vs locked)
  local root_pass_status
  root_pass_status=$(passwd -S root 2>/dev/null | awk '{print $2}')
  if [[ "$root_pass_status" == "L" || "$root_pass_status" == "LK" ]]; then
    record_check "users" "U-011" "MEDIUM" "PASS" "Root account password is locked (sudo-only access)" ""
  else
    record_check "users" "U-011" "MEDIUM" "WARN" "Root account has a usable password" \
      "Consider locking root and enforcing sudo-only: passwd -l root"
  fi
}
