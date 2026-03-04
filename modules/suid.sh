#!/usr/bin/env bash
# Module: suid — SUID/SGID binary and capabilities audit

# Known-safe SUID binaries (common, expected)
EXPECTED_SUID=(
  /bin/su /usr/bin/su /bin/sudo /usr/bin/sudo
  /bin/mount /usr/bin/mount /bin/umount /usr/bin/umount
  /usr/bin/passwd /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp
  /usr/bin/pkexec /usr/bin/gpasswd
  /bin/ping /usr/bin/ping /usr/bin/traceroute6.iputils
  /usr/sbin/pppd /usr/lib/openssh/ssh-keysign
  /usr/lib/dbus-1.0/dbus-daemon-launch-helper
  /usr/lib/eject/dmcrypt-get-device
  /usr/bin/at /usr/bin/crontab
)

audit_suid() {
  print_section "SUID/SGID & CAPABILITIES"

  # Find all SUID binaries
  local suid_bins
  suid_bins=$(find / -xdev -type f -perm -4000 2>/dev/null \
    ! -path "/proc/*" ! -path "/sys/*" ! -path "/snap/*")

  local unexpected=()
  while IFS= read -r bin; do
    local is_expected=false
    for expected in "${EXPECTED_SUID[@]}"; do
      [[ "$bin" == "$expected" ]] && { is_expected=true; break; }
    done
    $is_expected || unexpected+=("$bin")
  done <<< "$suid_bins"

  local total_suid
  total_suid=$(echo "$suid_bins" | grep -c "." 2>/dev/null || echo 0)
  record_check "suid" "SU-000" "INFO" "INFO" "Total SUID binaries found: $total_suid" \
    "$(echo "$suid_bins" | tr '\n' ' ' | head -c 300)"

  if [[ ${#unexpected[@]} -gt 0 ]]; then
    record_check "suid" "SU-001" "HIGH" "FAIL" "Unexpected SUID binaries detected" \
      "${unexpected[*]}"
  else
    record_check "suid" "SU-001" "HIGH" "PASS" "All SUID binaries are expected/known" ""
  fi

  # SGID binaries
  local sgid_bins
  sgid_bins=$(find / -xdev -type f -perm -2000 2>/dev/null \
    ! -path "/proc/*" ! -path "/sys/*" ! -path "/snap/*" | head -20)
  if [[ -n "$sgid_bins" ]]; then
    record_check "suid" "SU-002" "MEDIUM" "WARN" "SGID binaries present (review each)" \
      "$(echo "$sgid_bins" | tr '\n' ' ' | head -c 300)"
  else
    record_check "suid" "SU-002" "MEDIUM" "PASS" "No unexpected SGID binaries found" ""
  fi

  # Capabilities audit
  if command -v getcap &>/dev/null; then
    local caps
    caps=$(getcap -r / 2>/dev/null | grep -v "^$" || echo "")
    if [[ -n "$caps" ]]; then
      # Flag dangerous caps
      local dangerous_caps=()
      while IFS= read -r cap_line; do
        echo "$cap_line" | grep -qiE "(cap_net_admin|cap_sys_admin|cap_sys_ptrace|cap_dac_override|cap_setuid|cap_setgid|cap_net_raw)" \
          && dangerous_caps+=("$cap_line")
      done <<< "$caps"

      if [[ ${#dangerous_caps[@]} -gt 0 ]]; then
        record_check "suid" "SU-003" "CRITICAL" "FAIL" "Binaries with dangerous Linux capabilities" \
          "$(printf '%s\n' "${dangerous_caps[@]}" | head -5 | tr '\n' ' ')"
      else
        record_check "suid" "SU-003" "CRITICAL" "PASS" "No binaries with dangerous capabilities" \
          "$(echo "$caps" | wc -l) cap entries found, none flagged as critical"
      fi
    else
      record_check "suid" "SU-003" "CRITICAL" "PASS" "No elevated file capabilities set" ""
    fi
  else
    record_check "suid" "SU-003" "CRITICAL" "WARN" "getcap not available — capability audit skipped" ""
  fi

  # GTFOBins-like check: common sudo-exploitable SUID bins
  local gtfo_risky=(python python3 perl ruby lua node php vim nano more less find awk nmap nohup strace)
  local gtfo_found=()
  for bin in "${gtfo_risky[@]}"; do
    local full_path
    full_path=$(command -v "$bin" 2>/dev/null || echo "")
    [[ -z "$full_path" ]] && continue
    if [[ -u "$full_path" ]]; then
      gtfo_found+=("$bin ($full_path)")
    fi
  done
  if [[ ${#gtfo_found[@]} -gt 0 ]]; then
    record_check "suid" "SU-004" "CRITICAL" "FAIL" "GTFOBins-exploitable SUID binaries found" \
      "${gtfo_found[*]}"
  else
    record_check "suid" "SU-004" "CRITICAL" "PASS" "No GTFOBins-exploitable SUID binaries detected" ""
  fi

  # Check if /usr/bin/pkexec is vulnerable (Polkit CVE-2021-4034 / PwnKit)
  if [[ -f /usr/bin/pkexec ]]; then
    local pkexec_ver
    pkexec_ver=$(pkexec --version 2>/dev/null | grep -oP '\d+\.\d+(\.\d+)?' | head -1)
    record_check "suid" "SU-005" "HIGH" "WARN" "pkexec (polkit) present — verify CVE-2021-4034 patch" \
      "Version: ${pkexec_ver:-unknown}. Patched in polkit >= 0.120"
  else
    record_check "suid" "SU-005" "HIGH" "PASS" "pkexec (polkit) not installed" ""
  fi
}
