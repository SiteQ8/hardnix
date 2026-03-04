#!/usr/bin/env bash
# Module: ssh — SSH daemon hardening checks

audit_ssh() {
  print_section "SSH DAEMON"

  local sshd_config="/etc/ssh/sshd_config"

  if [[ ! -f "$sshd_config" ]]; then
    record_check "ssh" "SSH-000" "INFO" "WARN" "sshd_config not found — SSH may not be installed" ""
    return
  fi

  # Helper: parse sshd config (handles Include directives naively)
  get_ssh_param() {
    local key="$1"
    grep -iE "^\s*${key}\s+" "$sshd_config" 2>/dev/null \
      | tail -1 | awk '{print $2}' | tr '[:upper:]' '[:lower:]'
  }

  ssh_check() {
    local id="$1" sev="$2" title="$3" key="$4" bad_val="$5" good_val="$6"
    local val
    val=$(get_ssh_param "$key")
    val="${val:-$good_val}"  # treat absence as default (safe default = good_val)
    if [[ "$val" == "$bad_val" ]]; then
      record_check "ssh" "$id" "$sev" "FAIL" "$title" "$key = $val"
    else
      record_check "ssh" "$id" "$sev" "PASS" "$title" "$key = ${val:-<default>}"
    fi
  }

  ssh_check "S-001" "CRITICAL" "Root login disabled"                    PermitRootLogin    "yes"        "no"
  ssh_check "S-002" "HIGH"     "Password authentication disabled"       PasswordAuthentication "yes"    "no"
  ssh_check "S-003" "CRITICAL" "Empty passwords rejected"               PermitEmptyPasswords   "yes"   "no"
  ssh_check "S-004" "HIGH"     "Challenge-response auth disabled"       ChallengeResponseAuthentication "yes" "no"
  ssh_check "S-005" "MEDIUM"   "X11 forwarding disabled"                X11Forwarding      "yes"        "no"
  ssh_check "S-006" "MEDIUM"   "Agent forwarding disabled"              AllowAgentForwarding "yes"      "no"
  ssh_check "S-007" "MEDIUM"   "TCP forwarding disabled"                AllowTcpForwarding "yes"        "no"
  ssh_check "S-008" "LOW"      "Compression disabled (post-auth)"       Compression        "yes"        "no"
  ssh_check "S-009" "LOW"      "UseDNS disabled (performance)"          UseDNS             "yes"        "no"

  # Protocol version
  local proto
  proto=$(get_ssh_param "Protocol")
  if [[ "$proto" == "1" ]]; then
    record_check "ssh" "S-010" "CRITICAL" "FAIL" "SSHv1 is ENABLED" "Protocol = 1 — SSHv1 is cryptographically broken"
  else
    record_check "ssh" "S-010" "CRITICAL" "PASS" "SSH Protocol 2 only" "Protocol = ${proto:-2 (default)}"
  fi

  # MaxAuthTries
  local max_tries
  max_tries=$(get_ssh_param "MaxAuthTries")
  max_tries="${max_tries:-6}"
  if [[ "$max_tries" -gt 4 ]]; then
    record_check "ssh" "S-011" "MEDIUM" "FAIL" "MaxAuthTries too high (brute-force risk)" \
      "MaxAuthTries = $max_tries (recommend ≤ 4)"
  else
    record_check "ssh" "S-011" "MEDIUM" "PASS" "MaxAuthTries acceptable" "MaxAuthTries = $max_tries"
  fi

  # ClientAliveInterval / Timeout
  local cai
  cai=$(get_ssh_param "ClientAliveInterval")
  if [[ -z "$cai" || "$cai" -eq 0 ]]; then
    record_check "ssh" "S-012" "LOW" "WARN" "No idle session timeout configured" \
      "ClientAliveInterval not set — idle sessions may persist indefinitely"
  else
    record_check "ssh" "S-012" "LOW" "PASS" "Idle session timeout set" "ClientAliveInterval = $cai"
  fi

  # LoginGraceTime
  local lgt
  lgt=$(get_ssh_param "LoginGraceTime")
  lgt="${lgt:-120}"
  if [[ "$lgt" -gt 60 ]]; then
    record_check "ssh" "S-013" "LOW" "WARN" "LoginGraceTime high (DoS risk)" \
      "LoginGraceTime = ${lgt}s (recommend ≤ 30)"
  else
    record_check "ssh" "S-013" "LOW" "PASS" "LoginGraceTime acceptable" "LoginGraceTime = ${lgt}s"
  fi

  # Ciphers — flag weak ones
  local ciphers
  ciphers=$(grep -i "^Ciphers" "$sshd_config" 2>/dev/null | awk '{$1=""; print}' | xargs)
  if echo "$ciphers" | grep -qiE "(arcfour|3des|blowfish|cast|rc4|des)"; then
    record_check "ssh" "S-014" "HIGH" "FAIL" "Weak SSH ciphers configured" \
      "Weak cipher detected: $ciphers"
  else
    record_check "ssh" "S-014" "HIGH" "PASS" "No obviously weak SSH ciphers" \
      "${ciphers:-<server defaults>}"
  fi

  # MACs — flag weak ones
  local macs
  macs=$(grep -i "^MACs" "$sshd_config" 2>/dev/null | awk '{$1=""; print}' | xargs)
  if echo "$macs" | grep -qiE "(md5|sha1[^-]|umac-64[^@])"; then
    record_check "ssh" "S-015" "HIGH" "FAIL" "Weak SSH MACs configured" \
      "Weak MAC detected: $macs"
  else
    record_check "ssh" "S-015" "HIGH" "PASS" "No obviously weak SSH MACs" \
      "${macs:-<server defaults>}"
  fi

  # StrictModes
  local strict
  strict=$(get_ssh_param "StrictModes")
  strict="${strict:-yes}"
  if [[ "$strict" == "no" ]]; then
    record_check "ssh" "S-016" "MEDIUM" "FAIL" "StrictModes disabled" \
      "File permission checks bypassed — misconfig may allow unauthorized keys"
  else
    record_check "ssh" "S-016" "MEDIUM" "PASS" "StrictModes enabled" ""
  fi

  # Check port is non-default (obscurity, but still common ask)
  local port
  port=$(get_ssh_param "Port")
  port="${port:-22}"
  if [[ "$port" == "22" ]]; then
    record_check "ssh" "S-017" "LOW" "WARN" "SSH running on default port 22" \
      "Consider moving to non-standard port to reduce automated scanning noise"
  else
    record_check "ssh" "S-017" "LOW" "PASS" "SSH on non-default port" "Port = $port"
  fi

  # AllowUsers / AllowGroups set?
  if grep -qiE "^\s*(AllowUsers|AllowGroups)" "$sshd_config" 2>/dev/null; then
    record_check "ssh" "S-018" "MEDIUM" "PASS" "SSH access restricted via AllowUsers/AllowGroups" ""
  else
    record_check "ssh" "S-018" "MEDIUM" "WARN" "No AllowUsers/AllowGroups configured" \
      "Any system user may attempt SSH login — restrict with AllowUsers or AllowGroups"
  fi
}
