#!/usr/bin/env bash
# Module: network — Network stack hardening checks

audit_network() {
  print_section "NETWORK HARDENING"

  sysctl_net() {
    local id="$1" sev="$2" title="$3" key="$4" expected="$5"
    local val
    val=$(sysctl -n "$key" 2>/dev/null || echo "UNAVAILABLE")
    if [[ "$val" == "UNAVAILABLE" ]]; then
      record_check "network" "$id" "$sev" "WARN" "$title" "sysctl $key not available"
    elif [[ "$val" == "$expected" ]]; then
      record_check "network" "$id" "$sev" "PASS" "$title" "$key = $val"
    else
      record_check "network" "$id" "$sev" "FAIL" "$title" "$key = $val (expected $expected)"
    fi
  }

  # IP forwarding (router behavior — usually bad on workstations/servers)
  sysctl_net "N-001" "HIGH"   "IPv4 forwarding disabled"                      net.ipv4.ip_forward                     "0"
  sysctl_net "N-002" "HIGH"   "IPv6 forwarding disabled"                      net.ipv6.conf.all.forwarding             "0"
  # Source routing
  sysctl_net "N-003" "HIGH"   "Source routing disabled (all)"                 net.ipv4.conf.all.accept_source_route    "0"
  sysctl_net "N-004" "HIGH"   "Source routing disabled (default)"             net.ipv4.conf.default.accept_source_route "0"
  # ICMP redirect acceptance
  sysctl_net "N-005" "MEDIUM" "ICMP redirect acceptance disabled (all)"       net.ipv4.conf.all.accept_redirects       "0"
  sysctl_net "N-006" "MEDIUM" "ICMP redirect acceptance disabled (default)"   net.ipv4.conf.default.accept_redirects   "0"
  sysctl_net "N-007" "MEDIUM" "Secure ICMP redirects disabled"                net.ipv4.conf.all.secure_redirects       "0"
  # ICMP redirect sending (avoid acting as MITM)
  sysctl_net "N-008" "MEDIUM" "ICMP redirect sending disabled"                net.ipv4.conf.all.send_redirects         "0"
  # Log martians
  sysctl_net "N-009" "LOW"    "Log martian packets enabled"                   net.ipv4.conf.all.log_martians           "1"
  # SYN cookies (SYN flood protection)
  sysctl_net "N-010" "HIGH"   "SYN cookies enabled (SYN flood protection)"   net.ipv4.tcp_syncookies                  "1"
  # TCP timestamps (side-channel)
  sysctl_net "N-011" "LOW"    "TCP timestamps disabled (info leak)"           net.ipv4.tcp_timestamps                  "0"
  # Reverse path filtering (anti-spoofing)
  sysctl_net "N-012" "HIGH"   "Reverse path filtering strict mode (all)"      net.ipv4.conf.all.rp_filter              "1"
  sysctl_net "N-013" "HIGH"   "Reverse path filtering strict mode (default)"  net.ipv4.conf.default.rp_filter          "1"
  # IPv6 router advertisements
  sysctl_net "N-014" "MEDIUM" "IPv6 router advertisements ignored"            net.ipv6.conf.all.accept_ra              "0"
  # ARP ignore/announce
  sysctl_net "N-015" "MEDIUM" "ARP announce strict (prevent ARP poisoning)"  net.ipv4.conf.all.arp_announce           "2"

  # Firewall status
  local fw_active=false
  if command -v ufw &>/dev/null; then
    local ufw_status
    ufw_status=$(ufw status 2>/dev/null | head -1)
    if echo "$ufw_status" | grep -qi "active"; then
      record_check "network" "N-016" "CRITICAL" "PASS" "UFW firewall is active" "$ufw_status"
      fw_active=true
    else
      record_check "network" "N-016" "CRITICAL" "FAIL" "UFW firewall is INACTIVE" "$ufw_status"
    fi
  fi

  if command -v firewall-cmd &>/dev/null; then
    local fwd_status
    fwd_status=$(firewall-cmd --state 2>/dev/null || echo "not running")
    if [[ "$fwd_status" == "running" ]]; then
      record_check "network" "N-016b" "CRITICAL" "PASS" "firewalld is active" ""
      fw_active=true
    else
      record_check "network" "N-016b" "CRITICAL" "FAIL" "firewalld is NOT running" "$fwd_status"
    fi
  fi

  if ! $fw_active; then
    # Check raw iptables
    if command -v iptables &>/dev/null; then
      local ipt_rules
      ipt_rules=$(iptables -L 2>/dev/null | grep -c "^ACCEPT\|^DROP\|^REJECT" || echo "0")
      if [[ "$ipt_rules" -gt 2 ]]; then
        record_check "network" "N-016c" "CRITICAL" "PASS" "iptables rules present" "$ipt_rules filtering rules found"
      else
        record_check "network" "N-016c" "CRITICAL" "FAIL" "No effective firewall detected" \
          "No ufw/firewalld/iptables rules — system is fully exposed"
      fi
    fi
  fi

  # Check for open ports (services listening externally)
  if command -v ss &>/dev/null; then
    local listening_external
    listening_external=$(ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1\|0.0.0.0:22 \|:::22 " | grep "LISTEN" | tail -n +2 || echo "")
    local count
    count=$(echo "$listening_external" | grep -c "." || echo "0")
    if [[ "$count" -gt 0 ]]; then
      record_check "network" "N-017" "HIGH" "WARN" "Non-SSH services listening on external interfaces" \
        "$(echo "$listening_external" | awk '{print $5}' | tr '\n' ' ' | head -c 200)"
    else
      record_check "network" "N-017" "HIGH" "PASS" "Minimal external listening services detected" ""
    fi
  fi
}
