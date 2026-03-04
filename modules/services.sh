#!/usr/bin/env bash
# Module: services — Running services & daemon exposure

audit_services() {
  print_section "SERVICES"

  # Risky services that should not normally be running
  local risky_services=(telnet rsh rlogin rexec tftp xinetd finger r-services
                         rsyncd nfs-server smbd nmbd snmpd vsftpd ftpd proftpd
                         avahi-daemon cups sendmail postfix exim dovecot)

  for svc in "${risky_services[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      record_check "services" "SVC-001" "HIGH" "FAIL" "Risky service is running: $svc" \
        "Disable with: systemctl disable --now $svc"
    fi
  done

  # Telnet port check
  if ss -tlnp 2>/dev/null | grep -q ":23 "; then
    record_check "services" "SVC-002" "CRITICAL" "FAIL" "Telnet port (23) is open" \
      "Telnet transmits credentials in plaintext — disable immediately"
  else
    record_check "services" "SVC-002" "CRITICAL" "PASS" "Telnet port (23) not listening" ""
  fi

  # FTP check
  if ss -tlnp 2>/dev/null | grep -q ":21 "; then
    record_check "services" "SVC-003" "HIGH" "FAIL" "FTP port (21) is open" \
      "FTP transmits credentials in plaintext — use SFTP instead"
  else
    record_check "services" "SVC-003" "HIGH" "PASS" "FTP port (21) not listening" ""
  fi

  # Unused services enabled at boot
  local enabled_count
  enabled_count=$(systemctl list-unit-files --state=enabled 2>/dev/null | grep -c "enabled" || echo "0")
  if [[ "$enabled_count" -gt 30 ]]; then
    record_check "services" "SVC-004" "LOW" "WARN" "High number of enabled services ($enabled_count)" \
      "Review with: systemctl list-unit-files --state=enabled"
  else
    record_check "services" "SVC-004" "LOW" "PASS" "Enabled service count reasonable ($enabled_count)" ""
  fi
}
