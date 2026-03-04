#!/usr/bin/env bash
# Module: containers — Docker, namespaces, and container escape vectors

audit_containers() {
  print_section "CONTAINERS"

  # Docker socket world-accessible?
  if [[ -S /var/run/docker.sock ]]; then
    local sock_perms
    sock_perms=$(stat -c "%a %G" /var/run/docker.sock 2>/dev/null)
    if echo "$sock_perms" | grep -qE "^(66[0-9]|67[0-9]|6[7-9][0-9]|[7-9][0-9]{2})"; then
      record_check "containers" "C-001" "CRITICAL" "FAIL" "Docker socket world/group accessible" \
        "/var/run/docker.sock perms: $sock_perms — group docker = container escape to root"
    else
      record_check "containers" "C-001" "CRITICAL" "PASS" "Docker socket permissions restricted" \
        "/var/run/docker.sock perms: $sock_perms"
    fi

    # Who is in docker group?
    local docker_users
    docker_users=$(getent group docker 2>/dev/null | cut -d: -f4)
    if [[ -n "$docker_users" ]]; then
      record_check "containers" "C-002" "HIGH" "WARN" "Users in docker group (effective root)" \
        "Members: $docker_users — docker group = trivial root via container mount"
    else
      record_check "containers" "C-002" "HIGH" "PASS" "No non-root users in docker group" ""
    fi

    # Rootless Docker?
    if docker info 2>/dev/null | grep -q "rootless"; then
      record_check "containers" "C-003" "HIGH" "PASS" "Docker running in rootless mode" ""
    else
      record_check "containers" "C-003" "HIGH" "WARN" "Docker NOT in rootless mode" \
        "Consider switching to rootless Docker: dockerd-rootless-setuptool.sh install"
    fi
  else
    record_check "containers" "C-001" "CRITICAL" "PASS" "Docker socket not present" ""
  fi

  # Are we inside a container?
  if [[ -f /.dockerenv ]] || grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    record_check "containers" "C-004" "INFO" "WARN" "Running INSIDE a container environment" \
      "Check for container escape vectors if this audit is from within a container"

    # Privileged container check
    if [[ -d /sys/kernel/security/apparmor ]] && cat /proc/self/status 2>/dev/null | grep -q "CapEff:\s*0000003fffffffff"; then
      record_check "containers" "C-005" "CRITICAL" "FAIL" "Possibly running as privileged container" \
        "Full capabilities detected — privileged container allows host escape"
    fi
  fi

  # Seccomp default profile active?
  if [[ -f /proc/self/status ]]; then
    local seccomp_status
    seccomp_status=$(grep -i "Seccomp:" /proc/self/status 2>/dev/null | awk '{print $2}')
    if [[ "$seccomp_status" == "2" ]]; then
      record_check "containers" "C-006" "HIGH" "PASS" "Seccomp filter is active" "Seccomp mode: $seccomp_status"
    elif [[ "$seccomp_status" == "0" ]]; then
      record_check "containers" "C-006" "HIGH" "WARN" "Seccomp not enabled for this process" \
        "Seccomp mode: $seccomp_status — syscall filtering inactive"
    fi
  fi

  # AppArmor status
  if command -v apparmor_status &>/dev/null; then
    local aa_status
    aa_status=$(apparmor_status --enabled 2>/dev/null && echo "enabled" || echo "disabled")
    if [[ "$aa_status" == "enabled" ]]; then
      record_check "containers" "C-007" "HIGH" "PASS" "AppArmor is enabled" ""
    else
      record_check "containers" "C-007" "HIGH" "FAIL" "AppArmor is disabled" \
        "Enable AppArmor: systemctl enable --now apparmor"
    fi
  elif command -v sestatus &>/dev/null; then
    local se_status
    se_status=$(sestatus 2>/dev/null | grep "SELinux status" | awk '{print $3}')
    if [[ "$se_status" == "enabled" ]]; then
      record_check "containers" "C-007" "HIGH" "PASS" "SELinux is enabled" ""
    else
      record_check "containers" "C-007" "HIGH" "FAIL" "SELinux is disabled" \
        "SELinux status: $se_status"
    fi
  else
    record_check "containers" "C-007" "HIGH" "WARN" "No MAC framework (AppArmor/SELinux) detected" \
      "Mandatory access control not active — reduced containment"
  fi
}
