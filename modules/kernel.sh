#!/usr/bin/env bash
# Module: kernel — Kernel parameter & memory protection checks

audit_kernel() {
  print_section "KERNEL HARDENING"

  # Helper: sysctl check
  sysctl_check() {
    local id="$1" sev="$2" title="$3" key="$4" expected="$5"
    local val
    val=$(sysctl -n "$key" 2>/dev/null || echo "UNAVAILABLE")
    if [[ "$val" == "UNAVAILABLE" ]]; then
      record_check "kernel" "$id" "$sev" "WARN" "$title" "sysctl key $key not found"
    elif [[ "$val" == "$expected" ]]; then
      record_check "kernel" "$id" "$sev" "PASS" "$title" "$key = $val"
    else
      record_check "kernel" "$id" "$sev" "FAIL" "$title" "$key = $val (expected $expected)"
    fi
  }

  # ASLR
  sysctl_check "K-001" "HIGH"     "ASLR enabled (full randomization)"         kernel.randomize_va_space        "2"
  # kptr restriction (hide kernel pointers from /proc)
  sysctl_check "K-002" "HIGH"     "Kernel pointer restriction (kptr_restrict)" kernel.kptr_restrict              "2"
  # dmesg restriction
  sysctl_check "K-003" "MEDIUM"   "dmesg restricted to root"                  kernel.dmesg_restrict             "1"
  # SysRq disabled
  sysctl_check "K-004" "MEDIUM"   "SysRq disabled"                            kernel.sysrq                      "0"
  # Core dumps restricted
  sysctl_check "K-005" "MEDIUM"   "Core dumps restricted (setuid)"            fs.suid_dumpable                  "0"
  # ptrace scope
  sysctl_check "K-006" "HIGH"     "ptrace scope restricted (Yama LSM)"        kernel.yama.ptrace_scope          "1"
  # Unprivileged BPF disabled
  sysctl_check "K-007" "HIGH"     "Unprivileged eBPF disabled"                kernel.unprivileged_bpf_disabled  "1"
  # Perf events restricted
  sysctl_check "K-008" "MEDIUM"   "Perf events restricted"                    kernel.perf_event_paranoid        "3"
  # Userns restricted (CVE mitigations)
  sysctl_check "K-009" "HIGH"     "Unprivileged user namespaces disabled"     kernel.unprivileged_userns_clone  "0"
  # Exec shield / stack randomization
  sysctl_check "K-010" "MEDIUM"   "mmap ASLR minimum entropy (64-bit)"       vm.mmap_rnd_bits                  "32"

  # Kernel module loading
  sysctl_check "K-011" "HIGH"     "Kernel module loading locked down"         kernel.modules_disabled           "1"

  # Check NX/XD support in CPU flags
  if grep -q ' nx ' /proc/cpuinfo 2>/dev/null; then
    record_check "kernel" "K-012" "HIGH" "PASS" "CPU NX/XD (No-Execute) bit supported" "/proc/cpuinfo nx flag present"
  else
    record_check "kernel" "K-012" "HIGH" "FAIL" "CPU NX/XD bit NOT detected" "Hardware NX missing — code execution protections reduced"
  fi

  # Check Spectre/Meltdown mitigations
  local vuln_dir="/sys/devices/system/cpu/vulnerabilities"
  if [[ -d "$vuln_dir" ]]; then
    local unmitigated=()
    for vuln_file in "$vuln_dir"/*; do
      local content
      content=$(cat "$vuln_file" 2>/dev/null || echo "")
      [[ "$content" =~ Vulnerable ]] && unmitigated+=("$(basename "$vuln_file")")
    done
    if [[ ${#unmitigated[@]} -eq 0 ]]; then
      record_check "kernel" "K-013" "CRITICAL" "PASS" "CPU vulnerabilities mitigated" "All /sys/devices/system/cpu/vulnerabilities entries mitigated"
    else
      record_check "kernel" "K-013" "CRITICAL" "FAIL" "CPU vulnerabilities NOT fully mitigated" \
        "Vulnerable: ${unmitigated[*]}"
    fi
  else
    record_check "kernel" "K-013" "CRITICAL" "WARN" "Cannot read CPU vulnerability status" "$vuln_dir not available"
  fi

  # Kernel version — flag if EOL (basic check)
  local kver
  kver=$(uname -r | cut -d. -f1-2)
  record_check "kernel" "K-014" "LOW" "INFO" "Kernel version: $(uname -r)" "Manually verify kernel is not EOL"

  # /proc/sys/kernel/core_pattern — check for pipe-to-userspace
  local core_pattern
  core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "unknown")
  if [[ "$core_pattern" == "|"* ]]; then
    record_check "kernel" "K-015" "MEDIUM" "WARN" "core_pattern pipes to userspace handler" \
      "core_pattern=$core_pattern — potential privilege escalation vector"
  else
    record_check "kernel" "K-015" "MEDIUM" "PASS" "core_pattern not piped to userspace" "core_pattern=$core_pattern"
  fi
}
