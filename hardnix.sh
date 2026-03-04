#!/usr/bin/env bash
# =============================================================================
#  HardNix — System Hardening Auditor for Red Teamers & Pentesters
#  https://github.com/YOUR_USERNAME/hardnix
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
OUTPUT_DIR="$SCRIPT_DIR/output"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME=$(hostname)
REPORT_FILE="$OUTPUT_DIR/hardnix_${HOSTNAME}_${TIMESTAMP}"

# ── Scoring ───────────────────────────────────────────────────────────────────
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNED_CHECKS=0
declare -a FINDINGS=()

# ── Output format (default: terminal) ─────────────────────────────────────────
FORMAT="terminal"
VERBOSE=false
NO_COLOR=false
MODULES_TO_RUN=()

# ── Colors ────────────────────────────────────────────────────────────────────
setup_colors() {
  if [[ "$NO_COLOR" == false && -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
    DIM='\033[2m'; RESET='\033[0m'
    PASS="✅"; FAIL="❌"; WARN="⚠️ "; INFO="ℹ️ "
  else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; RESET=''
    PASS="[PASS]"; FAIL="[FAIL]"; WARN="[WARN]"; INFO="[INFO]"
  fi
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}HardNix v${VERSION}${RESET} — System Hardening Auditor

${BOLD}USAGE:${RESET}
  $(basename "$0") [OPTIONS]

${BOLD}OPTIONS:${RESET}
  -m, --modules  <list>   Comma-separated modules to run (default: all)
                          kernel,ssh,fs,users,services,network,pam,
                          containers,crypto,logging,suid,cron
  -f, --format   <fmt>    Output format: terminal | json | html (default: terminal)
  -o, --output   <dir>    Output directory (default: ./output)
  -v, --verbose           Show passing checks too
  -n, --no-color          Disable color output
  -h, --help              Show this help

${BOLD}EXAMPLES:${RESET}
  sudo ./hardnix.sh                          # Full audit, terminal output
  sudo ./hardnix.sh -m ssh,kernel -v         # Only SSH & kernel checks, verbose
  sudo ./hardnix.sh -f json -o /tmp/reports  # JSON report to /tmp/reports
  sudo ./hardnix.sh -f html                  # HTML report (open in browser)

${BOLD}MODULES:${RESET}
  kernel      Kernel parameters, ASLR, kptr, dmesg restrictions
  ssh         SSH daemon configuration hardening
  fs          Filesystem permissions, world-writable paths, /tmp noexec
  users       Sudoers, empty passwords, UID 0 accounts, shell access
  services    Listening services, unnecessary daemons
  network     Firewall, IPv6, IP forwarding, ARP configs
  pam         PAM stack, password policies, account lockout
  containers  Docker socket, namespaces, container escape vectors
  crypto      TLS ciphers, certificate expiry, weak key usage
  logging     auditd, syslog, log permissions, journald
  suid        SUID/SGID binaries, capabilities audit
  cron        Cron jobs, world-writable cron paths, root crontabs

${BOLD}SCORING:${RESET}
  Results are scored 0–100. Severity weights:
    CRITICAL: -10pts  HIGH: -5pts  MEDIUM: -2pts  LOW: -1pt

EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -m|--modules) IFS=',' read -ra MODULES_TO_RUN <<< "$2"; shift 2 ;;
      -f|--format)  FORMAT="$2"; shift 2 ;;
      -o|--output)  OUTPUT_DIR="$2"; REPORT_FILE="$OUTPUT_DIR/hardnix_${HOSTNAME}_${TIMESTAMP}"; shift 2 ;;
      -v|--verbose) VERBOSE=true; shift ;;
      -n|--no-color) NO_COLOR=true; shift ;;
      -h|--help)    usage ;;
      *) echo "Unknown option: $1"; usage ;;
    esac
  done
  [[ ${#MODULES_TO_RUN[@]} -eq 0 ]] && MODULES_TO_RUN=(kernel ssh fs users services network pam containers crypto logging suid cron)
}

# ── Check result recording ────────────────────────────────────────────────────
# record_check <MODULE> <CHECK_ID> <SEVERITY> <STATUS> <TITLE> <DETAIL>
record_check() {
  local module="$1" id="$2" severity="$3" status="$4" title="$5" detail="${6:-}"
  ((TOTAL_CHECKS++))

  case "$status" in
    PASS)  ((PASSED_CHECKS++)) ;;
    FAIL)  ((FAILED_CHECKS++)) ;;
    WARN)  ((WARNED_CHECKS++)) ;;
  esac

  FINDINGS+=("${module}|${id}|${severity}|${status}|${title}|${detail}")

  if [[ "$VERBOSE" == true ]] || [[ "$status" != "PASS" ]]; then
    local icon color
    case "$status" in
      PASS) icon="$PASS"; color="$GREEN" ;;
      FAIL) icon="$FAIL"; color="$RED" ;;
      WARN) icon="$WARN"; color="$YELLOW" ;;
      INFO) icon="$INFO"; color="$BLUE" ;;
    esac
    printf "  ${color}%s${RESET} ${BOLD}[%-8s]${RESET} ${color}%-10s${RESET} %s\n" \
      "$icon" "$severity" "[$id]" "$title"
    [[ -n "$detail" ]] && printf "     ${DIM}↳ %s${RESET}\n" "$detail"
  fi
}

# ── Section header ────────────────────────────────────────────────────────────
print_section() {
  printf "\n${BOLD}${CYAN}━━━  %s  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n" "$1"
}

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
  printf "${BOLD}${RED}"
  cat <<'EOF'
  _  _              _ _  _ _     
 | || |__ _ _ _ __| | \| (_)_ __
 | __ / _` | '_/ _` | .` | \ \ /
 |_||_\__,_|_| \__,_|_|\_|_/_\_\
EOF
  printf "${RESET}"
  printf "${BOLD}  System Hardening Auditor v%s${RESET}\n" "$VERSION"
  printf "${DIM}  For authorized security assessments only${RESET}\n\n"
  printf "  ${BOLD}Target   :${RESET} %s\n" "$(uname -n)"
  printf "  ${BOLD}OS       :${RESET} %s\n" "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)"
  printf "  ${BOLD}Kernel   :${RESET} %s\n" "$(uname -r)"
  printf "  ${BOLD}Auditor  :${RESET} %s\n" "$(whoami)"
  printf "  ${BOLD}Date     :${RESET} %s\n" "$(date)"
  printf "  ${BOLD}Modules  :${RESET} %s\n" "${MODULES_TO_RUN[*]}"
}

# ── Privilege check ───────────────────────────────────────────────────────────
check_privileges() {
  if [[ $EUID -ne 0 ]]; then
    printf "\n${YELLOW}${WARN} Running without root. Some checks will be skipped.${RESET}\n"
    printf "   ${DIM}Run with: sudo ./hardnix.sh for full coverage${RESET}\n"
  fi
}

# ── Load and run modules ──────────────────────────────────────────────────────
run_modules() {
  for mod in "${MODULES_TO_RUN[@]}"; do
    local modfile="$MODULES_DIR/${mod}.sh"
    if [[ -f "$modfile" ]]; then
      # shellcheck source=/dev/null
      source "$modfile"
      "audit_${mod}"
    else
      printf "${YELLOW}  ${WARN} Module not found: %s${RESET}\n" "$mod"
    fi
  done
}

# ── Score calculation ─────────────────────────────────────────────────────────
calculate_score() {
  local score=100
  for finding in "${FINDINGS[@]}"; do
    local severity status
    severity=$(echo "$finding" | cut -d'|' -f3)
    status=$(echo "$finding" | cut -d'|' -f4)
    [[ "$status" == "PASS" ]] && continue
    case "$severity" in
      CRITICAL) score=$((score - 10)) ;;
      HIGH)     score=$((score - 5)) ;;
      MEDIUM)   score=$((score - 2)) ;;
      LOW)      score=$((score - 1)) ;;
    esac
  done
  echo $((score < 0 ? 0 : score))
}

grade_score() {
  local score=$1
  if   [[ $score -ge 90 ]]; then echo "A — Hardened"
  elif [[ $score -ge 75 ]]; then echo "B — Good"
  elif [[ $score -ge 60 ]]; then echo "C — Fair"
  elif [[ $score -ge 40 ]]; then echo "D — Weak"
  else                            echo "F — Critical Risk"
  fi
}

# ── Terminal summary ──────────────────────────────────────────────────────────
print_summary() {
  local score
  score=$(calculate_score)
  local grade
  grade=$(grade_score "$score")

  local score_color
  if   [[ $score -ge 75 ]]; then score_color="$GREEN"
  elif [[ $score -ge 50 ]]; then score_color="$YELLOW"
  else                            score_color="$RED"
  fi

  printf "\n${BOLD}${CYAN}━━━  AUDIT SUMMARY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n\n"
  printf "  ${BOLD}Total checks :${RESET} %d\n" "$TOTAL_CHECKS"
  printf "  ${GREEN}${BOLD}Passed       :${RESET} %d\n" "$PASSED_CHECKS"
  printf "  ${RED}${BOLD}Failed       :${RESET} %d\n" "$FAILED_CHECKS"
  printf "  ${YELLOW}${BOLD}Warnings     :${RESET} %d\n" "$WARNED_CHECKS"
  printf "\n  ${BOLD}Score        :${RESET} ${score_color}${BOLD}%d / 100${RESET}\n" "$score"
  printf "  ${BOLD}Grade        :${RESET} ${score_color}${BOLD}%s${RESET}\n\n" "$grade"

  # Top findings
  printf "  ${BOLD}Critical/High Findings:${RESET}\n"
  local found=0
  for finding in "${FINDINGS[@]}"; do
    local sev stat title detail
    sev=$(echo   "$finding" | cut -d'|' -f3)
    stat=$(echo  "$finding" | cut -d'|' -f4)
    title=$(echo "$finding" | cut -d'|' -f5)
    detail=$(echo "$finding" | cut -d'|' -f6)
    [[ "$stat" == "PASS" ]] && continue
    [[ "$sev" == "CRITICAL" || "$sev" == "HIGH" ]] || continue
    printf "    ${RED}${FAIL}${RESET} ${BOLD}[%s]${RESET} %s\n" "$sev" "$title"
    [[ -n "$detail" ]] && printf "       ${DIM}%s${RESET}\n" "$detail"
    ((found++))
  done
  [[ $found -eq 0 ]] && printf "    ${GREEN}None — looking solid!${RESET}\n"
  printf "\n"
}

# ── JSON report ───────────────────────────────────────────────────────────────
generate_json_report() {
  local score
  score=$(calculate_score)
  local outfile="${REPORT_FILE}.json"
  mkdir -p "$(dirname "$outfile")"

  {
    echo "{"
    echo "  \"meta\": {"
    echo "    \"tool\": \"HardNix\","
    echo "    \"version\": \"${VERSION}\","
    echo "    \"hostname\": \"${HOSTNAME}\","
    echo "    \"timestamp\": \"$(date -Iseconds)\","
    echo "    \"kernel\": \"$(uname -r)\","
    echo "    \"auditor\": \"$(whoami)\""
    echo "  },"
    echo "  \"score\": ${score},"
    echo "  \"grade\": \"$(grade_score "$score")\","
    echo "  \"stats\": {"
    echo "    \"total\": ${TOTAL_CHECKS},"
    echo "    \"passed\": ${PASSED_CHECKS},"
    echo "    \"failed\": ${FAILED_CHECKS},"
    echo "    \"warnings\": ${WARNED_CHECKS}"
    echo "  },"
    echo "  \"findings\": ["

    local first=true
    for finding in "${FINDINGS[@]}"; do
      local mod id sev stat title detail
      mod=$(echo    "$finding" | cut -d'|' -f1)
      id=$(echo     "$finding" | cut -d'|' -f2)
      sev=$(echo    "$finding" | cut -d'|' -f3)
      stat=$(echo   "$finding" | cut -d'|' -f4)
      title=$(echo  "$finding" | cut -d'|' -f5)
      detail=$(echo "$finding" | cut -d'|' -f6)
      # Escape for JSON
      title=$(echo "$title"   | sed 's/"/\\"/g')
      detail=$(echo "$detail" | sed 's/"/\\"/g')
      [[ "$first" == false ]] && echo ","
      printf "    {\"module\":\"%s\",\"id\":\"%s\",\"severity\":\"%s\",\"status\":\"%s\",\"title\":\"%s\",\"detail\":\"%s\"}" \
        "$mod" "$id" "$sev" "$stat" "$title" "$detail"
      first=false
    done
    echo ""
    echo "  ]"
    echo "}"
  } > "$outfile"

  printf "${GREEN}${PASS} JSON report saved:${RESET} %s\n" "$outfile"
}

# ── HTML report ───────────────────────────────────────────────────────────────
generate_html_report() {
  local score
  score=$(calculate_score)
  local grade
  grade=$(grade_score "$score")
  local outfile="${REPORT_FILE}.html"
  mkdir -p "$(dirname "$outfile")"

  local score_color="crimson"
  [[ $score -ge 75 ]] && score_color="#22c55e"
  [[ $score -ge 50 && $score -lt 75 ]] && score_color="#f59e0b"

  {
  cat <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HardNix Report — ${HOSTNAME}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  header{background:linear-gradient(135deg,#1e293b,#0f172a);border-bottom:1px solid #334155;padding:2rem}
  header h1{font-size:2rem;color:#f8fafc;font-weight:700}
  header h1 span{color:#ef4444}
  .meta{display:flex;flex-wrap:wrap;gap:1.5rem;margin-top:1rem;font-size:.85rem;color:#94a3b8}
  .meta b{color:#cbd5e1}
  .container{max-width:1200px;margin:0 auto;padding:2rem}
  .score-card{background:linear-gradient(135deg,#1e293b,#162032);border:1px solid #334155;border-radius:1rem;padding:2rem;display:flex;align-items:center;gap:2rem;margin-bottom:2rem}
  .score-circle{width:110px;height:110px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;border:4px solid ${score_color};flex-shrink:0}
  .score-circle .num{font-size:2.2rem;font-weight:800;color:${score_color}}
  .score-circle .max{font-size:.75rem;color:#64748b}
  .score-info h2{font-size:1.5rem;font-weight:700;color:#f8fafc}
  .score-info p{color:#94a3b8;margin-top:.25rem}
  .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-top:1rem}
  .stat{background:#0f172a;border-radius:.5rem;padding:.75rem 1rem;text-align:center}
  .stat .n{font-size:1.5rem;font-weight:700}
  .stat .l{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}
  .pass{color:#22c55e}.fail{color:#ef4444}.warn{color:#f59e0b}
  .findings{display:flex;flex-direction:column;gap:.75rem}
  .finding{background:#1e293b;border-radius:.75rem;padding:1rem 1.25rem;border-left:4px solid #334155;display:flex;align-items:flex-start;gap:1rem}
  .finding.CRITICAL{border-left-color:#ef4444}
  .finding.HIGH{border-left-color:#f97316}
  .finding.MEDIUM{border-left-color:#f59e0b}
  .finding.LOW{border-left-color:#3b82f6}
  .finding.PASS-row{border-left-color:#22c55e;opacity:.7}
  .badge{font-size:.65rem;font-weight:700;padding:.2rem .5rem;border-radius:.25rem;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;flex-shrink:0}
  .badge.CRITICAL{background:#7f1d1d;color:#fca5a5}
  .badge.HIGH{background:#7c2d12;color:#fdba74}
  .badge.MEDIUM{background:#713f12;color:#fde68a}
  .badge.LOW{background:#1e3a5f;color:#93c5fd}
  .badge.PASS{background:#14532d;color:#86efac}
  .badge.WARN{background:#713f12;color:#fde68a}
  .f-title{font-weight:600;color:#f1f5f9;font-size:.95rem}
  .f-detail{font-size:.8rem;color:#64748b;margin-top:.2rem}
  .f-meta{font-size:.7rem;color:#475569;margin-top:.1rem}
  h3{font-size:1.1rem;font-weight:600;color:#f8fafc;margin:1.5rem 0 .75rem}
  .module-group{margin-bottom:1.5rem}
  .module-label{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:#64748b;font-weight:600;margin-bottom:.5rem;padding-left:.25rem}
  footer{text-align:center;padding:2rem;color:#334155;font-size:.8rem;border-top:1px solid #1e293b}
</style>
</head>
<body>
<header>
  <h1><span>Hard</span>Nix — System Hardening Report</h1>
  <div class="meta">
    <span><b>Host:</b> ${HOSTNAME}</span>
    <span><b>OS:</b> $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)</span>
    <span><b>Kernel:</b> $(uname -r)</span>
    <span><b>Auditor:</b> $(whoami)</span>
    <span><b>Date:</b> $(date)</span>
  </div>
</header>
<div class="container">
  <div class="score-card">
    <div class="score-circle">
      <span class="num">${score}</span>
      <span class="max">/100</span>
    </div>
    <div class="score-info">
      <h2>${grade}</h2>
      <p>Security hardening score based on ${TOTAL_CHECKS} automated checks</p>
      <div class="stats">
        <div class="stat"><div class="n pass">${PASSED_CHECKS}</div><div class="l">Passed</div></div>
        <div class="stat"><div class="n fail">${FAILED_CHECKS}</div><div class="l">Failed</div></div>
        <div class="stat"><div class="n warn">${WARNED_CHECKS}</div><div class="l">Warnings</div></div>
      </div>
    </div>
  </div>
HTMLEOF

  # Group by module
  declare -A mod_findings
  for finding in "${FINDINGS[@]}"; do
    local mod
    mod=$(echo "$finding" | cut -d'|' -f1)
    mod_findings["$mod"]+="$finding"$'\n'
  done

  echo '<h3>Findings by Module</h3>'
  echo '<div class="findings">'
  for mod in "${!mod_findings[@]}"; do
    echo "<div class='module-group'>"
    echo "<div class='module-label'>📦 $mod</div>"
    while IFS= read -r finding; do
      [[ -z "$finding" ]] && continue
      local id sev stat title detail row_class
      id=$(echo     "$finding" | cut -d'|' -f2)
      sev=$(echo    "$finding" | cut -d'|' -f3)
      stat=$(echo   "$finding" | cut -d'|' -f4)
      title=$(echo  "$finding" | cut -d'|' -f5)
      detail=$(echo "$finding" | cut -d'|' -f6)
      row_class="$sev"
      [[ "$stat" == "PASS" ]] && row_class="PASS-row"
      echo "<div class='finding $row_class'>"
      echo "  <span class='badge $sev'>$sev</span>"
      echo "  <div>"
      echo "    <div class='f-title'>$title</div>"
      [[ -n "$detail" ]] && echo "    <div class='f-detail'>$detail</div>"
      echo "    <div class='f-meta'>$id · $stat</div>"
      echo "  </div>"
      echo "</div>"
    done <<< "${mod_findings[$mod]}"
    echo "</div>"
  done
  echo '</div>'

  cat <<HTMLEOF2
</div>
<footer>Generated by HardNix v${VERSION} · For authorized use only · $(date)</footer>
</body></html>
HTMLEOF2
  } > "$outfile"

  printf "${GREEN}${PASS} HTML report saved:${RESET} %s\n" "$outfile"
}

# ── Entry point ───────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  setup_colors
  mkdir -p "$OUTPUT_DIR"
  print_banner
  check_privileges
  run_modules
  print_summary

  case "$FORMAT" in
    json) generate_json_report ;;
    html) generate_html_report ;;
  esac
}

main "$@"
