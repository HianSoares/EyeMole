#!/usr/bin/env bash
# =============================================================================
# EyeMole Safe Uninstaller
# Idempotent removal of EyeMole/HMG-SOAR components.
#
# Modes:
#   --dry-run       List actions without changing anything
#   (default)       Remove integration/code, preserve data
#   --purge         Remove everything including data (requires confirmation)
#   --purge --yes   Skip interactive confirmation
#   --remove-user   Remove hmg-soar user after safety checks
#   --help          Show usage
#
# Transactional order:
#   1. Parse args → 2. Root check → 3. Preflight/path validation
#   4. Inventory → 5. Dry-run output → 6. Purge confirmation
#   7. Backup → 8. Stop/disable services → 9. Remove Nginx integration
#   10. Remove systemd units → 11. Remove PolicyKit/legacy artifacts
#   12. Preserve data OR purge → 13. Remove application directories
#   14. Final validations → 15. Optional user removal → 16. Final report
# =============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

# ─── Overridable variables ────────────────────────────────────────────────────
APP_USER="${APP_USER:-hmg-soar}"
WEB_GROUP="${WEB_GROUP:-www-data}"
APP_DIR="${APP_DIR:-/opt/hmg-soar}"
WEB_DIR="${WEB_DIR:-/var/www/wazuh-soar}"
ETC_DIR="${ETC_DIR:-/etc/hmg-soar}"
HTPASSWD_FILE="${HTPASSWD_FILE:-/etc/nginx/.htpasswd-wazuh-soar}"
SNIPPET_FILE="${SNIPPET_FILE:-/etc/nginx/snippets/eyemole-soar-locations.conf}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
POLKIT_RULE_FILE="${POLKIT_RULE_FILE:-/etc/polkit-1/rules.d/49-hmg-soar.rules}"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/hmg-soar-api}"
WRAPPER_RUN_ANALYSIS="${WRAPPER_RUN_ANALYSIS:-/usr/local/sbin/hmg-soar-run-analysis}"
WRAPPER_STATUS="${WRAPPER_STATUS:-/usr/local/sbin/hmg-soar-status}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt}"
NGINX_ROOT="${NGINX_ROOT:-/etc/nginx}"
PRESERVE_ROOT="${PRESERVE_ROOT:-/var/lib/eyemole-preserved}"
API_SERVICE_FILE="hmg-soar-api.service"
REPORT_SERVICE_FILE="hmg-soar-report.service"
REPORT_TIMER_FILE="hmg-soar-report.timer"

# ─── Runtime state ────────────────────────────────────────────────────────────
DRY_RUN=0
PURGE=0
YES=0
REMOVE_USER=0
TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/backup-eyemole-uninstall-${TS}"
declare -a ACTIONS_TAKEN=()
declare -a WARNINGS=()
declare -a INVENTORY_FOUND=()
declare -a INVENTORY_MISSING=()

# ─── Never-remove safeguards ─────────────────────────────────────────────────
NEVER_REMOVE_USERS=("www-data" "root" "nginx" "nobody")
NEVER_REMOVE_PACKAGES=("nginx" "python3" "wazuh-manager" "wazuh-agent")

# =============================================================================
# Logging helpers
# =============================================================================
log()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; WARNINGS+=("$*"); }
die()  { echo "[x] $*" >&2; exit 1; }
info() { echo "    $*"; }

dry_log() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[DRY-RUN] $*"
    fi
}

# =============================================================================
# Usage
# =============================================================================
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

EyeMole Safe Uninstaller — idempotent removal of EyeMole/HMG-SOAR.

Options:
  --dry-run        List planned actions without making changes
  --purge          Remove everything including data (requires confirmation)
  --yes            Skip interactive confirmation (use with --purge)
  --remove-user    Remove the ${APP_USER} system user after safety checks
  --help           Show this help message

Default behavior (no flags):
  Removes integration code and systemd units while preserving data
  under ${PRESERVE_ROOT}.

Environment variables:
  All paths are overridable. See top of script for defaults.

Examples:
  sudo ./uninstall.sh --dry-run
  sudo ./uninstall.sh
  sudo ./uninstall.sh --purge --yes
  sudo ./uninstall.sh --purge --yes --remove-user
EOF
    exit 0
}

# =============================================================================
# Path safety
# =============================================================================
assert_safe_managed_path() {
    local path="$1"
    local label="${2:-path}"

    # Reject empty
    if [[ -z "$path" ]]; then
        die "assert_safe_managed_path: ${label} is empty"
    fi

    # Reject relative paths
    if [[ "$path" != /* ]]; then
        die "assert_safe_managed_path: ${label} '${path}' is not absolute"
    fi

    # Reject paths with ..
    if [[ "$path" == *".."* ]]; then
        die "assert_safe_managed_path: ${label} '${path}' contains '..'"
    fi

    # Reject dangerous roots
    local -a forbidden=("/" "/opt" "/var" "/etc" "/etc/nginx" "/usr" "/usr/local" "/home")
    local resolved
    resolved="$(realpath -m "$path" 2>/dev/null || echo "$path")"

    for f in "${forbidden[@]}"; do
        if [[ "$resolved" == "$f" ]]; then
            die "assert_safe_managed_path: ${label} '${path}' resolves to forbidden path '${f}'"
        fi
    done

    return 0
}

# =============================================================================
# Argument parsing
# =============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)    DRY_RUN=1;      shift ;;
            --purge)      PURGE=1;        shift ;;
            --yes)        YES=1;          shift ;;
            --remove-user) REMOVE_USER=1; shift ;;
            --help|-h)    usage ;;
            *)            die "Unknown option: $1. Use --help for usage." ;;
        esac
    done
}

# =============================================================================
# Root check
# =============================================================================
check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "This script must be run as root (use sudo)."
    fi
}

# =============================================================================
# Preflight — validate all configured paths
# =============================================================================
preflight_validate() {
    log "Preflight: validating configured paths..."
    assert_safe_managed_path "$APP_DIR"       "APP_DIR"
    assert_safe_managed_path "$WEB_DIR"       "WEB_DIR"
    assert_safe_managed_path "$ETC_DIR"       "ETC_DIR"
    assert_safe_managed_path "$HTPASSWD_FILE" "HTPASSWD_FILE"
    assert_safe_managed_path "$SNIPPET_FILE"  "SNIPPET_FILE"
    assert_safe_managed_path "$POLKIT_RULE_FILE"      "POLKIT_RULE_FILE"
    assert_safe_managed_path "$SUDOERS_FILE"          "SUDOERS_FILE"
    assert_safe_managed_path "$WRAPPER_RUN_ANALYSIS"  "WRAPPER_RUN_ANALYSIS"
    assert_safe_managed_path "$WRAPPER_STATUS"        "WRAPPER_STATUS"
    assert_safe_managed_path "$PRESERVE_ROOT"         "PRESERVE_ROOT"
    log "Preflight: all paths valid."
}

# =============================================================================
# Inventory — discover what actually exists
# =============================================================================
inventory() {
    log "Inventorying installed components..."

    local -a check_paths=(
        "$APP_DIR"
        "$WEB_DIR"
        "$ETC_DIR"
        "$HTPASSWD_FILE"
        "$SNIPPET_FILE"
        "${SYSTEMD_UNIT_DIR}/${API_SERVICE_FILE}"
        "${SYSTEMD_UNIT_DIR}/${REPORT_SERVICE_FILE}"
        "${SYSTEMD_UNIT_DIR}/${REPORT_TIMER_FILE}"
        "$POLKIT_RULE_FILE"
        "$SUDOERS_FILE"
        "$WRAPPER_RUN_ANALYSIS"
        "$WRAPPER_STATUS"
    )

    for p in "${check_paths[@]}"; do
        if [[ -e "$p" ]]; then
            INVENTORY_FOUND+=("$p")
            info "FOUND: $p"
        else
            INVENTORY_MISSING+=("$p")
        fi
    done

    # Check user
    if id "$APP_USER" &>/dev/null; then
        INVENTORY_FOUND+=("user:${APP_USER}")
        info "FOUND: user ${APP_USER}"
    else
        INVENTORY_MISSING+=("user:${APP_USER}")
    fi

    # Check nginx include line
    local nginx_site_conf="${NGINX_ROOT}/sites-enabled/wazuh-dashboard-proxy"
    if [[ -f "$nginx_site_conf" ]] && grep -q "eyemole-soar-locations" "$nginx_site_conf" 2>/dev/null; then
        INVENTORY_FOUND+=("nginx-include:${nginx_site_conf}")
        info "FOUND: nginx include in ${nginx_site_conf}"
    fi

    if [[ ${#INVENTORY_FOUND[@]} -eq 0 ]]; then
        log "Nothing found to uninstall. EyeMole does not appear to be installed."
        exit 0
    fi

    log "Inventory complete: ${#INVENTORY_FOUND[@]} items found, ${#INVENTORY_MISSING[@]} already absent."
}

# =============================================================================
# Dry-run output
# =============================================================================
show_dry_run() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  DRY-RUN: The following actions WOULD be performed"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    for item in "${INVENTORY_FOUND[@]}"; do
        case "$item" in
            user:*)
                if [[ "$REMOVE_USER" -eq 1 ]]; then
                    echo "  [REMOVE]   $item"
                else
                    echo "  [KEEP]     $item (use --remove-user to remove)"
                fi
                ;;
            nginx-include:*)
                echo "  [REMOVE]   Nginx include line from ${item#nginx-include:}"
                ;;
            *)
                if [[ "$PURGE" -eq 1 ]]; then
                    echo "  [PURGE]    $item"
                elif [[ "$item" == "$APP_DIR"* ]] || [[ "$item" == "$WEB_DIR"* ]] || [[ "$item" == "$ETC_DIR"* ]]; then
                    echo "  [PRESERVE] $item → ${PRESERVE_ROOT}/"
                else
                    echo "  [REMOVE]   $item"
                fi
                ;;
        esac
    done

    echo ""
    echo "  Backup would be created at: ${BACKUP_DIR}"
    if [[ "$PURGE" -eq 0 ]]; then
        echo "  Data preserved under: ${PRESERVE_ROOT}"
    fi
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  No changes made. Re-run without --dry-run to execute."
    echo "═══════════════════════════════════════════════════════════════"
}

# =============================================================================
# Purge confirmation
# =============================================================================
confirm_purge() {
    if [[ "$PURGE" -eq 0 ]]; then
        return 0
    fi
    if [[ "$YES" -eq 1 ]]; then
        log "Purge mode: --yes provided, skipping confirmation."
        return 0
    fi

    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  WARNING: --purge will PERMANENTLY DELETE all EyeMole data   ║"
    echo "║  including reports, configurations, and analysis history.     ║"
    echo "║                                                               ║"
    echo "║  Type exactly: PURGE EYEMOLE                                  ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    read -rp "Confirmation: " confirmation
    if [[ "$confirmation" != "PURGE EYEMOLE" ]]; then
        die "Purge not confirmed. Aborting."
    fi
    log "Purge confirmed."
}

# =============================================================================
# Backup with SHA-256 manifest
# =============================================================================
create_backup() {
    log "Creating backup at ${BACKUP_DIR}..."

    # Space check — require at least 100MB free
    local available_kb
    available_kb="$(df -k "$(dirname "$BACKUP_DIR")" | awk 'NR==2 {print $4}')"
    if [[ "$available_kb" -lt 102400 ]]; then
        die "Insufficient disk space for backup. Need at least 100MB free in $(dirname "$BACKUP_DIR")."
    fi

    mkdir -p "$BACKUP_DIR"

    for item in "${INVENTORY_FOUND[@]}"; do
        # Skip non-path entries
        case "$item" in
            user:*|nginx-include:*) continue ;;
        esac

        if [[ -e "$item" ]]; then
            local rel_path="${item#/}"
            local dest_dir="${BACKUP_DIR}/$(dirname "$rel_path")"
            mkdir -p "$dest_dir"
            cp -a "$item" "${BACKUP_DIR}/${rel_path}" 2>/dev/null || true
        fi
    done

    # Backup nginx site config if include exists
    local nginx_site_conf="${NGINX_ROOT}/sites-enabled/wazuh-dashboard-proxy"
    if [[ -f "$nginx_site_conf" ]]; then
        mkdir -p "${BACKUP_DIR}/${NGINX_ROOT#/}/sites-enabled"
        cp -a "$nginx_site_conf" "${BACKUP_DIR}/${NGINX_ROOT#/}/sites-enabled/" 2>/dev/null || true
    fi

    # Generate SHA-256 manifest
    log "Generating SHA-256 manifest..."
    find "$BACKUP_DIR" -type f ! -name "MANIFEST.sha256" -exec sha256sum {} + \
        > "${BACKUP_DIR}/MANIFEST.sha256" 2>/dev/null || true

    local file_count
    file_count="$(find "$BACKUP_DIR" -type f | wc -l)"
    log "Backup complete: ${file_count} files in ${BACKUP_DIR}"
    ACTIONS_TAKEN+=("Backup created: ${BACKUP_DIR}")
}

# =============================================================================
# Stop and disable systemd services (correct order)
# =============================================================================
stop_services() {
    log "Stopping and disabling systemd services..."

    local -a units_ordered=(
        "$REPORT_TIMER_FILE"
        "$REPORT_SERVICE_FILE"
        "$API_SERVICE_FILE"
    )

    for unit in "${units_ordered[@]}"; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            log "  Stopping ${unit}..."
            systemctl stop "$unit" 2>/dev/null || true
            ACTIONS_TAKEN+=("Stopped: ${unit}")
        fi
        if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
            log "  Disabling ${unit}..."
            systemctl disable "$unit" 2>/dev/null || true
            ACTIONS_TAKEN+=("Disabled: ${unit}")
        fi
    done

    log "Services stopped and disabled."
}

# =============================================================================
# Remove Nginx integration (with rollback on nginx -t failure)
# =============================================================================
remove_nginx_integration() {
    log "Removing Nginx integration..."

    local nginx_site_conf="${NGINX_ROOT}/sites-enabled/wazuh-dashboard-proxy"
    local nginx_changed=0

    # Remove include line from site config
    if [[ -f "$nginx_site_conf" ]] && grep -q "eyemole-soar-locations" "$nginx_site_conf"; then
        log "  Removing include line from ${nginx_site_conf}..."
        local backup_conf="${nginx_site_conf}.bak-uninstall-${TS}"
        cp -a "$nginx_site_conf" "$backup_conf"

        sed -i '/eyemole-soar-locations/d' "$nginx_site_conf"
        nginx_changed=1
        ACTIONS_TAKEN+=("Removed include line from ${nginx_site_conf}")
    fi

    # Remove snippet file
    if [[ -f "$SNIPPET_FILE" ]]; then
        rm -f "$SNIPPET_FILE"
        log "  Removed snippet: ${SNIPPET_FILE}"
        ACTIONS_TAKEN+=("Removed: ${SNIPPET_FILE}")
    fi

    # Remove htpasswd file
    if [[ -f "$HTPASSWD_FILE" ]]; then
        rm -f "$HTPASSWD_FILE"
        log "  Removed htpasswd: ${HTPASSWD_FILE}"
        ACTIONS_TAKEN+=("Removed: ${HTPASSWD_FILE}")
    fi

    # Validate nginx configuration; rollback on failure
    if [[ "$nginx_changed" -eq 1 ]]; then
        log "  Testing nginx configuration..."
        if ! nginx -t 2>/dev/null; then
            warn "nginx -t FAILED after removing include line. Rolling back..."
            if [[ -f "$backup_conf" ]]; then
                cp -a "$backup_conf" "$nginx_site_conf"
                warn "Rollback complete. Nginx config restored from ${backup_conf}"
                ACTIONS_TAKEN+=("ROLLBACK: Restored ${nginx_site_conf}")
            fi
        else
            log "  nginx -t passed."
            # Reload nginx to apply changes
            systemctl reload nginx 2>/dev/null || true
            ACTIONS_TAKEN+=("Reloaded nginx")
        fi
    fi

    log "Nginx integration removal complete."
}

# =============================================================================
# Remove systemd unit files + daemon-reload
# =============================================================================
remove_systemd_units() {
    log "Removing systemd unit files..."

    local -a unit_files=(
        "${SYSTEMD_UNIT_DIR}/${API_SERVICE_FILE}"
        "${SYSTEMD_UNIT_DIR}/${REPORT_SERVICE_FILE}"
        "${SYSTEMD_UNIT_DIR}/${REPORT_TIMER_FILE}"
    )

    local removed=0
    for uf in "${unit_files[@]}"; do
        if [[ -f "$uf" ]]; then
            rm -f "$uf"
            log "  Removed: ${uf}"
            ACTIONS_TAKEN+=("Removed: ${uf}")
            removed=1
        fi
    done

    if [[ "$removed" -eq 1 ]]; then
        systemctl daemon-reload 2>/dev/null || true
        log "  systemctl daemon-reload completed."
        ACTIONS_TAKEN+=("daemon-reload")
    fi
}

# =============================================================================
# Remove PolicyKit rules and legacy artifacts
# =============================================================================
remove_polkit_and_legacy() {
    log "Removing PolicyKit rules and legacy artifacts..."

    # PolicyKit rule
    if [[ -f "$POLKIT_RULE_FILE" ]]; then
        rm -f "$POLKIT_RULE_FILE"
        log "  Removed PolicyKit rule: ${POLKIT_RULE_FILE}"
        ACTIONS_TAKEN+=("Removed: ${POLKIT_RULE_FILE}")
    fi

    # Sudoers file
    if [[ -f "$SUDOERS_FILE" ]]; then
        rm -f "$SUDOERS_FILE"
        log "  Removed sudoers file: ${SUDOERS_FILE}"
        ACTIONS_TAKEN+=("Removed: ${SUDOERS_FILE}")
    fi

    # Wrapper scripts
    if [[ -f "$WRAPPER_RUN_ANALYSIS" ]]; then
        rm -f "$WRAPPER_RUN_ANALYSIS"
        log "  Removed wrapper: ${WRAPPER_RUN_ANALYSIS}"
        ACTIONS_TAKEN+=("Removed: ${WRAPPER_RUN_ANALYSIS}")
    fi

    if [[ -f "$WRAPPER_STATUS" ]]; then
        rm -f "$WRAPPER_STATUS"
        log "  Removed wrapper: ${WRAPPER_STATUS}"
        ACTIONS_TAKEN+=("Removed: ${WRAPPER_STATUS}")
    fi
}

# =============================================================================
# Preserve data (default mode) — move to PRESERVE_ROOT
# =============================================================================
preserve_data() {
    if [[ "$PURGE" -eq 1 ]]; then
        return 0
    fi

    log "Preserving data to ${PRESERVE_ROOT}..."
    mkdir -p "$PRESERVE_ROOT"

    local -a data_dirs=("$APP_DIR" "$WEB_DIR" "$ETC_DIR")
    for dir in "${data_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local basename
            basename="$(basename "$dir")"
            local dest="${PRESERVE_ROOT}/${basename}-${TS}"
            log "  Moving ${dir} → ${dest}"
            mv "$dir" "$dest"
            ACTIONS_TAKEN+=("Preserved: ${dir} → ${dest}")
        fi
    done

    log "Data preservation complete."
}

# =============================================================================
# Purge data — permanently remove all data directories
# =============================================================================
purge_data() {
    if [[ "$PURGE" -eq 0 ]]; then
        return 0
    fi

    log "Purging all EyeMole data..."

    local -a data_dirs=("$APP_DIR" "$WEB_DIR" "$ETC_DIR")
    for dir in "${data_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            assert_safe_managed_path "$dir" "purge target"
            rm -rf "$dir"
            log "  Purged: ${dir}"
            ACTIONS_TAKEN+=("Purged: ${dir}")
        fi
    done

    # Also remove any preserved data from previous runs
    if [[ -d "$PRESERVE_ROOT" ]]; then
        assert_safe_managed_path "$PRESERVE_ROOT" "PRESERVE_ROOT"
        rm -rf "$PRESERVE_ROOT"
        log "  Purged preserved data: ${PRESERVE_ROOT}"
        ACTIONS_TAKEN+=("Purged: ${PRESERVE_ROOT}")
    fi

    log "Purge complete."
}

# =============================================================================
# Remove application directories (only called if preserve already moved data)
# =============================================================================
remove_app_directories() {
    log "Cleaning up remaining application directories..."

    local -a dirs=("$APP_DIR" "$WEB_DIR" "$ETC_DIR")
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # In preserve mode this shouldn't exist (already moved),
            # but handle edge cases with empty dirs
            if [[ "$(ls -A "$dir" 2>/dev/null)" == "" ]]; then
                rmdir "$dir" 2>/dev/null || true
                log "  Removed empty dir: ${dir}"
            else
                warn "Directory ${dir} still has content — skipping removal."
            fi
        fi
    done
}

# =============================================================================
# Final validations
# =============================================================================
final_validations() {
    log "Running final validations..."

    local issues=0

    # Check no stray systemd units
    for unit in "$API_SERVICE_FILE" "$REPORT_SERVICE_FILE" "$REPORT_TIMER_FILE"; do
        if systemctl list-unit-files "$unit" 2>/dev/null | grep -q "$unit"; then
            warn "Systemd unit ${unit} still registered (may need reboot to clear)."
            issues=$((issues + 1))
        fi
    done

    # Verify nginx is healthy (if installed)
    if command -v nginx &>/dev/null; then
        if ! nginx -t 2>/dev/null; then
            warn "nginx -t is failing. Manual intervention may be required."
            issues=$((issues + 1))
        fi
    fi

    if [[ "$issues" -eq 0 ]]; then
        log "Final validations passed."
    else
        warn "Final validations found ${issues} issue(s). See warnings above."
    fi
}

# =============================================================================
# User removal (optional, with safety checks)
# =============================================================================
remove_app_user() {
    if [[ "$REMOVE_USER" -eq 0 ]]; then
        return 0
    fi

    log "Evaluating user removal for '${APP_USER}'..."

    # Safety: never remove protected users
    for protected in "${NEVER_REMOVE_USERS[@]}"; do
        if [[ "$APP_USER" == "$protected" ]]; then
            warn "Refusing to remove protected user '${APP_USER}'."
            return 1
        fi
    done

    # Check user exists
    if ! id "$APP_USER" &>/dev/null; then
        log "  User '${APP_USER}' does not exist. Nothing to do."
        return 0
    fi

    # Safety: check for running processes owned by the user
    local proc_count
    proc_count="$(pgrep -u "$APP_USER" 2>/dev/null | wc -l || echo 0)"
    if [[ "$proc_count" -gt 0 ]]; then
        warn "User '${APP_USER}' still has ${proc_count} running process(es)."
        warn "Cannot safely remove user. Stop all processes first."
        return 1
    fi

    # Safety: check if user owns files outside of managed paths
    local stray_files
    stray_files="$(find / -user "$APP_USER" \
        -not -path "${APP_DIR}/*" \
        -not -path "${WEB_DIR}/*" \
        -not -path "${ETC_DIR}/*" \
        -not -path "${PRESERVE_ROOT}/*" \
        -not -path "${BACKUP_ROOT}/backup-eyemole-*" \
        -not -path "/proc/*" \
        -not -path "/sys/*" \
        2>/dev/null | head -5 || true)"

    if [[ -n "$stray_files" ]]; then
        warn "User '${APP_USER}' owns files outside managed paths:"
        echo "$stray_files" | while read -r f; do warn "  $f"; done
        warn "Proceeding with user removal, but stray files will remain."
    fi

    # Remove user (without removing home if it is a managed path)
    userdel "$APP_USER" 2>/dev/null || true
    log "  User '${APP_USER}' removed."
    ACTIONS_TAKEN+=("Removed user: ${APP_USER}")

    # Remove group if it exists and is not a primary group elsewhere
    if getent group "$APP_USER" &>/dev/null; then
        groupdel "$APP_USER" 2>/dev/null || true
        log "  Group '${APP_USER}' removed."
        ACTIONS_TAKEN+=("Removed group: ${APP_USER}")
    fi
}

# =============================================================================
# Final report
# =============================================================================
final_report() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  EyeMole Uninstall Report"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Timestamp:    ${TS}"
    echo "  Mode:         $(if [[ "$PURGE" -eq 1 ]]; then echo "PURGE"; else echo "PRESERVE"; fi)"
    echo "  Backup:       ${BACKUP_DIR}"
    if [[ "$PURGE" -eq 0 ]]; then
        echo "  Preserved:    ${PRESERVE_ROOT}"
    fi
    echo ""
    echo "  Actions taken (${#ACTIONS_TAKEN[@]}):"
    for action in "${ACTIONS_TAKEN[@]}"; do
        echo "    • ${action}"
    done

    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        echo ""
        echo "  Warnings (${#WARNINGS[@]}):"
        for w in "${WARNINGS[@]}"; do
            echo "    ⚠  ${w}"
        done
    fi

    echo ""
    echo "  Items NOT removed (by policy):"
    echo "    • nginx package"
    echo "    • python3"
    echo "    • wazuh-manager / wazuh-agent"
    echo "    • www-data user"
    echo "    • Previous backups (${BACKUP_ROOT}/backup-eyemole-*)"
    echo ""

    if [[ "$PURGE" -eq 0 ]]; then
        echo "  To fully remove preserved data later:"
        echo "    sudo rm -rf ${PRESERVE_ROOT}"
        echo ""
    fi

    echo "  To verify manifest integrity:"
    echo "    cd ${BACKUP_DIR} && sha256sum -c MANIFEST.sha256"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Uninstall complete."
    echo "═══════════════════════════════════════════════════════════════"
}

# =============================================================================
# Main orchestration
# =============================================================================
main() {
    # 1. Parse args
    parse_args "$@"

    # Show help has no side effects
    # (handled inside parse_args via usage)

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  EyeMole Safe Uninstaller"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # 2. Root check (skip in dry-run for convenience)
    if [[ "$DRY_RUN" -eq 0 ]]; then
        check_root
    else
        if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
            warn "Not running as root. Dry-run can still show plan, but inventory may be incomplete."
        fi
    fi

    # 3. Preflight / path validation
    preflight_validate

    # 4. Inventory
    inventory

    # 5. Dry-run output
    if [[ "$DRY_RUN" -eq 1 ]]; then
        show_dry_run
        exit 0
    fi

    # 6. Purge confirmation
    confirm_purge

    # 7. Backup (with space check)
    create_backup

    # 8. Stop/disable services
    stop_services

    # 9. Remove Nginx integration (with rollback)
    remove_nginx_integration

    # 10. Remove systemd units + daemon-reload
    remove_systemd_units

    # 11. Remove PolicyKit/legacy artifacts
    remove_polkit_and_legacy

    # 12. Preserve data OR purge
    preserve_data
    purge_data

    # 13. Remove application directories
    remove_app_directories

    # 14. Final validations
    final_validations

    # 15. Optional user removal
    remove_app_user

    # 16. Final report
    final_report
}

# =============================================================================
# Source guard — allow sourcing for testing without executing
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
