#!/usr/bin/env bash
###############################################################################
# WPHACKFIX - WordPress malware / hack cleanup helper
# Usage: ./wp-hack-fix.bash [wp-username-to-reset]
###############################################################################


###############################################################################
# Auto-detect WordPress installations
###############################################################################


set -euo pipefail

WP_BASE="/home"
WP_PATHS=()

while IFS= read -r -d '' cfg; do
    wp_root="$(dirname "$cfg")"
    WP_PATHS+=("$wp_root")
done < <(find "$WP_BASE" -type f -name wp-config.php -path "*/public_html/*" -print0)

if [[ "${#WP_PATHS[@]}" -eq 0 ]]; then
    echo "No WordPress installations found under $WP_BASE"
    exit 0
fi

echo "Detected ${#WP_PATHS[@]} WordPress installation(s)"
echo

SCRIPT_NAME="$(basename "$0")"
SITE_NAME="$(basename "$(pwd)")"
LOG_DIR="./logs-$SITE_NAME"
MAIN_LOG="${LOG_DIR}/wp-hackfix.log"
REMOVED_LOG="${LOG_DIR}/wp-hackfix-removed.log"

mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date '+%F %T')"
    printf '[%s] [%s] %s\n' "$ts" "$level" "$msg" | tee -a "$MAIN_LOG"
}

log_removed() {
    local msg="$*"
    local ts
    ts="$(date '+%F %T')"
    printf '[%s] %s\n' "$ts" "$msg" >> "$REMOVED_LOG"
}

fatal() {
    log "ERROR" "$*"
    exit 1
}

on_error() {
    local exit_code=$?
    local cmd=${BASH_COMMAND:-unknown}
    log "ERROR" "Command failed (exit=${exit_code}): ${cmd}"
    # Do not exit here; set -e will already terminate.
}
trap on_error ERR

killme() {
    if [[ "$SCRIPT_NAME" == "wp-hack-fix.bash" ]]; then
        log "INFO" "Self-destructing script..."
        rm -f -- "$0" || log "WARN" "Failed to remove script, please delete manually."
    else
        log "INFO" "Remember to remove this script manually."
    fi
}
trap killme EXIT

run_wp_cleanup() {
    local WP_ROOT="$1"
    local USERNAME="$2"

    cd "$WP_ROOT" || return

    echo "Starting WordPress Hack Fix Script"
    echo "----------------------------------"
    
    ###############################################################################
    # Safety checks
    ###############################################################################
    
    if [[ ! -f "wp-config.php" ]]; then
        fatal "wp-config.php not found. Run this from the WordPress root."
    fi
    
    if ! command -v wp >/dev/null 2>&1; then
        fatal "wp-cli not installed or not in PATH."
    fi
    
    WP_OWNER="$(stat -c '%U' wp-config.php)"
    WP_GROUP="$(stat -c '%G' wp-config.php)"
    log "INFO" "Detected WordPress owner: ${WP_OWNER}:${WP_GROUP}"
    
    ###############################################################################
    # Configuration
    ###############################################################################
    
    # Plugins that should NEVER be removed even if reinstall fails
    PLUGIN_EXCEPTIONS=(
        "all-in-one-wp-migration-gdrive-extension"
        "astra-addon"
    )
    
    # Common plugins to upgrade to latest version if installed
    COMMON_PLUGINS_UPGRADE=(
        "litespeed-cache"
        "contact-form-7"
        "sg-security"
    )
    
    # Themes to REMOVE (exact folder names)
    THEMES_TO_REMOVE=(
        "twentytwentytwo"
        "twentytwentythree"
        "twentytwentyfour"
        "twentytwentyfive"
    )
    
    # Known bad plugins
    BAD_PLUGINS=(
        "wp-compat"
        "wp-vcd"
        "cache-wordpress"
        "wp-file-manager"
    )
    
    SUSPICIOUS_REGEX='eval\(|base64_decode\(|gzinflate\(|str_rot13\(|gzuncompress\(|assert\(|shell_exec\(|exec\(|passthru\(|system\(|popen\(|proc_open\(|curl_exec\(|fsockopen\(|stream_socket_client\(|preg_replace\(.*/e'
    
    ###############################################################################
    # Helpers
    ###############################################################################
    
    wp_run() {
        # Wrapper to run WP-CLI as the correct user
        if [[ "$(id -u)" -eq 0 ]]; then
            sudo -u "$WP_OWNER" -- wp "$@"
        else
            wp "$@"
        fi
    }
    
    in_array() {
        local needle="$1"; shift
        local item
        for item in "$@"; do
            [[ "$item" == "$needle" ]] && return 0
        done
        return 1
    }
    
    ###############################################################################
    # Password handling
    ###############################################################################
    
    change_wp_user_password() {
        local username="${1:-}"
    
        [[ -z "$username" ]] && return 0
    
        echo
        log "INFO" "Password reset requested for user: ${username}"
    
        if ! wp_run user get "$username" >/dev/null 2>&1; then
            log "WARN" "User '${username}' does not exist. Skipping password change."
            return 0
        fi
    
        local pass1 pass2
        while true; do
            read -r -s -p "Enter new password for user '${username}': " pass1
            echo
            read -r -s -p "Confirm new password: " pass2
            echo
    
            if [[ -z "$pass1" ]]; then
                echo "Password cannot be empty. Try again."
                continue
            fi
    
            if [[ "$pass1" != "$pass2" ]]; then
                echo "Passwords do not match. Try again."
                continue
            fi
            break
        done
    
        if wp_run user update "$username" --by=login --user_pass="$pass1" >/dev/null 2>&1; then
            log "INFO" "Password updated successfully for user: ${username}"
        else
            log "ERROR" "Failed to update password for user: ${username}"
        fi
    
        unset pass1 pass2
    }
    
    ###############################################################################
    # Plugin operations
    ###############################################################################
    
    upgrade_common_plugins() {
        echo
        log "INFO" "Upgrading selected common plugins to latest versions (if installed)..."
    
        local plugin
        for plugin in "${COMMON_PLUGINS_UPGRADE[@]}"; do
            if wp_run plugin is-installed "$plugin" >/dev/null 2>&1; then
                echo "-----"
                echo "Plugin: $plugin"
                if wp_run plugin update "$plugin" >/dev/null 2>&1; then
                    log "INFO" "Plugin '${plugin}' upgraded to latest version."
                else
                    log "WARN" "Upgrade failed for plugin '${plugin}'."
                fi
            fi
        done
    }
    
    remove_plugin_if_exists() {
        local plugin="${1:-}"
        [[ -z "$plugin" ]] && return 0
    
        echo
        echo "Checking for plugin/malware to remove: $plugin"
    
        # Try to deactivate if WP-CLI knows about it
        if wp_run plugin is-installed "$plugin" >/dev/null 2>&1; then
            wp_run plugin deactivate "$plugin" >/dev/null 2>&1 || true
        fi
    
        # 1) Standard plugin locations
        local plugin_dir="wp-content/plugins/$plugin"
        local plugin_file_in_plugins="wp-content/plugins/$plugin.php"
    
        # 2) Generic single-file malware locations (common in infections)
        #    These paths are intentionally aggressive — tune if needed.
        local candidates=(
            "$plugin_dir"
            "$plugin_file_in_plugins"
            "wp-content/$plugin"
            "wp-content/$plugin.php"
            "wp-content/mu-plugins/$plugin"
            "wp-content/mu-plugins/$plugin.php"
        )
    
        local found_any=false
        local target
        for target in "${candidates[@]}"; do
            if [[ -d "$target" ]]; then
                rm -rf -- "$target"
                echo "Removed directory: $target"
                log_removed "Removed directory: $target"
                found_any=true
            elif [[ -f "$target" ]]; then
                rm -f -- "$target"
                echo "Removed file: $target"
                log_removed "Removed file: $target"
                found_any=true
            fi
        done
    
        if [[ "$found_any" == false ]]; then
            echo "No matching files/dirs found for '$plugin'. Skipping."
        fi
    }
    
    
    reinstall_all_plugins() {
        echo
        log "INFO" "Reinstalling plugins (with exceptions)..."
    
        # Cache plugin list to avoid multiple wp calls per plugin
        local plugin_list
        plugin_list="$(wp_run plugin list --fields=name,version --format=csv 2>/dev/null || true)"
    
        if [[ -z "$plugin_list" ]]; then
            log "INFO" "No plugins found."
            return 0
        fi
    
        # Skip CSV header
        echo "$plugin_list" | tail -n +2 | while IFS=',' read -r name version; do
            local plugin="$name"
            local version="$version"
    
            echo "-----"
            echo "Plugin: $plugin"
    
            if [[ -n "$version" && "$version" != "none" ]]; then
                if wp_run plugin install "$plugin" --force --version="$version" >/dev/null 2>&1; then
                    echo "Reinstalled successfully"
                    continue
                fi
            fi
    
            if wp_run plugin install "$plugin" --force >/dev/null 2>&1; then
                echo "Reinstalled successfully"
                continue
            fi
    
            echo "Reinstall failed for plugin: $plugin"
    
            if in_array "$plugin" "${PLUGIN_EXCEPTIONS[@]}"; then
                echo "Plugin is in exception list, skipping removal"
                continue
            fi
    
            remove_plugin_if_exists "$plugin"
        done
    }
    
    ###############################################################################
    # Theme operations
    ###############################################################################
    
    remove_selected_themes() {
        echo
        log "INFO" "Removing selected themes (no reinstall)..."
    
        local theme theme_path
        for theme in "${THEMES_TO_REMOVE[@]}"; do
            echo "-----"
            echo "Theme: $theme"
            theme_path="wp-content/themes/$theme"
    
            if [[ -d "$theme_path" ]]; then
                rm -rf -- "$theme_path"
                echo "Removed theme: $theme_path"
                log_removed "Removed theme: $theme"
            else
                echo "Theme not found, skipping"
            fi
        done
    }
    
    reinstall_all_themes() {
        echo
        log "INFO" "Reinstalling all themes (skipping unknown/custom ones)..."
        echo
        echo "Processing themes..."
    
        local themes
        themes="$(wp_run theme list --fields=name,version --format=csv 2>/dev/null || true)"
    
        if [[ -z "$themes" ]]; then
            echo "No themes installed. Skipping theme processing."
            return 0
        fi
    
        echo "$themes" | tail -n +2 | while IFS=',' read -r name version; do
            local theme="$name"
            local ver="$version"
    
            echo "-----"
            echo "Theme: $theme"
    
            if [[ -n "$ver" && "$ver" != "none" ]]; then
                if wp_run theme install "$theme" --force --version="$ver" >/dev/null 2>&1; then
                    echo "Reinstalled successfully"
                    continue
                fi
            fi
    
            if wp_run theme install "$theme" --force >/dev/null 2>&1; then
                echo "Reinstalled successfully"
            else
                echo "Theme not found in repository, skipping"
            fi
        done
    }
    
    ###############################################################################
    # Core operations
    ###############################################################################
    
    reinstall_core_and_cleanup() {
        echo
        log "INFO" "Reinstalling WordPress core..."
        local core_version
        core_version="$(wp_run core version)"
        wp_run core download --force --version="$core_version" --skip-content
    
        echo
        log "INFO" "Removing rogue core files..."
        wp_run core verify-checksums 2>&1 \
            | grep 'should not exist:' \
            | cut -d : -f 3- \
            | while read -r file; do
                  [[ -f "$file" ]] && rm -fv -- "$file"
              done
    
        echo
        log "INFO" "Reinstalling WordPress core (second pass)..."
        core_version="$(wp_run core version)"
        wp_run core download --force --version="$core_version" --skip-content
    
        echo
        log "INFO" "Hardening wp-config.php for WP-CLI compatibility..."
        sed -i 's|^add_filter|if (function_exists("add_filter")) add_filter|g' wp-config.php
        sed -i 's|^add_action|if (function_exists("add_action")) add_action|g' wp-config.php
    
        chown "$WP_OWNER:$WP_GROUP" wp-config.php
    }
    
    ###############################################################################
    # Malware indicators
    ###############################################################################
    
    scan_suspicious_core_files() {
        echo
        log "INFO" "Scanning wp-config.php and index.php for suspicious functions..."
        echo "If any match is NOT part of normal WordPress core, investigate immediately."
        echo
    
        grep -E -n --color=auto "$SUSPICIOUS_REGEX" wp-config.php index.php || true
    }
    
    ###############################################################################
    # Main
    ###############################################################################
    
    main() {
        local username="${1:-}"
    
        reinstall_core_and_cleanup
    
        echo
        log "INFO" "Removing known bad plugins (if present)..."
        local bad
        for bad in "${BAD_PLUGINS[@]}"; do
            remove_plugin_if_exists "$bad"
        done
    
        reinstall_all_plugins
        remove_selected_themes
        reinstall_all_themes
    
        echo
        log "INFO" "Final core checksum verification..."
        wp_run core verify-checksums
    
        echo
        log "INFO" "Upgrading selected plugins to latest versions..."
        upgrade_common_plugins
    
        scan_suspicious_core_files
        change_wp_user_password "$username"
    
        echo
        echo "All done!"
        log "INFO" "Cleanup completed."
    }

    main "$USERNAME"
}

###############################################################################
# RUN CLEANUP FOR ALL SITES
###############################################################################

USERNAME="${1:-}"

for site in "${WP_PATHS[@]}"; do
    echo
    echo "========================================"
    echo "Processing site: $site"
    echo "========================================"

    run_wp_cleanup "$site" "$USERNAME" || echo "Skipped $site due to error"
done

echo
echo "All WordPress sites processed."

