#!/usr/bin/env bash
###############################################################################
# WPHACKFIX - WordPress malware / hack cleanup helper
# Usage: ./wp-hack-fix.bash [wp-username-to-reset]
###############################################################################

set -euo pipefail

set -E
shopt -s inherit_errexit 2>/dev/null || true

###############################################################################
# Logging Setup
###############################################################################

SCRIPT_NAME="$(basename "$0")"
SITE_NAME="$(basename "$(pwd)")"
LOG_DIR="/tmp/logs-$SITE_NAME"
MAIN_LOG="${LOG_DIR}/wp-hackfix.log"
REMOVED_LOG="${LOG_DIR}/wp-hackfix-removed.log"

mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date '+%F %T')"
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    printf '[%s] [%s] %s\n' "$ts" "$level" "$msg" | tee -a "$MAIN_LOG" || true
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

###############################################################################
# Better error output for failed commands
###############################################################################
on_error() {
    local exit_code=$?
    local line_no="${BASH_LINENO[0]:-unknown}"
    local cmd="${BASH_COMMAND:-unknown}"

    echo
    log "ERROR" "Command failed!"
    log "ERROR" "Exit code : ${exit_code}"
    log "ERROR" "Line      : ${line_no}"
    log "ERROR" "Command   : ${cmd}"
    echo

    # Exit explicitly so it doesn't "quietly quit"
    exit "$exit_code"
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

###############################################################################
# Domains to skip (folder names under /home)
###############################################################################

SKIP_DOMAINS=(
    "backlinksgenerator.in"
    "dssinfotech.co.in"
)

###############################################################################
# Auto-detect WordPress installations
# - If current dir is WP root -> scan ONLY current directory
# - Else -> scan /home public_html installs
###############################################################################

WP_PATHS=()
USERNAME="${1:-}"

is_wp_root_dir() {
    [[ -f "./wp-config.php" ]]
}

if is_wp_root_dir; then
    log "INFO" "WordPress detected in current directory. Scanning only: $(pwd)"
    WP_PATHS+=("$(pwd)")
else
    WP_BASE="/home"
    log "INFO" "No wp-config.php in current directory. Scanning under: $WP_BASE"

    while IFS= read -r -d '' cfg; do
        wp_root="$(dirname "$cfg")"
        WP_PATHS+=("$wp_root")
    done < <(find "$WP_BASE" -type f -name wp-config.php -path "*/public_html/*" -print0)

    if [[ "${#WP_PATHS[@]}" -eq 0 ]]; then
        log "INFO" "No WordPress installations found under $WP_BASE"
        exit 0
    fi
fi

echo
log "INFO" "Detected ${#WP_PATHS[@]} WordPress installation(s)"
echo

###############################################################################
# Cleanup Function (your original logic preserved)
###############################################################################

run_wp_cleanup() {
    local WP_ROOT="$1"
    local USERNAME="$2"

    cd "$WP_ROOT"

    LOG_DIR="$WP_ROOT/logs"
    mkdir -p "$LOG_DIR"
    chmod 700 "$LOG_DIR"
    
    QUAR_DIR="${LOG_DIR}/quarantine"
    mkdir -p "$QUAR_DIR"
    chmod 700 "$QUAR_DIR"


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

    PLUGIN_EXCEPTIONS=(
        "all-in-one-wp-migration-gdrive-extension"
        "astra-addon"
    )

    COMMON_PLUGINS_UPGRADE=(
        "litespeed-cache"
        "contact-form-7"
        "sg-security"
    )

    THEMES_TO_REMOVE=(
        "twentytwentytwo"
        "twentytwentythree"
        "twentytwentyfour"
        "twentytwentyfive"
    )

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

    quarantine_file() {
        local src="$1"
    
        [[ ! -f "$src" ]] && return 0
    
        # Make a safe filename based on original path
        local safe_name
        safe_name="$(echo "$src" | sed 's|/|__|g')"
    
        # Unique timestamp suffix
        local ts
        ts="$(date '+%Y%m%d_%H%M%S')"
    
        local dest="${QUAR_DIR}/${ts}__${safe_name}"
    
        # Hash before moving (best effort)
        local hash="na"
        if command -v sha256sum >/dev/null 2>&1; then
            hash="$(sha256sum "$src" | awk '{print $1}')" || hash="na"
        fi
    
        # Move file into quarantine (preserve file)
        mv -f -- "$src" "$dest"
    
        # Make it completely unusable
        chmod 000 "$dest" || true
    
        log_removed "QUARANTINED: $src  ->  $dest  (sha256=$hash)"
        log "WARN" "Quarantined infected file: $src  ->  $dest"
    }
    
    remove_infected_wpcontent_php_files() {
        echo
        log "INFO" "Scanning wp-content for infected/backdoor PHP files (quarantine mode)..."
    
        local wpcontent_dir="wp-content"
        [[ ! -d "$wpcontent_dir" ]] && log "WARN" "wp-content not found, skipping scan." && return 0
    
        # Strong malware/backdoor indicators (covers your sample + common droppers)
        # Keep specific to reduce false positives.
        local patterns=(
            "md5\(.*md5\("                         # md5 gate
            "base64_decode"                        # payload decode
            "file_put_contents"                    # dropper write
            "fopen\(" "fwrite\("                   # file write
            "\$_POST" "\$_REQUEST"                 # control channel
            "eval\("                               # execution
            "assert\("                             # execution
            "gzinflate\(" "gzuncompress\("         # unpack
            "str_rot13\("                          # obfuscation
            "preg_replace\(.*/e"                   # legacy RCE
            "shell_exec\(" "passthru\(" "system\(" "exec\(" "popen\(" "proc_open\("
            "curl_exec\(" "fsockopen\(" "stream_socket_client\("
            "php:\/\/input"                        # webshell io
        )
    
        local rx
        rx="$(printf "%s|" "${patterns[@]}")"
        rx="${rx%|}"
    
        # Scan zones (aggressive where infections usually live)
        local scan_dirs=(
            "wp-content/uploads"
            "wp-content/cache"
            "wp-content/mu-plugins"
            "wp-content/plugins"
            "wp-content/themes"
            "wp-content"
        )
    
        local scanned=0
        local quarantined=0
    
        for dir in "${scan_dirs[@]}"; do
            [[ ! -d "$dir" ]] && continue
    
            # Find PHP files. No pipefail risk.
            while IFS= read -r -d '' f; do
                scanned=$((scanned + 1))
    
                # skip WP normal placeholder index.php files
                if [[ "$(basename "$f")" == "index.php" ]]; then
                    continue
                fi
    
                # optional: do not touch plugin/theme main bootstrap files too aggressively
                # but still allow if they match heavy patterns like eval/base64/file_put_contents
                if grep -Eqi "$rx" "$f" 2>/dev/null; then
                    quarantine_file "$f"
                    quarantined=$((quarantined + 1))
                fi
    
            done < <(find "$dir" -type f -name "*.php" -print0 2>/dev/null || true)
        done
    
        log "INFO" "wp-content malware scan complete. Scanned=$scanned, Quarantined=$quarantined"
        log "INFO" "Quarantine location: $QUAR_DIR"
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

            [[ -z "$pass1" ]] && echo "Password cannot be empty. Try again." && continue
            [[ "$pass1" != "$pass2" ]] && echo "Passwords do not match. Try again." && continue
            break
        done

        wp_run user update "$username" --by=login --user_pass="$pass1" >/dev/null 2>&1
        log "INFO" "Password updated successfully for user: ${username}"

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
                wp_run plugin update "$plugin" >/dev/null 2>&1
                log "INFO" "Plugin '${plugin}' upgraded to latest version."
            fi
        done
    }

    remove_plugin_if_exists() {
        local plugin="${1:-}"
        [[ -z "$plugin" ]] && return 0

        echo
        echo "Checking for plugin/malware to remove: $plugin"

        if wp_run plugin is-installed "$plugin" >/dev/null 2>&1; then
            wp_run plugin deactivate "$plugin" >/dev/null 2>&1 || true
        fi

        local candidates=(
            "wp-content/plugins/$plugin"
            "wp-content/plugins/$plugin.php"
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

        [[ "$found_any" == false ]] && echo "No matching files/dirs found for '$plugin'. Skipping."
    }

    ###############################################################################
    # Kill active malicious processes before cleanup
    ###############################################################################

    kill_malicious_activity() {
        echo
        log "INFO" "Stopping active processes for user: $WP_OWNER"

        pkill -9 -u "$WP_OWNER" php || true
        pkill -9 -u "$WP_OWNER" php-fpm || true

        for proc in bash sh curl wget perl python python3 nc ncat socat; do
            pkill -9 -u "$WP_OWNER" "$proc" || true
        done

        ps -u "$WP_OWNER" -o pid,cmd --no-headers \
            | grep "$PWD" \
            | awk '{print $1}' \
            | xargs -r kill -9 || true

        log "INFO" "Malicious activity suppressed for $WP_OWNER"
    }

    reinstall_all_plugins() {
        echo
        log "INFO" "Reinstalling plugins (with exceptions)..."

        local plugin_list
        plugin_list="$(wp_run plugin list --fields=name,version --format=csv 2>/dev/null || true)"

        [[ -z "$plugin_list" ]] && log "INFO" "No plugins found." && return 0

        echo "$plugin_list" | tail -n +2 | while IFS=',' read -r name version; do
            local plugin="$name"
            local ver="$version"

            echo "-----"
            echo "Plugin: $plugin"

            if [[ -n "$ver" && "$ver" != "none" ]]; then
                if wp_run plugin install "$plugin" --force --version="$ver" >/dev/null 2>&1; then
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
        echo "Processing themes..."

        local themes
        themes="$(wp_run theme list --fields=name,version --format=csv 2>/dev/null || true)"

        [[ -z "$themes" ]] && echo "No themes installed. Skipping theme processing." && return 0

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

    reinstall_core_and_cleanup() {
        echo
        log "INFO" "Reinstalling WordPress core..."
        local core_version
        core_version="$(wp_run core version)"
        wp_run core download --force --version="$core_version" --skip-content

        echo
        log "INFO" "Removing rogue core files..."
        
        rogue_files="$(
          wp_run core verify-checksums 2>&1 \
            | grep 'should not exist:' \
            | cut -d : -f 3- || true
        )"
        
        if [[ -z "${rogue_files}" ]]; then
          log "INFO" "No rogue core files detected."
        else
          while IFS= read -r file; do
            [[ -f "$file" ]] && rm -fv -- "$file"
          done <<< "$rogue_files"
        fi

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

    scan_suspicious_core_files() {
        echo
        log "INFO" "Scanning wp-config.php and index.php for suspicious functions..."
        echo "If any match is NOT part of normal WordPress core, investigate immediately."
        echo

        grep -E -n --color=auto "$SUSPICIOUS_REGEX" wp-config.php index.php || true
    }

    main() {
        local username="${1:-}"

        kill_malicious_activity
        reinstall_core_and_cleanup

        echo
        log "INFO" "Removing known bad plugins (if present)..."
        local bad
        for bad in "${BAD_PLUGINS[@]}"; do
            remove_plugin_if_exists "$bad"
        done

        remove_infected_wpcontent_php_files

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

for site in "${WP_PATHS[@]}"; do

    # If scanning /home, DOMAIN logic applies. If scanning current WP, skip this.
    if [[ "$site" != "$(pwd)" ]]; then
        DOMAIN="$(basename "$(dirname "$site")")"
        if printf '%s\n' "${SKIP_DOMAINS[@]}" | grep -qx "$DOMAIN"; then
            echo "Skipping domain: $DOMAIN"
            continue
        fi
    fi

    echo
    echo "========================================"
    echo "Processing site: $site"
    echo "========================================"

    run_wp_cleanup "$site" "$USERNAME"
done

echo
echo "All WordPress sites processed."
