#!/bin/bash
#############
# WPHACKFIX #
#############

set -euo pipefail

echo "Starting WordPress Hack Fix Script"
echo "----------------------------------"

### Safety check
if [ ! -f wp-config.php ]; then
    echo "Error: wp-config.php not found. Run this from WordPress root."
    exit 1
fi

### Detect WordPress owner
WP_OWNER=$(stat -c '%U' wp-config.php)
WP_GROUP=$(stat -c '%G' wp-config.php)

# Plugins that should NEVER be removed even if reinstall fails
PLUGIN_EXCEPTIONS=(
    "all-in-one-wp-migration-gdrive-extension"
)

# Themes to REMOVE (exact folder names)
THEMES_TO_REMOVE=(
    "twentytwentytwo"
    "twentytwentythree"
    "twentytwentyfour"
    "twentytwentyfive"
)

echo "Detected WordPress owner: $WP_OWNER:$WP_GROUP"

### Wrapper to run WP-CLI as correct user
wp_run() {
    if [ "$(id -u)" -eq 0 ]; then
        sudo -u "$WP_OWNER" wp "$@"
    else
        wp "$@"
    fi
}

# Helper: check if value exists in array
in_array() {
    local needle="$1"
    shift
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

### Verify WP-CLI exists
if ! command -v wp >/dev/null 2>&1; then
    echo "Error: wp-cli not installed."
    exit 1
fi

echo
echo "Reinstalling WordPress core..."
CORE_VERSION=$(wp_run core version)
wp_run core download --force --version="$CORE_VERSION" --skip-content

echo
echo "Removing rogue core files..."
wp_run core verify-checksums 2>&1 \
| grep 'should not exist:' \
| cut -d : -f 3- \
| while read -r file; do
    [ -f "$file" ] && rm -fv "$file"
done

echo
echo "Reinstalling WordPress core..."
CORE_VERSION=$(wp_run core version)
wp_run core download --force --version="$CORE_VERSION" --skip-content

echo
echo "Hardening wp-config.php for WP-CLI..."
sed -i 's|^add_filter|if (function_exists("add_filter")) add_filter|g' wp-config.php
sed -i 's|^add_action|if (function_exists("add_action")) add_action|g' wp-config.php

chown "$WP_OWNER:$WP_GROUP" wp-config.php

echo
echo "Reinstalling plugins (with exceptions)..."

wp_run plugin list --fields=name | grep -v '^name' | while read -r plugin; do
    echo "-----"
    echo "Plugin: $plugin"

    VERSION=$(wp_run plugin list --name="$plugin" --fields=version | grep -v '^version' || true)

    # Attempt reinstall
    if [ -n "$VERSION" ]; then
        wp_run plugin install "$plugin" --force --version="$VERSION" >/dev/null 2>&1 && {
            echo "Reinstalled successfully"
            continue
        }
    else
        wp_run plugin install "$plugin" --force >/dev/null 2>&1 && {
            echo "Reinstalled successfully"
            continue
        }
    fi

    # Reinstall failed
    echo "Reinstall failed for plugin: $plugin"

    # Check exception list
    if in_array "$plugin" "${PLUGIN_EXCEPTIONS[@]}"; then
        echo "Plugin is in exception list, skipping removal"
        continue
    fi

    PLUGIN_DIR="wp-content/plugins/$plugin"
    PLUGIN_FILE="wp-content/plugins/$plugin.php"

    if [ -d "$PLUGIN_DIR" ]; then
        rm -rf "$PLUGIN_DIR"
        echo "Removed plugin directory: $PLUGIN_DIR"
        echo "$(date '+%F %T') Removed plugin directory: $plugin" >> wp-hackfix-removed.log

    elif [ -f "$PLUGIN_FILE" ]; then
        rm -f "$PLUGIN_FILE"
        echo "Removed plugin file: $PLUGIN_FILE"
        echo "$(date '+%F %T') Removed plugin file: $plugin.php" >> wp-hackfix-removed.log

    else
        echo "Nothing found to remove for plugin: $plugin"
    fi
done

echo
echo "Removing selected themes (no reinstall)..."

for theme in "${THEMES_TO_REMOVE[@]}"; do
    echo "-----"
    echo "Theme: $theme"

    THEME_PATH="wp-content/themes/$theme"

    if [ -d "$THEME_PATH" ]; then
        rm -rf "$THEME_PATH"
        echo "Removed theme: $THEME_PATH"
        echo "$(date '+%F %T') Removed theme: $theme" >> wp-hackfix-removed.log
    else
        echo "Theme not found, skipping"
    fi
done

echo
echo "Reinstalling all themes (skipping unknown/custom ones)..."

wp_run theme list --fields=name | grep -v '^name' | while read -r theme; do
    echo "-----"
    echo "Theme: $theme"

    VERSION=$(wp_run theme list --name="$theme" --fields=version | grep -v '^version' || true)

    if [ -n "$VERSION" ]; then
        if wp_run theme install "$theme" --force --version="$VERSION" >/dev/null 2>&1; then
            echo "Reinstalled successfully"
        else
            echo "Theme not found in repository, skipping"
        fi
    else
        if wp_run theme install "$theme" --force >/dev/null 2>&1; then
            echo "Reinstalled successfully"
        else
            echo "Theme not found in repository, skipping"
        fi
    fi
done


echo
echo "Final core checksum verification..."
wp_run core verify-checksums

echo
echo "Scanning wp-config.php and index.php for suspicious PHP functions..."
echo "If any match is NOT part of normal WordPress core, investigate immediately."
echo

SUSPICIOUS_REGEX='eval\(|base64_decode\(|gzinflate\(|str_rot13\(|gzuncompress\(|assert\(|shell_exec\(|exec\(|passthru\(|system\(|popen\(|proc_open\(|curl_exec\(|fsockopen\(|stream_socket_client\(|preg_replace\(.*/e'

grep -E -n --color=auto "$SUSPICIOUS_REGEX" wp-config.php index.php || true

echo
echo "All done!"

### Self-destruct if script name matches
killme() {
    if [[ "$(basename "$0")" == "wp-hack-fix.bash" ]]; then
        echo -n "Self-destructing script... "
        sleep 1
        rm -fv "$0"
    else
        echo "Remember to remove this script manually."
    fi
}

trap killme EXIT
