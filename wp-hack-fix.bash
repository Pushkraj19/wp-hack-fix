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

echo "Detected WordPress owner: $WP_OWNER:$WP_GROUP"

### Wrapper to run WP-CLI as correct user
wp_run() {
    if [ "$(id -u)" -eq 0 ]; then
        sudo -u "$WP_OWNER" wp "$@"
    else
        wp "$@"
    fi
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
echo "Reinstalling plugins (only removing failed ones)..."

wp_run plugin list --fields=name | grep -v '^name' | while read -r plugin; do
    echo "-----"
    echo "Plugin: $plugin"

    PLUGIN_PATH="wp-content/plugins/$plugin"

    VERSION=$(wp_run plugin list --name="$plugin" --fields=version | grep -v '^version' || true)

    # Attempt reinstall
    if [ -n "$VERSION" ]; then
        if wp_run plugin install "$plugin" --force --version="$VERSION" >/dev/null 2>&1; then
            echo "Reinstalled successfully"
            continue
        fi
    else
        if wp_run plugin install "$plugin" --force >/dev/null 2>&1; then
            echo "Reinstalled successfully"
            continue
        fi
    fi

    # If we reach here, reinstall FAILED
    echo "Reinstall failed for plugin: $plugin"

    if [ -d "$PLUGIN_PATH" ]; then
        echo "Removing failed plugin directory..."
        rm -rf "$PLUGIN_PATH"
        echo "Removed: $PLUGIN_PATH"
        echo "$(date '+%F %T') Removed failed plugin: $plugin" >> wp-hackfix-removed.log
    else
        echo "Plugin directory not found, nothing to remove"
    fi
done



echo
echo "Reinstalling all themes..."
wp_run theme list --fields=name | grep -v '^name' | while read -r theme; do
    echo "-----"
    echo "Theme: $theme"
    VERSION=$(wp_run theme list --name="$theme" --fields=version | grep -v '^version')
    wp_run theme install "$theme" --force --version="$VERSION"
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
