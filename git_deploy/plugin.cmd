#!/bin/bash

# Detect OLSPanel base directory
BASE_DIR="/usr/local/olspanel/mypanel"
if [ ! -d "$BASE_DIR" ]; then
  # Fallback to local discovery
  BASE_DIR="$(pwd)"
  if [ ! -f "$BASE_DIR/manage.py" ]; then
    BASE_DIR="$(dirname "$(dirname "$BASE_DIR")")"
  fi
fi

# Define source and destination paths
MODULE_SRC="$BASE_DIR/3rdparty/git_deploy/modules/git_deploy"
MODULE_DEST="$BASE_DIR/modules/git_deploy"
ICON_SRC="$BASE_DIR/3rdparty/git_deploy/plugin_icon.svg"
ICON_DEST="$BASE_DIR/media/icon/git_deploy.svg"

# Copy dynamic Django module to the system modules directory
if [ -d "$MODULE_SRC" ]; then
  mkdir -p "$MODULE_DEST"
  cp -rf "$MODULE_SRC"/* "$MODULE_DEST"/
  chown -R www-data:www-data "$MODULE_DEST"
  echo "✅ Django module copied to $MODULE_DEST"
else
  echo "❌ Error: Django module source not found: $MODULE_SRC"
  exit 1
fi

# Deploy SVG vector icon for color adaptation support
if [ -f "$ICON_SRC" ]; then
  cp -f "$ICON_SRC" "$ICON_DEST"
  chown www-data:www-data "$ICON_DEST"
  echo "✅ SVG vector icon deployed to $ICON_DEST"
else
  echo "❌ Error: SVG icon source not found: $ICON_SRC"
  exit 1
fi

# Restart the panel service asynchronously to compile and register the new module
if systemctl is-active --quiet cp 2>/dev/null; then
  (sleep 2 && systemctl restart cp) &
  echo "🔄 Scheduled OLSPanel backend restart..."
fi

echo "🎉 Git Deploy hook script completed successfully."
