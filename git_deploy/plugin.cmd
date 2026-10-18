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

# Define source and destination paths with robust fallback
if [ -d "$BASE_DIR/3rdparty/git_deploy/modules/git_deploy" ]; then
  MODULE_SRC="$BASE_DIR/3rdparty/git_deploy/modules/git_deploy"
elif [ -d "$BASE_DIR/3rdparty/git_deploy/git_deploy/modules/git_deploy" ]; then
  MODULE_SRC="$BASE_DIR/3rdparty/git_deploy/git_deploy/modules/git_deploy"
else
  MODULE_SRC=""
fi
MODULE_DEST="$BASE_DIR/modules/git_deploy"

if [ -f "$BASE_DIR/3rdparty/git_deploy/plugin_icon.svg" ]; then
  ICON_SRC="$BASE_DIR/3rdparty/git_deploy/plugin_icon.svg"
elif [ -f "$BASE_DIR/3rdparty/git_deploy/git_deploy/plugin_icon.svg" ]; then
  ICON_SRC="$BASE_DIR/3rdparty/git_deploy/git_deploy/plugin_icon.svg"
else
  ICON_SRC=""
fi
ICON_DEST="$BASE_DIR/media/icon/git_deploy.svg"

# Copy dynamic Django module to the system modules directory
if [ -n "$MODULE_SRC" ] && [ -d "$MODULE_SRC" ]; then
  mkdir -p "$MODULE_DEST"
  cp -rf "$MODULE_SRC"/* "$MODULE_DEST"/
  chown -R www-data:www-data "$MODULE_DEST" 2>/dev/null || true
  chmod -R 755 "$MODULE_DEST" 2>/dev/null || true
  echo "✅ Django module copied to $MODULE_DEST"
else
  echo "⚠️ Warning: Django module source not found in standard paths"
fi

# Deploy SVG vector icon for color adaptation support
if [ -n "$ICON_SRC" ] && [ -f "$ICON_SRC" ]; then
  mkdir -p "$(dirname "$ICON_DEST")"
  cp -f "$ICON_SRC" "$ICON_DEST"
  chown www-data:www-data "$ICON_DEST" 2>/dev/null || true
  chmod 644 "$ICON_DEST" 2>/dev/null || true
  echo "✅ SVG vector icon deployed to $ICON_DEST"
else
  echo "⚠️ Warning: SVG icon source not found: $ICON_SRC"
fi

# Deploy PNG icon if available
PNG_SRC=""
if [ -f "$BASE_DIR/3rdparty/git_deploy/plugin_icon.png" ]; then
  PNG_SRC="$BASE_DIR/3rdparty/git_deploy/plugin_icon.png"
elif [ -f "$BASE_DIR/3rdparty/git_deploy/git_deploy/plugin_icon.png" ]; then
  PNG_SRC="$BASE_DIR/3rdparty/git_deploy/git_deploy/plugin_icon.png"
fi
if [ -n "$PNG_SRC" ] && [ -f "$PNG_SRC" ]; then
  cp -f "$PNG_SRC" "$BASE_DIR/media/icon/git_deploy.png" 2>/dev/null || true
  chown www-data:www-data "$BASE_DIR/media/icon/git_deploy.png" 2>/dev/null || true
  chmod 644 "$BASE_DIR/media/icon/git_deploy.png" 2>/dev/null || true
fi

# Restart the panel service asynchronously to compile and register the new module
if systemctl is-active --quiet cp 2>/dev/null; then
  (sleep 2 && systemctl restart cp) &
  echo "🔄 Scheduled OLSPanel backend restart..."
fi

echo "🎉 Git Deploy hook script completed successfully."
