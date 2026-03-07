#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/xinxin7/claw-shield.git"
EXT_DIR="${HOME}/.openclaw/extensions/claw-shield"
PROJECT_ID_DIR="${HOME}/.openclaw/plugins/claw-shield"

BOLD="\033[1m"
DIM="\033[2m"
CYAN="\033[36m"
GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

info()  { echo -e "${CYAN}${BOLD}▸${RESET} $1"; }
ok()    { echo -e "${GREEN}${BOLD}✓${RESET} $1"; }
fail()  { echo -e "${RED}${BOLD}✗${RESET} $1"; exit 1; }

echo ""
echo -e "${BOLD}  Claw Shield Installer${RESET}"
echo -e "${DIM}  AI Agent Governance Layer${RESET}"
echo ""

# ── Pre-flight checks ──────────────────────────────────────────────
command -v git >/dev/null 2>&1 || fail "git is required but not found"
command -v npm >/dev/null 2>&1 || fail "npm is required but not found"
command -v node >/dev/null 2>&1 || fail "node is required but not found"

# ── Download ────────────────────────────────────────────────────────
info "Downloading Claw Shield..."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git clone --depth 1 --quiet "$REPO" "$tmp/claw-shield"

# ── Install plugin ──────────────────────────────────────────────────
info "Installing plugin to ${DIM}${EXT_DIR}${RESET}"
rm -rf "$EXT_DIR"
mkdir -p "$(dirname "$EXT_DIR")"
cp -r "$tmp/claw-shield/client" "$EXT_DIR"
(cd "$EXT_DIR" && npm install --omit=dev --silent 2>/dev/null)
ok "Plugin installed"

# ── Preserve project identity ───────────────────────────────────────
if [ -f "${PROJECT_ID_DIR}/.project-id" ]; then
  ok "Project ID preserved ($(cat "${PROJECT_ID_DIR}/.project-id" | cut -c1-8)...)"
else
  info "A unique Project ID will be generated on first run"
fi

# ── Restart OpenClaw ────────────────────────────────────────────────
info "Restarting OpenClaw..."
if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active openclaw-gateway.service >/dev/null 2>&1; then
  systemctl --user restart openclaw-gateway.service
elif command -v openclaw >/dev/null 2>&1; then
  openclaw gateway restart 2>/dev/null || true
else
  echo -e "  ${DIM}Could not auto-restart. Please restart OpenClaw manually.${RESET}"
fi

sleep 3

# ── Verify ──────────────────────────────────────────────────────────
info "Verifying installation..."
STATUS=$(curl -sS --max-time 5 "http://127.0.0.1:18789/api/plugins/claw-shield/status" 2>/dev/null || echo "")
if echo "$STATUS" | grep -q '"ok":true'; then
  ok "Claw Shield is active and protecting your agent traffic"
  echo ""
  DASHBOARD_URL=$(echo "$STATUS" | grep -oP '"dashboardUrl"\s*:\s*"\K[^"]+' 2>/dev/null || echo "")
  if [ -n "$DASHBOARD_URL" ]; then
    echo -e "  ${BOLD}Dashboard:${RESET} ${CYAN}${DASHBOARD_URL}${RESET}"
  fi
  echo -e "  ${BOLD}Status:${RESET}    http://127.0.0.1:18789/api/plugins/claw-shield/status"
  echo ""
else
  echo -e "  ${DIM}OpenClaw may still be starting. Check status at:${RESET}"
  echo -e "  curl http://127.0.0.1:18789/api/plugins/claw-shield/status"
  echo ""
fi
