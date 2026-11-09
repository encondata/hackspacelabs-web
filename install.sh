#!/usr/bin/env bash
set -Eeuo pipefail
REPOSITORY=https://github.com/encondata/hackspacelabs-web.git
main() {
  local destination origin
  for command in git docker openssl; do
    command -v "$command" >/dev/null || { echo "Install $command first." >&2; exit 1; }
  done
  docker compose version >/dev/null || { echo 'Docker Compose v2+ is required.' >&2; exit 1; }
  docker info >/dev/null 2>&1 || { echo 'Docker is unavailable. Start Docker and check your permissions.' >&2; exit 1; }
  read -r -p 'Install directory [/mnt/user/hackspacelabs_web]: ' destination
  destination=${destination:-/mnt/user/hackspacelabs_web}
  [[ "$destination" == /* && "$destination" != / ]] || { echo 'Use an absolute directory other than /.' >&2; exit 1; }
  mkdir -p -- "$destination"
  destination=$(cd -- "$destination" && pwd -P)
  # Lock outside the checkout; a failed install leaves the code and data intact.
  local lock="${destination}.install-lock"
  mkdir -- "$lock" 2>/dev/null || { echo "Install already running, or stale lock: $lock" >&2; exit 1; }
  trap 'rmdir -- "$lock"' EXIT
  if [[ -d "$destination/.git" ]]; then
    [[ "$(git -C "$destination" rev-parse --show-toplevel)" == "$destination" ]] || exit 1
    origin=$(git -C "$destination" remote get-url origin)
    [[ "$origin" == "$REPOSITORY" || "$origin" == 'git@github.com:encondata/hackspacelabs-web.git' ]] || { echo 'Destination is a different repository; refusing to change it.' >&2; exit 1; }
    [[ -z "$(git -C "$destination" status --porcelain)" ]] || { echo 'Commit or stash local source changes before updating. deployment/.env is preserved.' >&2; exit 1; }
    [[ "$(git -C "$destination" branch --show-current)" == main ]] || { echo 'Switch this checkout to main before updating.' >&2; exit 1; }
    git -C "$destination" pull --ff-only origin main
  else
    [[ -z "$(ls -A -- "$destination")" ]] || { echo 'Destination must be empty or an existing HackSpaceLabs checkout.' >&2; exit 1; }
    git clone --branch main --single-branch "$REPOSITORY" "$destination"
  fi
  bash "$destination/deployment/scripts/setup.sh" "$destination"
  rmdir -- "$lock"
  trap - EXIT
}
main "$@"
