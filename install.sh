#!/usr/bin/env bash
set -Eeuo pipefail
REPOSITORY=https://github.com/encondata/hackspacelabs-web.git
main() {
  local destination origin checkout_root checkout_status checkout_branch
  local access_mode=keep lan_ip=
  case "${1:-}" in
    --lan-ip) access_mode=lan; lan_ip=${2:?Provide your private LAN IPv4 address} ;;
    --https) access_mode=https ;;
    '') ;;
    *) echo 'Usage: install.sh [--lan-ip PRIVATE_IP | --https]' >&2; exit 1 ;;
  esac
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
  # Capture the quoted path now: Bash may unwind local variables before EXIT.
  trap "rmdir -- $(printf '%q' "$lock")" EXIT
  # Unraid shares can be owned by a different UID. Trust only the chosen path,
  # for this command invocation; never change global Git trust settings.
  local -a checkout_git=(git -c "safe.directory=$destination" -C "$destination")
  if [[ -d "$destination/.git" ]]; then
    checkout_root=$("${checkout_git[@]}" rev-parse --show-toplevel)
    [[ "$checkout_root" == "$destination" ]] || exit 1
    origin=$("${checkout_git[@]}" remote get-url origin)
    [[ "$origin" == "$REPOSITORY" || "$origin" == 'git@github.com:encondata/hackspacelabs-web.git' ]] || { echo 'Destination is a different repository; refusing to change it.' >&2; exit 1; }
    checkout_status=$("${checkout_git[@]}" status --porcelain)
    [[ -z "$checkout_status" ]] || { echo 'Commit or stash local source changes before updating. deployment/.env is preserved.' >&2; exit 1; }
    checkout_branch=$("${checkout_git[@]}" branch --show-current)
    [[ "$checkout_branch" == main ]] || { echo 'Switch this checkout to main before updating.' >&2; exit 1; }
    "${checkout_git[@]}" pull --ff-only origin main
  else
    [[ -z "$(ls -A -- "$destination")" ]] || { echo 'Destination must be empty or an existing HackSpaceLabs checkout.' >&2; exit 1; }
    git clone --branch main --single-branch "$REPOSITORY" "$destination"
  fi
  echo "Building source commit: $("${checkout_git[@]}" rev-parse --short HEAD)"
  bash "$destination/deployment/scripts/setup.sh" "$destination" "$access_mode" "$lan_ip"
  rmdir -- "$lock"
  trap - EXIT
}
main "$@"
