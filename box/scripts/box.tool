#!/bin/bash

# Get script directory (useful if sourced or run relatively)
scripts_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# --- Configuration ---
# Assume settings are in /etc/box/settings.ini unless overridden
SETTINGS_FILE="${BOX_SETTINGS_FILE:-/etc/box/settings.ini}"

# --- Load Settings ---
if [[ -f "${SETTINGS_FILE}" ]]; then
 # Source settings carefully, handling potential errors
 set -a # Export all variables defined in the settings file
 source "${SETTINGS_FILE}" || { echo "[ERROR] Failed to source settings file: ${SETTINGS_FILE}" >&2; exit 1; }
 set +a
 # Basic check for essential variables (add more as needed)
 if [[ -z "$bin_name" || -z "$CONF_DIR" || -z "$RUN_DIR" || -z "$BIN_DIR" || -z "$box_user_group" ]]; then
 echo "[ERROR] Essential variables (e.g., bin_name, CONF_DIR, RUN_DIR, BIN_DIR, box_user_group) not defined in ${SETTINGS_FILE}" >&2
 exit 1
 fi
 # Set defaults if variables are missing
 user_agent="${user_agent:-box_for_root}"
 use_ghproxy="${use_ghproxy:-false}"
 url_ghproxy="${url_ghproxy:-https://mirror.ghproxy.com}"
 mihomo_stable="${mihomo_stable:-enable}" # Specific to Clash/Mihomo
 singbox_stable="${singbox_stable:-enable}" # Specific to Sing-box
 update_geo="${update_geo:-true}"
 update_subscription="${update_subscription:-true}" # Mainly for Clash
 custom_rules_subs="${custom_rules_subs:-false}" # Specific to Clash subs
 xclash_option="${xclash_option:-mihomo}" # Specific to Clash
 renew="${renew:-false}" # Used in upsubs logic

 # Define derived paths (ensure consistency with settings.ini)
 box_dir="${CONF_DIR}" # Assuming CONF_DIR is the main base like /data/adb/box
 bin_dir="${BIN_DIR}" # e.g., /usr/local/bin/box or ${CONF_DIR}/bin
 box_run="${RUN_DIR}" # e.g., /run/box
 box_pid="${box_run}/${bin_name}.pid"

 # Config file paths (ensure these match your setup and naming in settings)
 clash_config="${box_dir}/clash/config.yaml"
 clash_provide_config="${box_dir}/clash/providers/sub.yaml" # Example path
 clash_provide_rules="${box_dir}/clash/rulesets/sub_rules.yaml" # Example path
 sing_config_dir="${box_dir}/sing-box" # Directory containing *.json
 xray_config_dir="${box_dir}/xray"
 v2fly_config_dir="${box_dir}/v2fly"
 juicity_config="${box_dir}/juicity/config.json" # Assuming JSON config

 # Ensure runtime directory exists
 mkdir -p "${box_run}" || { echo "[ERROR] Failed to create runtime directory: ${box_run}"; exit 1; }
 chmod 0750 "${box_run}" # Restrict access
 chown "${box_user_group}" "${box_run}" || echo "[WARN] Failed to chown ${box_run} to ${box_user_group}"

 # Ensure bin directory exists
 mkdir -p "${bin_dir}" || { echo "[ERROR] Failed to create binary directory: ${bin_dir}"; exit 1; }

else
 echo "[ERROR] Settings file not found: ${SETTINGS_FILE}" >&2
 exit 1
fi

# --- Colors ---
normal=$(tput sgr0)
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
orange=$(tput setaf 3) # Alias for yellow

# --- Logging Function ---
log() {
 local level="$1"
 shift
 local message="$*"
 case "$level" in
 Info) echo "[INFO] ${message}" ;;
 Debug) echo "[DEBUG] ${message}" ;;
 Warn|Warning) echo "[WARN] ${message}" >&2 ;;
 Error) echo "[ERROR] ${message}" >&2 ;;
 *) echo "[${level}] ${message}" ;;
 esac
}

# --- Determine Download Tool ---
if command -v curl &> /dev/null; then
 rev1="curl --insecure -sL"
 dl_tool="curl"
elif command -v wget &> /dev/null; then
 rev1="wget --no-check-certificate -qO-"
 dl_tool="wget"
else
 log Error "Neither curl nor wget found. Cannot download files."
 exit 1
fi

# --- Helper Functions ---

# Updating files from URLs
upfile() {
 local file="$1"
 local update_url="$2"
 local file_bak="${file}.bak"

 if [ -f "${file}" ]; then
 # Try to create backup
 mv "${file}" "${file_bak}" || { log Error "Failed to backup ${file} to ${file_bak}"; return 1; }
 fi

 # Use ghproxy if enabled and URL matches
 local effective_url="${update_url}"
 if [[ "${use_ghproxy}" == "true" ]] && [[ "${update_url}" == @(https://github.com/*|https://raw.githubusercontent.com/*|https://gist.github.com/*|https://gist.githubusercontent.com/*) ]]; then
 effective_url="${url_ghproxy}/${update_url}"
 log Debug "Using ghproxy: ${effective_url}"
 fi

 local request
 log Debug "Downloading ${effective_url} to ${file}"
 if [[ "$dl_tool" == "curl" ]]; then
 request="curl -L --insecure --user-agent \"${user_agent}\" -o \"${file}\" \"${effective_url}\""
 echo "${yellow}${request}${normal}"
 curl -L --insecure --user-agent "${user_agent}" -o "${file}" "${effective_url}"
 else # wget
 request="wget --no-check-certificate --user-agent=\"${user_agent}\" -O \"${file}\" \"${effective_url}\""
 echo "${yellow}${request}${normal}"
 wget --no-check-certificate --user-agent="${user_agent}" -O "${file}" "${effective_url}"
 fi

 local exit_code=$?
 if [ $exit_code -ne 0 ]; then
 log Error "Download failed (Exit code: $exit_code) for: ${effective_url}"
 # Restore backup if download failed
 if [ -f "${file_bak}" ]; then
 mv "${file_bak}" "${file}" && log Info "Restored backup ${file}" || log Error "Failed to restore backup ${file_bak}"
 fi
 return 1
 else
 log Debug "Download successful."
 # Remove backup on success
 [ -f "${file_bak}" ] && rm -f "${file_bak}"
 return 0
 fi
}

# Restart the binary service
restart_box() {
 local service_name="box-${bin_name}.service" # Assumes systemd naming convention
 log Info "Attempting to restart service: ${service_name}"

 if command -v systemctl &> /dev/null; then
 if systemctl restart "${service_name}"; then
 # Wait a brief moment for the process to potentially start
 sleep 1
 # Check PID after restart attempt
 local PID=""
 PID=$(pidof "${bin_name}") || PID=$( [ -f "${box_pid}" ] && cat "${box_pid}" 2>/dev/null )
 if [[ -n "$PID" ]] && kill -0 "$PID" >/dev/null 2>&1; then
 log Info "${bin_name} restart reported success [$(date +"%F %R")] (PID: $PID)"
 else
 log Error "Service ${service_name} reported restart but process (PID: ${PID:-N/A}) not found or not running."
 # Attempt to disable iptables as a safety measure if restart fails
 "${scripts_dir}/box.iptables" disable >/dev/null 2>&1 || log Warn "Failed to disable iptables after restart failure."
 fi
 else
 log Error "Failed to restart service ${service_name} via systemctl."
 fi
 else
 log Warn "systemctl not found. Cannot restart service automatically. Please restart manually."
 return 1
 fi
}

# Check Configuration
check() {
 local bin_path="${bin_dir}/${bin_name}" # Path to the executable
 local report_file="${box_run}/${bin_name}_report.log"
 rm -f "$report_file" # Clear old report

 log Info "Checking configuration for ${bin_name}..."
 if [ ! -x "${bin_path}" ]; then
 log Error "Binary not found or not executable: ${bin_path}"
 return 1
 fi

 case "${bin_name}" in
 sing-box)
 # Sing-box check requires the config *directory*
 if [ -d "${sing_config_dir}" ]; then
 # Use --config-directory for multiple potential configs
 if "${bin_path}" check --config-directory "${sing_config_dir}" > "${report_file}" 2>&1; then
 log Info "sing-box configuration in ${sing_config_dir} passed check."
 else
 find "${sing_config_dir}" -name '*.json' -print -exec echo "---" \; # List configs tried
 log Error "sing-box configuration check failed. See details below:"
 cat "${report_file}" >&2
 return 1
 fi
 else
 log Error "Sing-box config directory not found: ${sing_config_dir}"
 return 1
 fi
 ;;
 clash)
 if [ -f "${clash_config}" ]; then
 # Clash check needs the directory containing the config and potentially geoip files etc.
 local clash_home_dir=$(dirname "${clash_config}")
 if "${bin_path}" -t -d "${clash_home_dir}" -f "${clash_config}" > "${report_file}" 2>&1; then
 log Info "Clash configuration (${clash_config}) passed check."
 else
 log Debug "Clash config file: ${clash_config}"
 log Error "Clash configuration check failed. See details below:"
 cat "${report_file}" >&2
 return 1
 fi
 else
 log Error "Clash config file not found: ${clash_config}"
 return 1
 fi
 ;;
 xray)
 if [ -d "${xray_config_dir}" ]; then
 log Info "Using Asset Location: ${xray_config_dir}"
 export XRAY_LOCATION_ASSET="${xray_config_dir}"
 # Xray check works on directory containing config files
 if "${bin_path}" test -confdir "${xray_config_dir}" > "${report_file}" 2>&1; then
 log Info "Xray configuration in ${xray_config_dir} passed check."
 else
 log Debug "Xray config directory: ${xray_config_dir} (Contents: $(ls -1 "${xray_config_dir}" | paste -sd ',' -))"
 log Error "Xray configuration check failed. See details below:"
 cat "${report_file}" >&2
 return 1
 fi
 else
 log Error "Xray config directory not found: ${xray_config_dir}"
 return 1
 fi
 ;;
 v2fly)
 if [ -d "${v2fly_config_dir}" ]; then
 log Info "Using Asset Location: ${v2fly_config_dir}"
 export V2RAY_LOCATION_ASSET="${v2fly_config_dir}"
 if "${bin_path}" test -confdir "${v2fly_config_dir}" > "${report_file}" 2>&1; then
 log Info "V2fly configuration in ${v2fly_config_dir} passed check."
 else
 log Debug "V2fly config directory: ${v2fly_config_dir} (Contents: $(ls -1 "${v2fly_config_dir}" | paste -sd ',' -))"
 log Error "V2fly configuration check failed. See details below:"
 cat "${report_file}" >&2
 return 1
 fi
 else
 log Error "V2fly config directory not found: ${v2fly_config_dir}"
 return 1
 fi
 ;;
 hysteria)
 # Hysteria (v1/v2) doesn't seem to have a dedicated config check command in the client/server binary itself.
 # A basic check could be validating JSON syntax if the config is JSON.
 local hysteria_config="${box_dir}/hysteria/config.json" # Assuming JSON
 if [ -f "$hysteria_config" ]; then
 if command -v jq &>/dev/null; then
 if jq '.' "$hysteria_config" > /dev/null 2>&1; then
 log Info "Hysteria config (${hysteria_config}) appears to be valid JSON."
 else
 log Error "Hysteria config (${hysteria_config}) is not valid JSON."
 return 1
 fi
 else
 log Warn "jq command not found. Cannot validate Hysteria JSON config syntax."
 log Info "Assuming Hysteria config ${hysteria_config} is okay (basic check)."
 fi
 # Returning true as there's no deeper check command
 return 0
 else
 log Error "Hysteria config file not found: ${hysteria_config}"
 return 1
 fi
 ;;
 juicity)
 # Juicity doesn't seem to have a 'check' command (as of v0.4.3).
 # Basic check: Validate JSON syntax of config file.
 if [ -f "${juicity_config}" ]; then
 if command -v jq &>/dev/null; then
 if jq '.' "${juicity_config}" > /dev/null 2>&1; then
 log Info "Juicity config (${juicity_config}) appears to be valid JSON."
 else
 log Error "Juicity config (${juicity_config}) is not valid JSON."
 return 1
 fi
 else
 log Warn "jq command not found. Cannot validate Juicity JSON config syntax."
 log Info "Assuming Juicity config ${juicity_config} is okay (basic check)."
 fi
 return 0
 else
 log Error "Juicity config not found: ${juicity_config}"
 return 1
 fi
 ;;
 *)
 log Error "<${bin_name}> unknown binary for config check."
 return 1
 ;;
 esac
}

# Reload base config (may involve API call or service restart)
reload() {
 local curl_command="${bin_dir}/curl" # Prefer potentially downloaded static curl
 if ! command -v "${curl_command}" &>/dev/null && command -v curl &>/dev/null; then
 curl_command=$(command -v curl) # Fallback to system curl
 elif [ ! -x "${curl_command}" ]; then
 log Debug "curl command not found or not executable (${curl_command}), attempting to download..."
 if ! upcurl; then
  log Error "Failed to download/find curl. Cannot use API reload."
  return 1
 fi
 # Verify again after download attempt
 if ! command -v "${curl_command}" &>/dev/null; then
  log Error "curl still not available after download attempt."
  return 1
 fi
 fi

 log Info "Attempting to reload configuration for ${bin_name}..."
 # First, perform a configuration check before attempting reload
 if ! check; then
 log Error "Configuration check failed. Aborting reload."
 return 1
 fi

 # Determine API endpoint and secret (might need adjustment per core)
 local endpoint=""
 local ip=""
 local port=""
 local auth_header=""
 # Extract IP/Port and Secret - logic needs careful review per core config format
 case "${bin_name}" in
 clash)
 ip=$(awk -F'[: ]+' '!/^ *#/ && /external-controller:/ {print $3}' "${clash_config}" 2>/dev/null)
 port=$(awk -F'[: ]+' '!/^ *#/ && /external-controller:/ {print $4}' "${clash_config}" 2>/dev/null)
 secret=$(awk -F': *' '!/^ *#/ && /secret:/ {print $2}' "${clash_config}" | tr -d '"' 2>/dev/null)
 if [[ -n "$ip" && -n "$port" ]]; then
 endpoint="http://${ip}:${port}/configs?force=true" # force=true for Mihomo/Clash-Meta
 [[ -n "$secret" ]] && auth_header="-H \"Authorization: Bearer ${secret}\""
 fi
 ;;
 sing-box)
 ip=$(find "${sing_config_dir}" -maxdepth 1 -type f \( -name '*.json' -o -name '*.json5' \) -exec sh -c "grep -oE '\"(external_controller|listen)\":\s*\"[0-9.]+\"' {} | head -1 | cut -d'\"' -f4" \; 2>/dev/null)
 port=$(find "${sing_config_dir}" -maxdepth 1 -type f \( -name '*.json' -o -name '*.json5' \) -exec sh -c "grep -oE '\"(external_controller|listen_port)\":\s*[0-9]+' {} | head -1 | grep -oE '[0-9]+'" \; 2>/dev/null)
 secret=$(find "${sing_config_dir}" -maxdepth 1 -type f \( -name '*.json' -o -name '*.json5' \) -exec sh -c "grep -oE '\"secret\":\s*\"[^"]+\"' {} | head -1 | cut -d'\"' -f4" \; 2>/dev/null)
 if [[ -z "$ip" ]]; then ip="127.0.0.1"; fi # Default if only port found
 if [[ -n "$ip" && -n "$port" ]]; then
 endpoint="http://${ip}:${port}/configs?force=true"
 [[ -n "$secret" ]] && auth_header="-H \"Authorization: Bearer ${secret}\""
 fi ;;
 *)
 # Other cores likely need restart
 endpoint=""
 ;;
 esac

 case "${bin_name}" in
 "clash"|"sing-box")
 if [[ -n "$endpoint" ]]; then
  log Debug "Using Endpoint: ${endpoint}"
  # The payload `{"path": "", "payload": ""}` tells Clash/Sing-box to reload from their primary config file(s)
  # Use eval carefully to construct the command with potential auth header
  local cmd_str="\"${curl_command}\" -X PUT ${auth_header} \"${endpoint}\" -d '{\"path\": \"\", \"payload\": \"\"}'"
  log Debug "Executing: ${cmd_str}"
  if eval "${cmd_str}" > /dev/null 2>&1; then
  log Info "${bin_name} configuration reload via API successful."
  return 0
  else
  log Error "${bin_name} configuration reload via API failed! Check controller settings and ${bin_name} logs."
  log Warn "Falling back to service restart..."
  restart_box || return 1
  fi
 else
  log Warn "${bin_name}: Could not determine API endpoint/port from config. Falling back to service restart."
  restart_box || return 1
 fi
 ;;
 "xray"|"v2fly"|"hysteria"|"juicity")
 log Info "${bin_name} does not support API reload. Restarting service..."
 restart_box || return 1
 ;;
 *)
 log Error "${bin_name} reload not supported."
 return 1
 ;;
 esac
}


# Get latest curl (static build)
upcurl() {
 local arch
 case $(uname -m) in
  "aarch64") arch="aarch64" ;;
  "armv7l"|"armv8l") arch="armv7" ;; # Assuming armv7 for 32-bit ARM
  "i686") arch="i686" ;;
  "x86_64") arch="amd64" ;;
  *) log Warning "Unsupported architecture for static curl: $(uname -m)"; return 1 ;;
 esac

 local api_url="https://api.github.com/repos/stunnel/static-curl/releases"
 local latest_version=$($rev1 "${api_url}" | grep "tag_name" | grep -oE "[0-9.]*" | head -1)

 if [ -z "$latest_version" ]; then
 log Error "Failed to get latest static-curl version."
 return 1
 fi

 mkdir -p "${bin_dir}/backup"
 [ -f "${bin_dir}/curl" ] && cp "${bin_dir}/curl" "${bin_dir}/backup/curl.bak"

 local download_link="https://github.com/stunnel/static-curl/releases/download/${latest_version}/curl-linux-${arch}-glibc-${latest_version}.tar.xz"
 local archive_file="${bin_dir}/curl.tar.xz"

 log Info "Downloading static curl ${latest_version} for ${arch}"
 log Debug "URL: ${download_link}"
 if upfile "${archive_file}" "${download_link}"; then
  log Info "Extracting curl..."
  if tar -xJf "${archive_file}" -C "${bin_dir}" --strip-components=1 curl 2>/dev/null; then # Attempt to extract only 'curl' binary
   chown "${box_user_group}" "${bin_dir}/curl" || log Warn "Failed to chown ${bin_dir}/curl"
   chmod 0755 "${bin_dir}/curl" || log Warn "Failed to chmod ${bin_dir}/curl"
   log Info "Static curl updated successfully to ${latest_version}."
   rm -f "${archive_file}"
   return 0
  else
   log Error "Failed to extract ${archive_file}"
   # Try restoring backup
   [ -f "${bin_dir}/backup/curl.bak" ] && cp "${bin_dir}/backup/curl.bak" "${bin_dir}/curl" && log Info "Restored previous curl"
   rm -f "${archive_file}"
   return 1
  fi
 else
  log Error "Failed to download static curl."
  return 1
 fi
}

# Get latest yq (for Linux)
upyq() {
 local arch platform="linux" # yq uses 'linux', not 'android'
 case $(uname -m) in
  "aarch64") arch="arm64" ;;
  "armv7l"|"armv8l") arch="arm" ;;
  "i686") arch="386" ;;
  "x86_64") arch="amd64" ;;
  *) log Warning "Unsupported architecture for yq: $(uname -m)"; return 1 ;;
 esac

 # Use Mike Farah's yq (common one) - Adjust repo if needed
 local api_url="https://api.github.com/repos/mikefarah/yq/releases/latest"
 local latest_version=$($rev1 "${api_url}" | grep "tag_name" | grep -oE "v[0-9.]*" | head -1)
 if [ -z "$latest_version" ]; then
 log Error "Failed to get latest yq version."
 return 1
 fi

 mkdir -p "${bin_dir}/backup"
 [ -f "${bin_dir}/yq" ] && cp "${bin_dir}/yq" "${bin_dir}/backup/yq.bak"

 local download_link="https://github.com/mikefarah/yq/releases/download/${latest_version}/yq_${platform}_${arch}"
 log Info "Downloading yq ${latest_version} for ${platform}_${arch}"
 log Debug "URL: ${download_link}"

 if upfile "${bin_dir}/yq" "${download_link}"; then
  chown "${box_user_group}" "${bin_dir}/yq" || log Warn "Failed to chown ${bin_dir}/yq"
  chmod 0755 "${bin_dir}/yq" || log Warn "Failed to chmod ${bin_dir}/yq"
  log Info "yq updated successfully to ${latest_version}."
  return 0
 else
  log Error "Failed to download yq."
  [ -f "${bin_dir}/backup/yq.bak" ] && cp "${bin_dir}/backup/yq.bak" "${bin_dir}/yq" && log Info "Restored previous yq"
  return 1
 fi
}


# Check and update geoip and geosite
upgeox() {
 log Info "Checking for geoip/geosite updates for ${bin_name}..."
 local target_dir=""
 local geoip_file="" geoip_url="" geosite_file="" geosite_url=""
 local dl_geoip=false dl_geosite=false

 case "${bin_name}" in
 clash)
 target_dir="${box_dir}/clash"
 mkdir -p "${target_dir}"
 # Determine geo file format based on config (mihomo supports both, prefers mmdb if geodata-mode is missing/true)
 local geodata_mode="true" # Default assumption for Mihomo
 if [ -f "${clash_config}" ]; then
  geodata_mode=$(awk '!/^ *#/ && /geodata-mode:/ {print $2; exit}' "${clash_config}")
  geodata_mode=${geodata_mode:-true} # Default to true if not found
 fi

 if [[ "${xclash_option}" == "premium" || "${geodata_mode}" == "false" ]]; then
  # Use old DAT format
  geoip_file="${target_dir}/GeoIP.dat"
  geoip_url="https://github.com/MetaCubeX/meta-rules-dat/raw/release/geoip.dat"
  geosite_file="${target_dir}/GeoSite.dat"
  geosite_url="https://github.com/MetaCubeX/meta-rules-dat/raw/release/geosite.dat"
 else
  # Use MMDB and DAT format (Mihomo default/preferred)
  geoip_file="${target_dir}/Country.mmdb"
  geoip_url="https://github.com/MetaCubeX/meta-rules-dat/raw/release/country.mmdb"
  geosite_file="${target_dir}/GeoSite.dat"
  geosite_url="https://github.com/MetaCubeX/meta-rules-dat/raw/release/geosite.dat"
 fi
 dl_geoip=true
 dl_geosite=true
 ;;
 sing-box)
 target_dir="${box_dir}/sing-box"
 mkdir -p "${target_dir}"
 geoip_file="${target_dir}/geoip.db"
 geoip_url="https://github.com/MetaCubeX/meta-rules-dat/raw/release/geoip.db"
 geosite_file="${target_dir}/geosite.db"
 geosite_url="https://github.com/MetaCubeX/meta-rules-dat/raw/release/geosite.db"
 dl_geoip=true
 dl_geosite=true
 ;;
 xray|v2fly|hysteria|juicity) # Assume DAT format for these
 target_dir="${box_dir}/${bin_name}"
 mkdir -p "${target_dir}"
 geoip_file="${target_dir}/geoip.dat"
 geoip_url="https://github.com/MetaCubeX/meta-rules-dat/raw/release/geoip.dat"
 geosite_file="${target_dir}/geosite.dat"
 geosite_url="https://github.com/MetaCubeX/meta-rules-dat/raw/release/geosite.dat"
 dl_geoip=true
 dl_geosite=true
 ;;
 *)
 log Warn "Geo file updates not configured for ${bin_name}."
 return 1
 ;;
 esac

 local success=true
 if [[ "${update_geo}" = "true" ]]; then
  log Info "Attempting daily updates for geox:"
  if [[ "${dl_geoip}" = true ]]; then
   log Debug "Updating ${geoip_file} from ${geoip_url}"
   if ! upfile "${geoip_file}" "${geoip_url}"; then
    log Error "Failed to update ${geoip_file}"
    success=false
   fi
  fi
  if [[ "${dl_geosite}" = true ]]; then
   log Debug "Updating ${geosite_file} from ${geosite_url}"
   if ! upfile "${geosite_file}" "${geosite_url}"; then
    log Error "Failed to update ${geosite_file}"
    success=false
   fi
  fi

  if [[ "$success" = true ]]; then
   # Cleanup old backups in the specific target directory
   find "${target_dir}" -maxdepth 1 -type f \( -name "*.db.bak" -o -name "*.dat.bak" -o -name "*.mmdb.bak" \) -delete
   log Info "Geo files update check completed [$(date "+%F %R")]"
   return 0
  else
   log Error "One or more geo files failed to update."
   return 1
  fi
 else
  log Info "Geo file update is disabled in settings (update_geo=${update_geo})."
  return 0 # Not an error if disabled
 fi
}

# Check and update subscription (Primarily for Clash)
upsubs() {
 log Info "Checking for subscription updates..."
 case "${bin_name}" in
 "clash")
 if [ -z "${subscription_url_clash}" ]; then
  log Warn "Clash subscription URL (subscription_url_clash) is not set in settings. Skipping."
  return 0 # Not an error if not configured
 fi

 if [ "${update_subscription}" != "true" ]; then
  log Info "Clash subscription update is disabled in settings (update_subscription=${update_subscription})."
  return 0 # Not an error if disabled
 fi

 log Info "Attempting daily subscription update for Clash."
 local yq_command="${bin_dir}/yq"
 local can_enhance=false
 if ! command -v "${yq_command}" &>/dev/null && command -v yq &>/dev/null; then
  yq_command=$(command -v yq) # Fallback to system yq
 fi
 if command -v "${yq_command}" &>/dev/null; then
  can_enhance=true
 else
  log Warn "yq command not found (${yq_command}). Cannot enhance subscription processing. Will save as raw file."
  # Optionally try to download yq here if critical
  # if ! upyq; then log Error "Failed to download yq."; fi
 fi

 # Define target paths for providers/rulesets (ensure directories exist)
 local clash_providers_dir=$(dirname "${clash_provide_config}")
 local clash_rulesets_dir=$(dirname "${clash_provide_rules}")
 mkdir -p "${clash_providers_dir}" || log Warn "Failed to create dir ${clash_providers_dir}"
 mkdir -p "${clash_rulesets_dir}" || log Warn "Failed to create dir ${clash_rulesets_dir}"

 # Download to a temporary file first
 local temp_sub_file="${box_run}/subscription_download.yaml"
 log Debug "Downloading subscription from ${subscription_url_clash} to ${temp_sub_file}"

 if upfile "${temp_sub_file}" "${subscription_url_clash}"; then
  log Info "Subscription downloaded successfully."

  if [[ "${can_enhance}" = "true" ]]; then
   log Debug "Processing subscription using yq..."
   # Check if it's a full Clash config (has proxies)
   if "${yq_command}" 'has("proxies")' "${temp_sub_file}" | grep -q "true"; then
    log Info "Detected full config format. Extracting proxies..."
    if "${yq_command}" '.proxies' "${temp_sub_file}" > "${clash_provide_config}.tmp"; then
     # Wrap in 'proxies:' key for provider format
     "${yq_command}" -i '{"proxies": .}' "${clash_provide_config}.tmp" && \
     mv "${clash_provide_config}.tmp" "${clash_provide_config}" && \
     log Info "Proxies extracted to ${clash_provide_config}"

     # Optionally extract rules if enabled
     if [[ "${custom_rules_subs}" = "true" ]]; then
      log Debug "Checking for rules in subscription..."
      if "${yq_command}" 'has("rules")' "${temp_sub_file}" | grep -q "true"; then
       if "${yq_command}" '.rules' "${temp_sub_file}" > "${clash_provide_rules}.tmp"; then
        "${yq_command}" -i '{"rules": .}' "${clash_provide_rules}.tmp" && \
        mv "${clash_provide_rules}.tmp" "${clash_provide_rules}" && \
        log Info "Custom rules extracted to ${clash_provide_rules}"
        # You might need logic here to automatically include this ruleset in your main config.yaml
        # Example: Add a rule provider reference if not exists. This is complex.
        # For now, just extracting is done. Manual config adjustment might be needed.
       else
        log Error "Failed to extract rules section."
        rm -f "${clash_provide_rules}.tmp"
       fi
      else
       log Info "No 'rules:' section found in the subscription."
      fi
     fi # end custom_rules_subs
     rm -f "${temp_sub_file}" # Clean up temp file on success
     log Info "Subscription processing complete."
     return 0
    else
     log Error "Failed to extract proxies using yq."
     rm -f "${clash_provide_config}.tmp" "${temp_sub_file}"
     return 1
    fi
   # Check if it's a raw list of proxies (e.g., base64 encoded vmess etc.)
   elif "${yq_command}" '.. | select(tag == "!!str")' "${temp_sub_file}" | grep -qE "vless://|vmess://|ss://|hysteria2?://|tuic://|trojan://|juicity://"; then
    log Info "Detected raw proxy list format. Saving directly as provider."
    # Simply move the downloaded file to be the provider file
    mv "${temp_sub_file}" "${clash_provide_config}"
    log Info "Raw subscription saved to ${clash_provide_config}"
    # Note: Clash needs 'type: http' and 'url:' in providers section pointing to this file, or use it differently.
    return 0
   else
    log Warn "Subscription format not recognized by yq (neither full config nor raw proxy list). Saving as is."
    mv "${temp_sub_file}" "${clash_provide_config}" # Save raw content anyway
    log Info "Downloaded content saved to ${clash_provide_config}"
    return 1 # Indicate potential issue
   fi
  else # No yq available
   log Warn "yq not available, saving raw subscription download."
   mv "${temp_sub_file}" "${clash_provide_config}"
   log Info "Raw subscription saved to ${clash_provide_config}"
   return 0 # Saved successfully, even if not processed
  fi
 else
  log Error "Failed to download subscription from ${subscription_url_clash}"
  rm -f "${temp_sub_file}" # Clean up failed download attempt
  return 1
 fi
 ;;
 "xray"|"v2fly"|"sing-box"|"hysteria"|"juicity")
  log Info "${bin_name} does not natively support direct subscription URL processing like Clash. Please configure proxy details manually or use external tools."
  return 0 # Not an error for these cores
 ;;
 *)
  log Error "<${bin_name}> unknown binary for subscription handling."
  return 1
 ;;
 esac
}


# Extract downloaded kernel/binary
xkernel() {
 local archive_path="$1" # Full path to the downloaded archive
 local expected_bin_name=$2 # The base name we expect (e.g., clash, sing-box)
 local platform_arch_ver_str="$3" # String like "linux-amd64-v1.2.3" for context
 local bin_install_path="${bin_dir}/${expected_bin_name}" # Final destination

 log Info "Extracting ${archive_path} for ${expected_bin_name}"
 mkdir -p "${bin_dir}/extract_tmp" || { log Error "Failed to create temp extraction dir"; return 1; }

 local extract_success=false
 local found_binary_path=""

 # Determine extraction command based on extension
 case "${archive_path}" in
 *.tar.gz|*.tgz)
  if tar -xzf "${archive_path}" -C "${bin_dir}/extract_tmp"; then extract_success=true; fi
  ;;
 *.gz)
  # If it's just .gz, gunzip it and hope the output filename is the binary name
  local gunzipped_name=$(basename "${archive_path}" .gz) # Rough guess
  if gunzip -c "${archive_path}" > "${bin_dir}/extract_tmp/${gunzipped_name}"; then
   extract_success=true
   # We need to find the *actual* binary name, might not match gunzipped_name
  fi
  ;;
 *.zip)
  if unzip -o "${archive_path}" -d "${bin_dir}/extract_tmp"; then extract_success=true; fi
  ;;
 *.tar.xz|*.txz)
  if tar -xJf "${archive_path}" -C "${bin_dir}/extract_tmp"; then extract_success=true; fi
  ;;
 *)
  # Direct download (e.g., hysteria) - assume archive_path IS the binary
  if mv "${archive_path}" "${bin_install_path}"; then
    log Info "Moved downloaded binary directly to ${bin_install_path}"
    chown "${box_user_group}" "${bin_install_path}" || log Warn "Failed to chown ${bin_install_path}"
    chmod 0755 "${bin_install_path}" || log Warn "Failed to chmod ${bin_install_path}"
    log Info "${expected_bin_name} binary placed successfully."
    # Already moved, skip further processing
    if [ -f "${box_pid}" ] && kill -0 "$(<"${box_pid}" 2>/dev/null)"; then restart_box; fi
    return 0 # SUCCESS (direct move)
  else
    log Error "Failed to move downloaded file ${archive_path} to ${bin_install_path}"
    return 1 # FAIL (direct move)
  fi
  ;;
 esac

 if [[ "$extract_success" = true ]]; then
  log Debug "Archive extracted successfully to ${bin_dir}/extract_tmp"
  # Find the expected binary within the extraction directory (handle subdirs)
  # Common names: bin_name, bin_name.bin, bin_name-linux-arch, etc.
  # Search for executable files matching pattern
  found_binary_path=$(find "${bin_dir}/extract_tmp" -type f -executable \( -name "${expected_bin_name}" -o -name "${expected_bin_name}.bin" -o -name "${expected_bin_name}-*" \) -print -quit)

  # Special case for juicity: look for client/server
  if [[ "${expected_bin_name}" == "juicity" ]] && [[ -z "$found_binary_path" ]]; then
    local client_path server_path
    client_path=$(find "${bin_dir}/extract_tmp" -type f -executable -name "juicity-client" -print -quit)
    server_path=$(find "${bin_dir}/extract_tmp" -type f -executable -name "juicity-server" -print -quit)
    if [[ -n "$client_path" ]] && [[ -n "$server_path" ]]; then
      log Info "Found juicity-client and juicity-server."
      local juicity_ok=true
      if ! mv "$client_path" "${bin_dir}/juicity-client"; then log Error "Failed to move juicity-client"; juicity_ok=false; fi
      if ! mv "$server_path" "${bin_dir}/juicity-server"; then log Error "Failed to move juicity-server"; juicity_ok=false; fi

      if [[ "$juicity_ok" = true ]]; then
          chown "${box_user_group}" "${bin_dir}/juicity-client" "${bin_dir}/juicity-server" || log Warn "Failed chown juicity bins"
          chmod 0755 "${bin_dir}/juicity-client" "${bin_dir}/juicity-server" || log Warn "Failed chmod juicity bins"
          log Info "Juicity client and server updated successfully."
          # Clean up tmp dir
          rm -rf "${bin_dir}/extract_tmp"
          # Remove original archive (already checked for success)
          rm -f "${archive_path}"
          # Restart if running
          if [ -f "${box_pid}" ] && kill -0 "$(<"${box_pid}" 2>/dev/null)"; then restart_box; fi
          return 0 # SUCCESS (juicity)
      else
        log Error "Kernel processing failed for Juicity binaries."
        rm -rf "${bin_dir}/extract_tmp"
        return 1 # FAIL (juicity move)
      fi
    else
      log Error "Could not find juicity-client or juicity-server in extracted files."
      found_binary_path="" # Ensure it remains empty
    fi
  fi # end juicity special case

  if [[ -n "$found_binary_path" ]]; then
   log Info "Found extracted binary: ${found_binary_path}"
   if mv "${found_binary_path}" "${bin_install_path}"; then
    chown "${box_user_group}" "${bin_install_path}" || log Warn "Failed to chown ${bin_install_path}"
    chmod 0755 "${bin_install_path}" || log Warn "Failed to chmod ${bin_install_path}"
    log Info "${expected_bin_name} kernel updated successfully to version inferred from ${platform_arch_ver_str:-archive}"
    # Clean up tmp dir
    rm -rf "${bin_dir}/extract_tmp"
    # Remove original archive (already checked for success)
    rm -f "${archive_path}"
    # Optional: Create symlink if using a versioned naming scheme
    # Example: ln -sf "${bin_install_path}" "${bin_dir}/${expected_bin_name}"

    # Restart service if it was running
    if [ -f "${box_pid}" ] && kill -0 "$(<"${box_pid}" 2>/dev/null)"; then
     # Specific cleanup before restart for some cores
     [[ "${expected_bin_name}" == "sing-box" ]] && rm -f "${box_dir}/sing-box/cache.db"
     restart_box
    else
     log Debug "${expected_bin_name} service not running, no restart needed."
    fi
    return 0 # SUCCESS
   else
    log Error "Failed to move extracted binary from ${found_binary_path} to ${bin_install_path}"
   fi
  else
   log Error "Could not find executable file matching '${expected_bin_name}' in extracted archive ${archive_path}"
   log Debug "Contents of extraction:"
   find "${bin_dir}/extract_tmp" -ls
  fi
 else
  log Error "Failed to extract archive: ${archive_path}"
 fi # end extract_success check

 # Cleanup on failure
 rm -rf "${bin_dir}/extract_tmp"
 log Error "Kernel update/extraction failed for ${expected_bin_name}."
 # Try restoring backup if extraction failed
 if [ -f "${bin_dir}/backup/${expected_bin_name}.bak" ]; then
    cp "${bin_dir}/backup/${expected_bin_name}.bak" "${bin_install_path}" && log Info "Restored previous ${expected_bin_name} kernel from backup." || log Error "Failed to restore kernel backup."
 fi
 return 1 # FAIL
}


# Check and update kernel
upkernel() {
 local current_bin_name="${bin_name}" # Use the currently set bin_name from settings
 log Info "Checking for kernel updates for ${current_bin_name}..."

 mkdir -p "${bin_dir}/backup"
 local backup_file="${bin_dir}/backup/${current_bin_name}.bak"
 if [ -f "${bin_dir}/${current_bin_name}" ]; then
  cp "${bin_dir}/${current_bin_name}" "${backup_file}" || log Warn "Failed to create backup for ${current_bin_name}"
 elif [[ "${current_bin_name}" == "juicity" ]] && [ -f "${bin_dir}/juicity-client" ]; then
   # Backup juicity client/server separately
  cp "${bin_dir}/juicity-client" "${bin_dir}/backup/juicity-client.bak" || log Warn "Failed backup juicity-client"
  cp "${bin_dir}/juicity-server" "${bin_dir}/backup/juicity-server.bak" || log Warn "Failed backup juicity-server"
 fi


 local arch platform="linux" # Default platform
 case $(uname -m) in
  "aarch64") arch="arm64" ;; # Standard Linux arm64
  "armv7l"|"armv8l") arch="armv7" ;; # Common naming for 32-bit ARMv7
  "i686") arch="386" ;; # Standard 32-bit x86
  "x86_64") arch="amd64" ;; # Standard 64-bit x86
  *) log Error "Unsupported architecture: $(uname -m)" >&2; return 1 ;;
 esac

 # Adjust arch/platform names based on specific project conventions
 local file_kernel_base="${current_bin_name}-${platform}-${arch}" # Base name for downloaded file
 local api_url="" url_down="" latest_version="" download_link="" filename="" archive_suffix=""

 case "${current_bin_name}" in
 "sing-box")
  api_url="https://api.github.com/repos/SagerNet/sing-box/releases"
  url_down="https://github.com/SagerNet/sing-box/releases"
  if [[ "${singbox_stable}" = "disable" ]]; then
   log Debug "Fetching latest sing-box Pre-release version..."
   latest_version=$($rev1 "${api_url}" | grep "tag_name" | grep -oE "v[0-9].*" | head -1 | cut -d'"' -f1)
  else
   log Debug "Fetching latest sing-box Stable version..."
   latest_version=$($rev1 "${api_url}/latest" | grep "tag_name" | grep -oE "v[0-9.]*" | head -1)
  fi
  if [ -z "$latest_version" ]; then log Error "Failed to get sing-box version"; return 1; fi
  # Sing-box uses version in filename
  local version_num=${latest_version#v}
  filename="sing-box-${version_num}-${platform}-${arch}"
  archive_suffix=".tar.gz"
  download_link="${url_down}/download/${latest_version}/${filename}${archive_suffix}"
  ;;

 "clash")
  if [[ "${xclash_option}" = "mihomo" ]]; then
   api_url="https://api.github.com/repos/MetaCubeX/mihomo/releases"
   url_down="https://github.com/MetaCubeX/mihomo/releases"
   local tag=""
   if [[ "${mihomo_stable}" = "enable" ]]; then
    log Debug "Fetching latest Mihomo Stable version..."
    tag=$($rev1 "${api_url}/latest" | grep "tag_name" | grep -oE "v[0-9.]*" | head -1)
    latest_version="$tag" # Use tag as version string
   else
    log Debug "Fetching latest Mihomo Alpha version..."
    tag="Prerelease-Alpha" # Use the specific tag for alpha
    # Need to fetch the specific release under the tag to get asset name/version
    # This is complex; simpler approach: guess filename pattern or fetch release page
    # Guessing pattern: alpha-YYYY.MM.DD-hash
    # Fetching release page for alpha tag:
    local release_info=$($rev1 "${api_url}/tags/${tag}" 2>/dev/null)
    latest_version=$(echo "$release_info" | grep '"name":' | grep 'alpha' | head -1 | grep -oE 'alpha-[0-9a-z\-]+' | sed 's/-linux.*//') # Extract version part
    if [ -z "$latest_version" ]; then # Fallback - scrape download page (less reliable)
      log Warn "Could not get alpha version from API, trying scrape..."
      download_page_url="${url_down}/expanded_assets/${tag}"
      [[ "$use_ghproxy" == true ]] && download_page_url="${url_ghproxy}/${download_page_url}"
      latest_version=$($rev1 "${download_page_url}" | grep -oE 'alpha-[0-9a-z\-]+' | head -1)
    fi
   fi
   if [ -z "$latest_version" ]; then log Error "Failed to get Mihomo version (tag: ${tag})"; return 1; fi
   # Mihomo arch for arm64 is 'arm64-v8a' or similar, need exact name
   local mihomo_arch="${arch}"
   [[ "$arch" == "arm64" ]] && mihomo_arch="armv8" # Mihomo uses armv8 for arm64
   filename="mihomo-${platform}-${mihomo_arch}-${latest_version}"
   archive_suffix=".gz"
   download_link="${url_down}/download/${tag}/${filename}${archive_suffix}"
  else
   log Warn "Clash Premium kernel is no longer available. Please switch to Mihomo (set xclash_option=mihomo)."
   return 1
  fi
  ;;

 "xray"|"v2fly")
  local repo_owner repo_name core_exe_name
  if [[ "${current_bin_name}" = "xray" ]]; then
   repo_owner="XTLS"; repo_name="Xray-core"; core_exe_name="xray"
  else
   repo_owner="v2fly"; repo_name="v2ray-core"; core_exe_name="v2ray"
  fi
  api_url="https://api.github.com/repos/${repo_owner}/${repo_name}/releases/latest"
  url_down="https://github.com/${repo_owner}/${repo_name}/releases"
  log Debug "Fetching latest ${current_bin_name} Stable version..."
  latest_version=$($rev1 ${api_url} | grep "tag_name" | grep -oE "v[0-9.]*" | head -1)
  if [ -z "$latest_version" ]; then log Error "Failed to get ${current_bin_name} version"; return 1; fi

  # Adjust arch naming for xray/v2fly zip files
  local zip_arch=""
  case "$arch" in
   "386") zip_arch="32" ;;
   "amd64") zip_arch="64" ;;
   "armv7") zip_arch="arm32-v7a" ;; # Check exact name needed
   "arm64") zip_arch="arm64-v8a" ;; # Check exact name needed
   *) log Error "Unsupported arch mapping for ${current_bin_name}: ${arch}"; return 1 ;;
  esac
  filename="${core_exe_name}-${platform}-${zip_arch}" # Base name matches binary
  archive_suffix=".zip"
  download_link="${url_down}/download/${latest_version}/${filename}${archive_suffix}"
  ;;

 "hysteria")
  # Hysteria v2 naming convention (apernet/hysteria)
  api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
  url_down="https://github.com/apernet/hysteria/releases"
  log Debug "Fetching latest Hysteria Stable version..."
  latest_version=$($rev1 ${api_url} | grep "tag_name" | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+') # Match standard semver
  if [ -z "$latest_version" ]; then log Error "Failed to get Hysteria version"; return 1; fi

  # Hysteria v2 provides direct binary downloads, no zip/tar usually
  # Filename: hysteria-linux-arch
  filename="hysteria-${platform}-${arch}"
  archive_suffix="" # Direct binary download
  download_link="${url_down}/download/${latest_version}/${filename}"
  ;;

 "juicity")
  api_url="https://api.github.com/repos/juicity/juicity/releases/latest"
  url_down="https://github.com/juicity/juicity/releases"
  log Debug "Fetching latest Juicity Stable version..."
  latest_version=$($rev1 ${api_url} | grep "tag_name" | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')
  if [ -z "$latest_version" ]; then log Error "Failed to get Juicity version"; return 1; fi

  # Filename: juicity-linux-arch.zip
  filename="juicity-${platform}-${arch}"
  archive_suffix=".zip"
  download_link="${url_down}/download/${latest_version}/${filename}${archive_suffix}"
  ;;

 *)
  log Error "<${current_bin_name}> unknown binary for kernel update."
  return 1
  ;;
 esac

 local download_target="${box_run}/${filename}${archive_suffix}" # Download to runtime dir
 local version_str="${latest_version}" # Use fetched version for context

 log Info "Attempting to download ${current_bin_name} kernel ${version_str}..."
 log Debug "URL: ${download_link}"
 if upfile "${download_target}" "${download_link}"; then
  # Pass archive path, expected binary name, context string
  xkernel "${download_target}" "${current_bin_name}" "${platform}-${arch}-${version_str}"
  local xkernel_exit_code=$?
  # xkernel now handles cleanup of archive on success
  return $xkernel_exit_code
 else
  log Error "Failed to download ${current_bin_name} kernel."
  rm -f "${download_target}" # Clean up failed download
  return 1
 fi
}


# Check and update yacd dashboard (Clash/Sing-box only)
upxui() {
 local xdashboard_base="dashboard" # Base name for the dashboard directory
 local target_dashboard_dir="${box_dir}/${bin_name}/${xdashboard_base}"

 log Info "Checking for dashboard UI update for ${bin_name}..."

 if [[ "${bin_name}" == @(clash|sing-box) ]]; then
  # Using YACD dashboard (adjust URL if using a different one like Meta Gist etc.)
  local url="https://github.com/MetaCubeX/Yacd-meta/archive/refs/heads/gh-pages.zip"
  local zip_file="${box_run}/dashboard_download.zip"
  local extract_dir_name="Yacd-meta-gh-pages" # This is inside the zip

  log Info "Attempting to update YACD dashboard..."
  log Debug "URL: ${url}"

  if upfile "${zip_file}" "${url}"; then
   log Info "Cleaning old dashboard directory: ${target_dashboard_dir}"
   rm -rf "${target_dashboard_dir}" # Remove old contents completely
   mkdir -p "${target_dashboard_dir}" || { log Error "Failed to create dashboard dir ${target_dashboard_dir}"; rm -f "${zip_file}"; return 1; }

   log Info "Extracting dashboard UI..."
   if unzip -o "${zip_file}" -d "${target_dashboard_dir}" >/dev/null 2>&1; then
    # Move contents from the subdirectory created by unzip to the target dir
    if mv -f "${target_dashboard_dir}/${extract_dir_name}/"* "${target_dashboard_dir}/"; then
      rm -rf "${target_dashboard_dir}/${extract_dir_name}" # Remove the now empty subdirectory
      rm -f "${zip_file}" # Clean up downloaded zip
      log Info "Dashboard UI updated successfully in ${target_dashboard_dir}"
      # Set ownership/permissions if needed (e.g., if served by proxy user)
      chown -R "${box_user_group}" "${target_dashboard_dir}" || log Warn "Failed dashboard chown"
      chmod -R u=rwX,g=rX,o= "${target_dashboard_dir}" || log Warn "Failed dashboard chmod" # User rwx, Group rx, Other none
      return 0
    else
      log Error "Failed to move extracted dashboard contents."
      rm -f "${zip_file}"
      rm -rf "${target_dashboard_dir}" # Clean up failed extraction
      return 1
    fi
   else
    log Error "Failed to extract dashboard zip file: ${zip_file}"
    rm -f "${zip_file}"
    # Don't remove target dir if extraction failed, might contain old files
    return 1
   fi
  else
   log Error "Failed to download dashboard UI."
   rm -f "${zip_file}"
   return 1
  fi
 else
  log Info "${bin_name} does not typically support a dedicated dashboard UI."
  return 0 # Not an error if not supported
 fi
}


# --- CGroup Functions ---
# Note: These assume cgroup v1. Paths and behavior might differ with v2.
# They also assume the service runs long enough for this script to find its PID.

find_cgroup_path() {
 local subsystem="$1" # e.g., memory, cpuset, blkio
 mount | grep 'cgroup' | grep "${subsystem}" | awk '{print $3}' | head -n 1
}

cgroup_blkio() {
 local path="${blkio_path:-$(find_cgroup_path blkio)}"
 local pid_val=$( [ -f "${box_pid}" ] && cat "${box_pid}" 2>/dev/null )

 if [ -z "${path}" ]; then log Warn "cgroup blkio path not found/set."; return 1; fi
 if [ ! -d "${path}" ]; then log Warn "cgroup blkio path does not exist: ${path}"; return 1; fi
 if [ -z "$pid_val" ]; then log Warn "PID not found in ${box_pid}"; return 1; fi

 # Linux doesn't typically have a 'background' blkio group by default.
 # Applying settings directly to the base group or a custom one is more common.
 # Example: Setting weight (Range 100-1000, default 500 for cfq)
 # echo 100 > "${path}/blkio.weight" # Lower priority example
 # For simplicity, just add pid to the base controller's task list if possible.
 if [ -w "${path}/cgroup.procs" ]; then
  echo "$pid_val" > "${path}/cgroup.procs" && log Info "Added PID ${pid_val} to blkio cgroup (${path})" || log Error "Failed to add PID ${pid_val} to ${path}/cgroup.procs"
 else
  log Warn "Cannot write to ${path}/cgroup.procs (no default group or permission issue?)"
  return 1
 fi
 return 0
}

cgroup_memcg() {
 local path="${memcg_path:-$(find_cgroup_path memory)}"
 local pid_val=$( [ -f "${box_pid}" ] && cat "${box_pid}" 2>/dev/null )
 local limit="${memcg_limit}" # Get limit from settings.ini

 if [ -z "${path}" ]; then log Warn "cgroup memory path not found/set."; return 1; fi
 if [ ! -d "${path}" ]; then log Warn "cgroup memory path does not exist: ${path}"; return 1; fi
 if [ -z "$pid_val" ]; then log Warn "PID not found in ${box_pid}"; return 1; fi
 if [ -z "$limit" ]; then log Info "Memory limit (memcg_limit) not set in settings. Skipping memory limit."; return 0; fi

 # Create a subdirectory for the service if needed
 local service_cgroup_path="${path}/${bin_name}"
 mkdir -p "${service_cgroup_path}" || { log Error "Failed to create memory cgroup dir: ${service_cgroup_path}"; return 1; }

 # Set the limit
 if [ -w "${service_cgroup_path}/memory.limit_in_bytes" ]; then
  echo "${limit}" > "${service_cgroup_path}/memory.limit_in_bytes" \
  && log Info "${bin_name} memory limit set to ${limit} bytes in ${service_cgroup_path}" \
  || { log Error "Failed to set memory limit in ${service_cgroup_path}"; rmdir "${service_cgroup_path}" 2>/dev/null; return 1; }
 else
  log Error "Cannot write to memory.limit_in_bytes in ${service_cgroup_path}"; rmdir "${service_cgroup_path}" 2>/dev/null; return 1;
 fi

 # Add the process ID to the group
 if [ -w "${service_cgroup_path}/cgroup.procs" ]; then
  echo "$pid_val" > "${service_cgroup_path}/cgroup.procs" \
  && log Info "Added PID ${pid_val} to memory cgroup (${service_cgroup_path})" \
  || { log Error "Failed to add PID ${pid_val} to ${service_cgroup_path}/cgroup.procs"; return 1; } # Don't remove dir if PID add failed
 else
  log Error "Cannot write to cgroup.procs in ${service_cgroup_path}"; return 1; # Don't remove dir
 fi
 return 0
}

cgroup_cpuset() {
 local path="${cpuset_path:-$(find_cgroup_path cpuset)}"
 local pid_val=$( [ -f "${box_pid}" ] && cat "${box_pid}" 2>/dev/null )

 if [ -z "${path}" ]; then log Warn "cgroup cpuset path not found/set."; return 1; fi
 if [ ! -d "${path}" ]; then log Warn "cgroup cpuset path does not exist: ${path}"; return 1; fi
 if [ -z "$pid_val" ]; then log Warn "PID not found in ${box_pid}"; return 1; fi

 # Linux doesn't have a 'top-app' cpuset group by default. Common practice is to
 # either create a specific subset (e.g., for background tasks) or just add
 # the process to an existing relevant group (like system.slice/...).
 # For simplicity, just try adding PID to the base cpuset controller's tasks.
 # More advanced: define cpuset_cores="0-1" in settings and apply to a custom group.
 if [ -w "${path}/cgroup.procs" ]; then
  echo "$pid_val" > "${path}/cgroup.procs" \
  && log Info "Added PID ${pid_val} to base cpuset cgroup (${path})" \
  || log Error "Failed to add PID ${pid_val} to ${path}/cgroup.procs"
 else
  log Warn "Cannot write to ${path}/cgroup.procs (no default group assignment or permission issue?)"
  return 1
 fi
 return 0
}

# --- Helper to get web UI address ---
# This requires parsing specific config files and is complex. Simple version:
get_controller_address() {
 # Reuse logic from reload function, just return ip:port
 local ip="" port=""
 case "${bin_name}" in
 clash)
  ip=$(awk -F'[: ]+' '!/^ *#/ && /external-controller:/ {print $3}' "${clash_config}" 2>/dev/null)
  port=$(awk -F'[: ]+' '!/^ *#/ && /external-controller:/ {print $4}' "${clash_config}" 2>/dev/null)
  ;;
 sing-box)
  ip=$(find "${sing_config_dir}" -maxdepth 1 -type f \( -name '*.json' -o -name '*.json5' \) -exec sh -c "grep -oE '\"(external_controller|listen)\":\s*\"[0-9.]+\"' {} | head -1 | cut -d'\"' -f4" \; 2>/dev/null)
  port=$(find "${sing_config_dir}" -maxdepth 1 -type f \( -name '*.json' -o -name '*.json5' \) -exec sh -c "grep -oE '\"(external_controller|listen_port)\":\s*[0-9]+' {} | head -1 | grep -oE '[0-9]+'" \; 2>/dev/null)
  if [[ -z "$ip" ]]; then ip="127.0.0.1"; fi
  ;;
 *)
  # Assume no standard controller for others
  ip="" port=""
  ;;
 esac
 # Construct address, default to localhost if only port found
 if [[ -n "$port" ]]; then
  echo "${ip:-127.0.0.1}:${port}"
 else
  echo "" # Return empty if cannot determine
 fi
}

# --- Webroot index generation ---
webroot() {
 # Define where the webroot index file should be placed
 # Option 1: Inside config dir (simple)
 local path_webroot="${box_dir}/webroot/index.html"
 # Option 2: Standard web server path (if hosting via nginx/apache)
 # local path_webroot="/var/www/html/box/index.html"
 # Ensure the directory exists
 mkdir -p "$(dirname "${path_webroot}")" || { log Error "Failed to create webroot directory"; return 1; }

 log Info "Generating webroot redirect file at ${path_webroot}"

 local controller_addr=$(get_controller_address)

 if [[ "${bin_name}" == @(clash|sing-box) ]] && [[ -n "$controller_addr" ]]; then
  cat > "${path_webroot}" <<- EOF
<!DOCTYPE html>
<html lang="en">
<head>
 <meta charset="UTF-8">
 <meta http-equiv="refresh" content="0; url=http://${controller_addr}/ui/">
 <title>Redirecting...</title>
 <script>
  document.location = 'http://${controller_addr}/ui/';
 </script>
</head>
<body>
 <p>If you are not redirected automatically, follow this <a href="http://${controller_addr}/ui/">link to the dashboard</a>.</p>
</body>
</html>
EOF
  log Info "Webroot redirect created for ${bin_name} UI at http://${controller_addr}/ui/"
 else
  cat > "${path_webroot}" <<- EOF
<!DOCTYPE html>
<html lang="en">
<head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
 <title>Unsupported Dashboard</title>
 <style>
  body { font-family: sans-serif; text-align: center; padding: 50px; }
  h1 { color: #cc0000; }
 </style>
</head>
<body>
 <h1>Dashboard Not Available</h1>
 <p>Sorry, ${bin_name} does not have a standard web dashboard interface, or its address could not be determined.</p>
</body>
</html>
EOF
  log Info "Generated placeholder page, as dashboard is not supported or configured for ${bin_name}."
 fi
 # Set permissions if needed (e.g., readable by web server user)
 chown "${box_user_group}" "${path_webroot}" || log Warn "Failed chown ${path_webroot}"
 chmod 0644 "${path_webroot}" || log Warn "Failed chmod ${path_webroot}"
}

# --- Network Parameter Tweaks ---
# WARNING: These are system-wide settings. Use with caution.
# Original script had specific Android interface names. Generalize or make interfaces configurable.

# Function to set parameters for multiple interfaces matching a pattern
set_iface_params() {
  local pattern="$1" # e.g., "eth", "wlp"
  local param="$2"   # e.g., "txqueuelen", "mtu"
  local value="$3"
  log Debug "Setting ${param}=${value} for interfaces matching ${pattern}*"
  for iface_path in /sys/class/net/${pattern}*; do
    if [ -e "$iface_path" ]; then
      local iface_name=$(basename "$iface_path")
      if ip link set dev "$iface_name" "${param}" "${value}"; then
        log Debug " -> Set ${param}=${value} for ${iface_name}"
      else
        log Warn " -> Failed to set ${param}=${value} for ${iface_name}"
      fi
    fi
  done
}

# Example presets (adapt interface patterns and values as needed)
bond0() {
 log Info "Applying 'bond0' network tweaks (lower latency focus)..."
 # TCP low latency mode (0 might mean disabled on Linux, check sysctl docs)
 if sysctl -w net.ipv4.tcp_low_latency=0 >/dev/null 2>&1; then
  log Debug "net.ipv4.tcp_low_latency=0"
 else
  log Warn "Failed to set net.ipv4.tcp_low_latency=0"
 fi
 # Adjust txqueuelen (lower values might suit low latency)
 set_iface_params "eth" "txqueuelen" 1000 # Example for wired
 set_iface_params "wlp" "txqueuelen" 1000 # Example for wireless
 set_iface_params "wwan" "txqueuelen" 500 # Example for modem
 # Adjust MTU if necessary (usually 1500 is standard)
 set_iface_params "eth" "mtu" 1500
 set_iface_params "wlp" "mtu" 1500
 set_iface_params "wwan" "mtu" 1500
}

bond1() {
 log Info "Applying 'bond1' network tweaks (higher throughput focus)..."
 # TCP low latency mode (1 might mean enabled, check docs)
 if sysctl -w net.ipv4.tcp_low_latency=1 >/dev/null 2>&1; then
  log Debug "net.ipv4.tcp_low_latency=1"
 else
  log Warn "Failed to set net.ipv4.tcp_low_latency=1 (might not exist or be bool)"
 fi
 # Adjust txqueuelen (higher values for throughput)
 set_iface_params "eth" "txqueuelen" 3000 # Example for wired
 set_iface_params "wlp" "txqueuelen" 3000 # Example for wireless
 set_iface_params "wwan" "txqueuelen" 1000 # Example for modem
 # Adjust MTU (Jumbo frames - only if network supports it!)
 # set_iface_params "eth" "mtu" 9000 # Caution with MTU > 1500
}


# --- Main Execution Logic ---

action="$1"
shift # Remove the action from arguments list

case "$action" in
 check)
 check
 ;;
 memcg|cpuset|blkio)
 log Info "Applying cgroup setting: ${action}"
 # PID must exist when these are run. Maybe call after service start?
 "cgroup_${action}"
 ;;
 bond0|bond1)
 if [[ $(id -u) -ne 0 ]]; then log Error "Network tweaks (${action}) require root privileges."; exit 1; fi
 "$action"
 ;;
 geosub)
 log Info "Running combined GeoIP/Geosite and Subscription update..."
 upsubs && upgeox
 local exit_code=$?
 if [ $exit_code -eq 0 ]; then
  log Info "Geo/Sub update process finished. Reloading configuration..."
  # Reload only if updates were successful (or not needed)
  if [ -f "${box_pid}" ] && kill -0 "$(<"${box_pid}" 2>/dev/null)"; then
   reload
  else
   log Info "Service not running, skipping reload."
  fi
 else
  log Error "Geo/Sub update failed. See logs above. Skipping reload."
 fi
 ;;
 geox|subs)
 log Info "Running update for: ${action}"
 if [ "$action" = "geox" ]; then
  upgeox || exit 1
 else # subs
  upsubs || exit 1
 fi
 log Info "Update for ${action} finished. Reloading configuration..."
 if [ -f "${box_pid}" ] && kill -0 "$(<"${box_pid}" 2>/dev/null)"; then
  reload
 else
  log Info "Service not running, skipping reload."
 fi
 ;;
 upkernel)
 upkernel
 ;;
 upxui)
 upxui
 ;;
 upyq|upcurl)
 log Info "Attempting update for tool: ${action}"
 "$action"
 ;;
 reload)
 reload
 ;;
 webroot)
 webroot
 ;;
 all)
  log Info "Running all update tasks..."
  all_success=true
  upyq || all_success=false
  upcurl || all_success=false
  # Assume bin_list array is defined in settings.ini
  if [[ ${#bin_list[@]} -gt 0 ]]; then
    original_bin_name=$bin_name # Save current active bin name
    for core_name in "${bin_list[@]}"; do
      log Info "--- Processing updates for potential core: ${core_name} ---"
      # Temporarily set bin_name for this loop iteration to update correctly
      bin_name=$core_name
      # Update derived variables based on new bin_name if needed (e.g. paths)
      # This part is tricky, assume upkernel/upgeox/etc adapt based on the global bin_name
      upkernel || log Error "Failed kernel update for ${core_name}" # Continue even if one fails
      upgeox || log Error "Failed geox update for ${core_name}"
      upsubs || log Error "Failed subs update for ${core_name}" # Might just log warnings for non-Clash
      upxui || log Error "Failed dashboard update for ${core_name}" # Might just log info for non-Clash/Singbox
    done
    bin_name=$original_bin_name # Restore original bin_name
    log Info "--- Finished processing all cores ---"
  else
    log Warn "'bin_list' not defined in settings. Cannot run updates for all cores."
    all_success=false
  fi
  if [[ "$all_success" = true ]]; then
    log Info "All update tasks completed."
  else
    log Error "One or more 'all' update tasks failed. Please check logs."
    exit 1
  fi
 ;;
 *)
  echo "${red}Error: Action '$action' not recognized.${normal}" >&2
  echo "${yellow}Usage${normal}: ${green}$0${normal} {${yellow}check|memcg|cpuset|blkio|geosub|geox|subs|upkernel|upxui|upyq|upcurl|reload|webroot|bond0|bond1|all${normal}}" >&2
  exit 1
 ;;
esac

exit 0 # Explicit success exit