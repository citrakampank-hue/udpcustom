#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="udp-custom-server"
SERVICE_USER="root"
SERVICE_GROUP="root"
GROUP_EXPLICIT=0
SYSTEMD_DIR="/etc/systemd/system"
ENABLE_SERVICE=0
START_SERVICE=0
UNINSTALL_SERVICE=0
REMOVE_USER=0
AUTO_IPTABLES=0
IPTABLES_INTERFACE=""
IPTABLES_EXCLUDE=""
IPTABLES_RANGES="1024-65535"
IPTABLES_CHAIN="UDP_CUSTOM_HOP"
LISTEN_ADDR=":36712"
CONFIG_SOURCE=""
BINARY_SOURCE="${UDP_CUSTOM_SERVER_BINARY:-}"
SERVER_ARCH="${UDP_CUSTOM_SERVER_ARCH:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR="${SCRIPT_DIR}"

usage() {
	cat <<'EOF'
Installer systemd untuk udp-custom-server.

Usage:
  sudo ./install-udp-custom-server.sh [options]

Options:
  --work-dir <dir>          WorkingDirectory unit. Default: directory tempat installer berada.
  --binary <path>           Path binary udp-custom-server yang sudah jadi.
                            Default: pakai udp-custom-server dari work-dir jika ada.
                            Path relatif dicari dari work-dir dulu.
  --config <path>           Path server.json yang akan dipasang jika work-dir belum punya config.
                            Default: pertahankan server.json dari work-dir jika sudah ada.
                            Service membaca server.json dari WorkingDirectory.
                            Path relatif dicari dari work-dir dulu.
  --listen <addr:port>      Listen address server. Default: :36712
  --auto-iptables           Tambahkan rule iptables redirect lewat systemd ExecStartPre.
                            hop_listen server.json otomatis mengikuti range
                            efektif setelah --iptables-exclude.
  --iptables-interface <if> Interface publik. Default: deteksi dari route 8.8.8.8.
  --iptables-ranges <csv>   Range UDP yang diizinkan, contoh: 1024-7299,7301-65535.
                            Default: 1024-65535, dipotong otomatis oleh
                            --iptables-exclude saat --auto-iptables aktif.
  --iptables-exclude <csv>  Port UDP yang tidak diarahkan, contoh: 5300,7300.
                            Port ini tidak dimasukkan ke hop_listen/rule redirect.
  --arch <arch>             Arsitektur binary siap pakai. Default: deteksi host.
  --service-name <name>     Nama unit systemd. Default: udp-custom-server
  --user <name>             User systemd. Default: root
  --group <name>            Group systemd. Default: root
  --enable                  Enable service saat boot.
  --start                   Start service setelah install.
  --uninstall               Stop, hapus rule iptables, disable, dan hapus service systemd.
  --remove-user             Saat --uninstall, hapus user/group system non-root jika ada.
  -h, --help                Tampilkan bantuan.

Contoh:
  cd /opt/udp-custom
  sudo ./install-udp-custom-server.sh --enable --start

  sudo ./install-udp-custom-server.sh \
    --work-dir /opt/udp-custom \
    --binary /path/to/udp-custom-server \
    --config /path/to/server.json \
    --listen :36712 \
    --auto-iptables \
    --iptables-ranges 1024-7299,7301-65535 \
    --iptables-exclude 5300,7300 \
    --enable \
    --start
EOF
}

fail() {
	echo "error: $*" >&2
	exit 1
}

absolute_path() {
	case "$1" in
		/*)
			printf '%s\n' "$1"
			;;
		*)
			printf '%s\n' "$(pwd)/$1"
			;;
	esac
}

source_path() {
	case "$1" in
		/*)
			printf '%s\n' "$1"
			;;
		*)
			if [ -e "${WORK_DIR}/$1" ]; then
				printf '%s\n' "${WORK_DIR}/$1"
			else
				absolute_path "$1"
			fi
			;;
	esac
}

validate_name() {
	local label="$1"
	local value="$2"
	if ! [[ "${value}" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
		fail "${label} hanya boleh berisi huruf, angka, titik, underscore, @, dan dash"
	fi
}

validate_port_value() {
	local label="$1"
	local value="$2"
	if ! [[ "${value}" =~ ^[0-9]+$ ]] || [ "${value}" -lt 1 ] || [ "${value}" -gt 65535 ]; then
		fail "${label} tidak valid: ${value}"
	fi
}

normalize_iptables_ranges() {
	local compact
	local token
	local start
	local end
	local output=""
	local -a tokens
	compact="$(printf '%s' "${IPTABLES_RANGES}" | tr -d '[:space:]')"
	[ -n "${compact}" ] || fail "--iptables-ranges kosong"
	IFS=',' read -r -a tokens <<<"${compact}"
	for token in "${tokens[@]}"; do
		[ -n "${token}" ] || fail "--iptables-ranges berisi token kosong"
		case "${token}" in
			*-*)
				start="${token%%-*}"
				end="${token#*-}"
				;;
			*)
				start="${token}"
				end="${token}"
				;;
		esac
		validate_port_value "range start" "${start}"
		validate_port_value "range end" "${end}"
		if [ "${start}" -gt "${end}" ]; then
			fail "range tidak valid: ${start}-${end}"
		fi
		if [ "${start}" = "${end}" ]; then
			output="${output:+${output},}${start}"
		else
			output="${output:+${output},}${start}-${end}"
		fi
	done
	printf '%s\n' "${output}"
}

normalize_iptables_excludes() {
	local compact
	local token
	local output=""
	local -a tokens
	compact="$(printf '%s' "${IPTABLES_EXCLUDE}" | tr -d '[:space:]')"
	[ -n "${compact}" ] || return 0
	IFS=',' read -r -a tokens <<<"${compact}"
	for token in "${tokens[@]}"; do
		[ -n "${token}" ] || fail "--iptables-exclude berisi token kosong"
		validate_port_value "exclude port" "${token}"
		output="${output:+${output},}${token}"
	done
	printf '%s\n' "${output}" | tr ',' '\n' | sort -n -u | paste -sd ',' -
}

append_port_range() {
	local start="$1"
	local end="$2"
	if [ "${start}" = "${end}" ]; then
		printf '%s\n' "${start}"
	else
		printf '%s-%s\n' "${start}" "${end}"
	fi
}

apply_iptables_excludes() {
	local ranges="$1"
	local excludes="$2"
	local token
	local exclude
	local start
	local end
	local current
	local range_part
	local output=""
	local -a range_tokens
	local -a exclude_tokens=()
	[ -n "${excludes}" ] || {
		printf '%s\n' "${ranges}"
		return
	}
	IFS=',' read -r -a range_tokens <<<"${ranges}"
	IFS=',' read -r -a exclude_tokens <<<"${excludes}"
	for token in "${range_tokens[@]}"; do
		case "${token}" in
			*-*)
				start="${token%%-*}"
				end="${token#*-}"
				;;
			*)
				start="${token}"
				end="${token}"
				;;
		esac
		current="${start}"
		for exclude in "${exclude_tokens[@]}"; do
			if [ "${exclude}" -lt "${current}" ] || [ "${exclude}" -gt "${end}" ]; then
				continue
			fi
			if [ "${exclude}" -gt "${current}" ]; then
				range_part="$(append_port_range "${current}" "$((exclude - 1))")"
				output="${output:+${output},}${range_part}"
			fi
			current="$((exclude + 1))"
			if [ "${current}" -gt "${end}" ]; then
				break
			fi
		done
		if [ "${current}" -le "${end}" ]; then
			range_part="$(append_port_range "${current}" "${end}")"
			output="${output:+${output},}${range_part}"
		fi
	done
	[ -n "${output}" ] || fail "--iptables-ranges habis setelah --iptables-exclude diterapkan"
	printf '%s\n' "${output}"
}

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		fail "jalankan sebagai root, contoh: sudo $0"
	fi
}

require_linux_systemd() {
	if [ "$(uname -s)" != "Linux" ]; then
		fail "installer ini hanya untuk Linux systemd"
	fi
	command -v systemctl >/dev/null 2>&1 || fail "systemctl tidak ditemukan"
	command -v install >/dev/null 2>&1 || fail "install tidak ditemukan"
}

detect_arch() {
	if [ -n "${SERVER_ARCH}" ]; then
		return
	fi
	case "$(uname -m)" in
		x86_64|amd64)
			SERVER_ARCH="amd64"
			;;
		i386|i686)
			SERVER_ARCH="386"
			;;
		aarch64|arm64)
			SERVER_ARCH="arm64"
			;;
		armv6l|armv7l|arm)
			SERVER_ARCH="arm"
			;;
		*)
			fail "arsitektur host tidak didukung: $(uname -m); gunakan --arch <arch>"
			;;
	esac
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--work-dir)
				[ "$#" -ge 2 ] || fail "--work-dir membutuhkan path"
				WORK_DIR="$2"
				shift 2
				;;
			--binary)
				[ "$#" -ge 2 ] || fail "--binary membutuhkan path"
				BINARY_SOURCE="$2"
				shift 2
				;;
			--config)
				[ "$#" -ge 2 ] || fail "--config membutuhkan path"
				CONFIG_SOURCE="$2"
				shift 2
				;;
			--listen)
				[ "$#" -ge 2 ] || fail "--listen membutuhkan addr:port"
				LISTEN_ADDR="$2"
				shift 2
				;;
			--auto-iptables)
				AUTO_IPTABLES=1
				shift
				;;
			--iptables-interface)
				[ "$#" -ge 2 ] || fail "--iptables-interface membutuhkan nama interface"
				IPTABLES_INTERFACE="$2"
				shift 2
				;;
			--iptables-ranges)
				[ "$#" -ge 2 ] || fail "--iptables-ranges membutuhkan daftar range port"
				IPTABLES_RANGES="$2"
				shift 2
				;;
			--iptables-exclude)
				[ "$#" -ge 2 ] || fail "--iptables-exclude membutuhkan daftar port"
				IPTABLES_EXCLUDE="$2"
				shift 2
				;;
			--arch)
				[ "$#" -ge 2 ] || fail "--arch membutuhkan nilai"
				SERVER_ARCH="$2"
				shift 2
				;;
			--service-name)
				[ "$#" -ge 2 ] || fail "--service-name membutuhkan nama"
				SERVICE_NAME="$2"
				shift 2
				;;
			--user)
				[ "$#" -ge 2 ] || fail "--user membutuhkan nama"
				SERVICE_USER="$2"
				if [ "${GROUP_EXPLICIT}" -ne 1 ]; then
					SERVICE_GROUP="${SERVICE_USER}"
				fi
				shift 2
				;;
			--group)
				[ "$#" -ge 2 ] || fail "--group membutuhkan nama"
				SERVICE_GROUP="$2"
				GROUP_EXPLICIT=1
				shift 2
				;;
			--enable)
				ENABLE_SERVICE=1
				shift
				;;
			--start)
				START_SERVICE=1
				shift
				;;
			--uninstall)
				UNINSTALL_SERVICE=1
				shift
				;;
			--remove-user)
				REMOVE_USER=1
				shift
				;;
			-h|--help)
				usage
				exit 0
				;;
			*)
				fail "option tidak dikenal: $1"
				;;
		esac
	done
}

resolve_defaults() {
	WORK_DIR="$(absolute_path "${WORK_DIR}")"
	if [ "${SERVICE_USER}" = "root" ]; then
		SERVICE_GROUP="root"
	fi
	if [ "${UNINSTALL_SERVICE}" -eq 1 ]; then
		return
	fi
	if [ -z "${BINARY_SOURCE}" ]; then
		detect_arch
		for candidate in \
			"${WORK_DIR}/udp-custom-server" \
			"${REPO_DIR}/udp-custom-server" \
			"${REPO_DIR}/build/server/linux/udp-custom-server-${SERVER_ARCH}"; do
			if [ -f "${candidate}" ]; then
				BINARY_SOURCE="${candidate}"
				break
			fi
		done
	fi
	[ -n "${BINARY_SOURCE}" ] || fail "binary tidak ditemukan; gunakan --binary <path>"
	BINARY_SOURCE="$(source_path "${BINARY_SOURCE}")"
	if [ -z "${CONFIG_SOURCE}" ] && [ -f "${REPO_DIR}/examples/server.json" ]; then
		CONFIG_SOURCE="${REPO_DIR}/examples/server.json"
	fi
	if [ -n "${CONFIG_SOURCE}" ]; then
		CONFIG_SOURCE="$(source_path "${CONFIG_SOURCE}")"
	fi
}

create_user_and_dir() {
	local nologin_shell="/usr/sbin/nologin"
	if [ ! -x "${nologin_shell}" ]; then
		nologin_shell="/sbin/nologin"
	fi
	if [ "${SERVICE_GROUP}" != "root" ] && ! getent group "${SERVICE_GROUP}" >/dev/null; then
		groupadd --system "${SERVICE_GROUP}"
	fi
	if [ "${SERVICE_USER}" != "root" ] && ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
		useradd --system --gid "${SERVICE_GROUP}" --home-dir "${WORK_DIR}" --shell "${nologin_shell}" "${SERVICE_USER}"
	fi
	install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${WORK_DIR}"
}

install_binary() {
	local target="${WORK_DIR}/udp-custom-server"
	[ -f "${BINARY_SOURCE}" ] || fail "binary tidak ditemukan: ${BINARY_SOURCE}"
	if [ "${BINARY_SOURCE}" != "${target}" ]; then
		install -m 0755 -o root -g "${SERVICE_GROUP}" "${BINARY_SOURCE}" "${target}"
	fi
	chown root:"${SERVICE_GROUP}" "${target}"
	chmod 0755 "${target}"
}

install_config() {
	local target="${WORK_DIR}/server.json"
	if [ -f "${target}" ]; then
		echo "Keeping existing ${target}."
		return
	fi
	[ -n "${CONFIG_SOURCE}" ] || fail "config tidak ditemukan; gunakan --config <path>"
	install -m 0640 -o root -g "${SERVICE_GROUP}" "${CONFIG_SOURCE}" "${target}"
}

sync_hop_listen_config() {
	if [ "${AUTO_IPTABLES}" -ne 1 ]; then
		return
	fi
	local target="${WORK_DIR}/server.json"
	local hop_listen=":${IPTABLES_RANGES}"
	local sync_status
	[ -f "${target}" ] || fail "server.json tidak ditemukan: ${target}"
	command -v python3 >/dev/null 2>&1 || fail "python3 dibutuhkan untuk menyinkronkan hop_listen otomatis"
	sync_status="$(python3 - "${target}" "${hop_listen}" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
hop_listen = sys.argv[2]
try:
    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
except Exception as exc:
    raise SystemExit(f"gagal membaca server.json: {exc}")
if not isinstance(config, dict):
    raise SystemExit("server.json harus berupa object JSON")
if config.get("hop_listen") == hop_listen:
    print("unchanged")
    raise SystemExit(0)
config["hop_listen"] = hop_listen
tmp_path = path.with_name(f"{path.name}.tmp")
with tmp_path.open("w", encoding="utf-8") as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
os.replace(tmp_path, path)
print("updated")
PY
)"
	chown root:"${SERVICE_GROUP}" "${target}"
	chmod 0640 "${target}"
	case "${sync_status}" in
		updated)
			echo "Synced hop_listen=${hop_listen} in ${target}."
			;;
		unchanged)
			echo "Keeping hop_listen=${hop_listen} in ${target}."
			;;
	esac
}

remove_legacy_environment_file() {
	local env_file="${WORK_DIR}/udp-custom-server.env"
	rm -f "${env_file}"
}

write_iptables_script() {
	if [ "${AUTO_IPTABLES}" -ne 1 ]; then
		return
	fi
	local script="${WORK_DIR}/udp-custom-iptables.sh"
	cat >"${script}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

ACTION="\${1:-add}"
LISTEN_ADDR="${LISTEN_ADDR}"
EXCLUDE_PORTS="${IPTABLES_EXCLUDE}"
HOP_RANGES="${IPTABLES_RANGES}"
CHAIN_NAME="${IPTABLES_CHAIN}"
PUBLIC_INTERFACE="${IPTABLES_INTERFACE}"

fail() {
	echo "error: \$*" >&2
	exit 1
}

listen_port() {
	local port="\${LISTEN_ADDR##*:}"
	[ -n "\${port}" ] || fail "listen port kosong: \${LISTEN_ADDR}"
	printf '%s\n' "\${port}"
}

detect_interface() {
	if [ -n "\${PUBLIC_INTERFACE}" ]; then
		printf '%s\n' "\${PUBLIC_INTERFACE}"
		return
	fi
	ip route get 8.8.8.8 | awk '{for (i=1; i<=NF; i++) if (\$i == "dev") {print \$(i+1); exit}}'
}

sorted_excludes() {
	{
		printf '%s\n' "\$(listen_port)"
		if [ -n "\${EXCLUDE_PORTS}" ]; then
			printf '%s\n' "\${EXCLUDE_PORTS}" | tr ',' '\n'
		fi
	} | awk 'NF {gsub(/[[:space:]]/, "", \$1); if (\$1 != "") print \$1}' | sort -n -u
}

validate_port() {
	local label="\$1"
	local port="\$2"
	if ! [[ "\${port}" =~ ^[0-9]+$ ]] || [ "\${port}" -lt 1 ] || [ "\${port}" -gt 65535 ]; then
		fail "\${label} tidak valid: \${port}"
	fi
}

hop_ranges() {
	local token
	local start
	local end
	printf '%s\n' "\${HOP_RANGES}" | tr ',' '\n' | while read -r token; do
		token="\${token//[[:space:]]/}"
		[ -n "\${token}" ] || continue
		token="\${token/-/:}"
		case "\${token}" in
			*:*)
				start="\${token%%:*}"
				end="\${token##*:}"
				;;
			*)
				start="\${token}"
				end="\${token}"
				;;
		esac
		validate_port "range start" "\${start}"
		validate_port "range end" "\${end}"
		if [ "\${start}" -gt "\${end}" ]; then
			fail "range tidak valid: \${start}-\${end}"
		fi
		printf '%s:%s\n' "\${start}" "\${end}"
	done
}

run_rule() {
	local family="\$1"
	shift
	if [ "\${family}" = "ip6tables" ] && ! is_ipv6_listen; then
		return
	fi
	if command -v "\${family}" >/dev/null 2>&1; then
		"\${family}" "\$@" || true
	fi
}

delete_rule() {
	local family="\$1"
	shift
	if [ "\${family}" = "ip6tables" ] && ! is_ipv6_listen; then
		return
	fi
	if command -v "\${family}" >/dev/null 2>&1; then
		"\${family}" "\$@" >/dev/null 2>&1 || true
	fi
}

reset_redirect_chain() {
	local family="\$1"
	local port="\$2"
	if [ "\${family}" = "ip6tables" ] && ! is_ipv6_listen; then
		return
	fi
	if ! command -v "\${family}" >/dev/null 2>&1; then
		return
	fi
	"\${family}" -t nat -N "\${CHAIN_NAME}" >/dev/null 2>&1 || true
	"\${family}" -t nat -F "\${CHAIN_NAME}" >/dev/null 2>&1 || true
	while read -r exclude_port; do
		[ -n "\${exclude_port}" ] || continue
		validate_port "exclude port" "\${exclude_port}"
		run_rule "\${family}" -t nat -A "\${CHAIN_NAME}" -p udp --dport "\${exclude_port}" -j RETURN
	done < <(sorted_excludes)
	run_rule "\${family}" -t nat -A "\${CHAIN_NAME}" -p udp -j REDIRECT --to-ports "\${port}"
}

delete_redirect_chain() {
	local family="\$1"
	if [ "\${family}" = "ip6tables" ] && ! is_ipv6_listen; then
		return
	fi
	if ! command -v "\${family}" >/dev/null 2>&1; then
		return
	fi
	"\${family}" -t nat -F "\${CHAIN_NAME}" >/dev/null 2>&1 || true
	"\${family}" -t nat -X "\${CHAIN_NAME}" >/dev/null 2>&1 || true
}

is_ipv6_listen() {
	case "\${LISTEN_ADDR}" in
		\[*\]*|*:*:*)
			return 0
			;;
		*)
			return 1
			;;
	esac
}

add_rules() {
	local iface
	local port
	iface="\$(detect_interface)"
	port="\$(listen_port)"
	validate_port "listen port" "\${port}"
	[ -n "\${iface}" ] || fail "interface publik tidak ditemukan; gunakan --iptables-interface"
	delete_rules
	sysctl -w net.core.rmem_max=16777216 >/dev/null || true
	sysctl -w net.core.wmem_max=16777216 >/dev/null || true
	run_rule iptables -I INPUT -p udp --dport "\${port}" -j ACCEPT
	run_rule ip6tables -I INPUT -p udp --dport "\${port}" -j ACCEPT
	reset_redirect_chain iptables "\${port}"
	reset_redirect_chain ip6tables "\${port}"
	while read -r range; do
		[ -n "\${range}" ] || continue
		run_rule iptables -t nat -I PREROUTING 1 -i "\${iface}" -p udp --dport "\${range}" -j "\${CHAIN_NAME}"
		run_rule ip6tables -t nat -I PREROUTING 1 -i "\${iface}" -p udp --dport "\${range}" -j "\${CHAIN_NAME}"
	done < <(hop_ranges)
}

delete_rules() {
	local iface
	local port
	iface="\$(detect_interface || true)"
	port="\$(listen_port)"
	[ -n "\${iface}" ] || return 0
	delete_rule iptables -D INPUT -p udp --dport "\${port}" -j ACCEPT
	delete_rule ip6tables -D INPUT -p udp --dport "\${port}" -j ACCEPT
	while read -r range; do
		[ -n "\${range}" ] || continue
		delete_rule iptables -D INPUT -p udp --dport "\${range}" -j ACCEPT
		delete_rule ip6tables -D INPUT -p udp --dport "\${range}" -j ACCEPT
		delete_rule iptables -t nat -D PREROUTING -i "\${iface}" -p udp --dport "\${range}" -j "\${CHAIN_NAME}"
		delete_rule ip6tables -t nat -D PREROUTING -i "\${iface}" -p udp --dport "\${range}" -j "\${CHAIN_NAME}"
	done < <(hop_ranges)
	delete_redirect_chain iptables
	delete_redirect_chain ip6tables
}

case "\${ACTION}" in
	add)
		add_rules
		;;
	delete)
		delete_rules
		;;
	*)
		fail "action tidak dikenal: \${ACTION}"
		;;
esac
EOF
	chown root:"${SERVICE_GROUP}" "${script}"
	chmod 0750 "${script}"
}

write_service_file() {
	local unit_file="${SYSTEMD_DIR}/${SERVICE_NAME}.service"
	local tmp_file
	tmp_file="$(mktemp)"
	cat >"${tmp_file}" <<EOF
[Unit]
Description=UDP Custom server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${WORK_DIR}
EOF
	if [ "${AUTO_IPTABLES}" -eq 1 ]; then
		cat >>"${tmp_file}" <<EOF
ExecStartPre=+${WORK_DIR}/udp-custom-iptables.sh add
ExecStopPost=+${WORK_DIR}/udp-custom-iptables.sh delete
EOF
	fi
	cat >>"${tmp_file}" <<EOF
ExecStart=${WORK_DIR}/udp-custom-server server --config server.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
	install -m 0644 -o root -g root "${tmp_file}" "${unit_file}"
	rm -f "${tmp_file}"
	systemctl daemon-reload
}

uninstall_service() {
	local unit_file="${SYSTEMD_DIR}/${SERVICE_NAME}.service"
	if systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1; then
		systemctl stop "${SERVICE_NAME}.service" || true
		systemctl disable "${SERVICE_NAME}.service" || true
	fi
	cleanup_iptables_on_uninstall
	remove_legacy_environment_file
	rm -f "${unit_file}"
	systemctl daemon-reload
	if [ "${REMOVE_USER}" -eq 1 ] && [ "${SERVICE_USER}" != "root" ]; then
		userdel "${SERVICE_USER}" >/dev/null 2>&1 || true
	fi
}

cleanup_iptables_on_uninstall() {
	local script="${WORK_DIR}/udp-custom-iptables.sh"
	if [ -x "${script}" ]; then
		"${script}" delete || true
	elif [ -f "${script}" ]; then
		bash "${script}" delete || true
	fi
}

main() {
	parse_args "$@"
	validate_name "service-name" "${SERVICE_NAME}"
	validate_name "user" "${SERVICE_USER}"
	validate_name "group" "${SERVICE_GROUP}"
	require_root
	require_linux_systemd
	resolve_defaults
	if [ "${UNINSTALL_SERVICE}" -eq 1 ]; then
		uninstall_service
		echo "Uninstalled ${SERVICE_NAME}.service"
		return
	fi
	if [ "${AUTO_IPTABLES}" -eq 1 ]; then
		IPTABLES_RANGES="$(apply_iptables_excludes "$(normalize_iptables_ranges)" "$(normalize_iptables_excludes)")"
	fi
	create_user_and_dir
	install_binary
	install_config
	sync_hop_listen_config
	remove_legacy_environment_file
	write_iptables_script
	write_service_file
	if [ "${ENABLE_SERVICE}" -eq 1 ]; then
		systemctl enable "${SERVICE_NAME}.service"
	fi
	if [ "${START_SERVICE}" -eq 1 ]; then
		systemctl restart "${SERVICE_NAME}.service"
	fi
	echo "Installed ${SERVICE_NAME}.service"
}

main "$@"
