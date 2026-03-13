#!/bin/sh

# OPNsense helper script for Zabbix UserParameters
# Requires: /bin/sh, awk, php, pfctl, route, pgrep, netstat, ifconfig
# Intended for OPNsense / FreeBSD.

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

pf_states_current() {
  pfctl -si 2>/dev/null | awk '/current entries/ {print $3; found=1; exit} END {if (!found) print 0}'
}

pf_states_max() {
  pfctl -si 2>/dev/null | awk '/limit states/ {print $4; found=1; exit} END {if (!found) print 0}'
}

pf_states_percent() {
  cur="$(pf_states_current)"
  max="$(pf_states_max)"
  if [ -z "$max" ] || [ "$max" -eq 0 ] 2>/dev/null; then
    echo 0
  else
    awk -v c="$cur" -v m="$max" 'BEGIN { printf "%.2f\n", (c*100)/m }'
  fi
}

pf_counter() {
  counter="$1"
  pfctl -si 2>/dev/null | awk -v c="$counter" '
    BEGIN { found=0 }
    $1 == c {
      print $2;
      found=1;
      exit
    }
    END { if (!found) print 0 }'
}

# Sum of all PF error/drop counters from pfctl -si.
# Excludes 'match' (counts all rule hits, including pass rules) and
# 'synproxy' (proxy intercept, not a discard). Everything else —
# bad-offset, fragment, short, normalize, memory, bad-timestamp,
# congestion, ip-option, proto-cksum, state-mismatch, state-insert,
# state-limit, src-limit, map-failed — represents a packet PF discarded.
pf_error_packets() {
  pfctl -si 2>/dev/null | awk '
    /^Counters$/     { in_c=1; next }
    in_c && /^[A-Z]/ { in_c=0 }
    in_c && $1 != "match" && $1 != "synproxy" { sum += $2 }
    END { print sum+0 }
  '
}

carp_master_count() {
  ifconfig 2>/dev/null | awk '/carp: .*MASTER/ {c++} END {print c+0}'
}

carp_backup_count() {
  ifconfig 2>/dev/null | awk '/carp: .*BACKUP/ {c++} END {print c+0}'
}

default_route_present() {
  route -n get default >/dev/null 2>&1 && echo 1 || echo 0
}

ipsec_established() {
  if command -v swanctl >/dev/null 2>&1; then
    swanctl --list-sas 2>/dev/null | awk '/ESTABLISHED/ {c++} END {print c+0}'
  elif command -v ipsec >/dev/null 2>&1; then
    ipsec statusall 2>/dev/null | awk '/ESTABLISHED/ {c++} END {print c+0}'
  else
    echo 0
  fi
}

openvpn_processes() {
  pgrep -f '/usr/local/sbin/openvpn' 2>/dev/null | awk 'END {print NR+0}'
}

# Emit a Zabbix LLD JSON array of OpenVPN instances whose .conf file in
# /var/etc/openvpn/ contains an inline <cert> block.  Each entry carries
# {#OVPN_CERT} set to the conf basename without extension (e.g. "server1",
# "client2").  OPNsense embeds the leaf certificate directly inside the conf
# file using OpenVPN's inline block syntax rather than separate .cert files.
openvpn_cert_discovery() {
  dir="/var/etc/openvpn"
  if [ ! -d "$dir" ]; then
    printf '{"data":[]}\n'
    return
  fi
  found=0
  printf '{"data":['
  for f in "$dir"/server[0-9]*.conf "$dir"/client[0-9]*.conf; do
    [ -r "$f" ] || continue
    # Only include instances that actually have an inline certificate block.
    grep -q '<cert>' "$f" 2>/dev/null || continue
    name="$(basename "$f" .conf)"
    # Skip any name that contains characters outside the safe set to avoid
    # JSON injection or unexpected behaviour downstream.
    case "$name" in
      *[!a-zA-Z0-9_-]*) continue ;;
    esac
    [ "$found" -gt 0 ] && printf ','
    printf '{"{#OVPN_CERT}":"%s"}' "$name"
    found=$((found + 1))
  done
  printf ']}\n'
}

# Return days remaining until the leaf certificate for a given OpenVPN
# instance expires.  Argument is the bare instance name as produced by
# openvpn_cert_discovery (e.g. "server1").  The certificate PEM is extracted
# from the inline <cert>...</cert> block inside the .conf file and fed to
# openssl on stdin.  Returns -9999 when the conf file cannot be read, the
# name fails the safety check, or openssl cannot parse the certificate.
openvpn_cert_days() {
  name="$1"
  case "$name" in
    "" | *[!a-zA-Z0-9_-]*) echo -9999; return ;;
  esac
  conffile="/var/etc/openvpn/${name}.conf"
  [ -r "$conffile" ] || { echo -9999; return; }
  enddate="$(awk '/<cert>/{p=1;next} /<\/cert>/{p=0} p' "$conffile" \
    | openssl x509 -enddate -noout 2>/dev/null | cut -d= -f2)"
  [ -z "$enddate" ] && { echo -9999; return; }
  end_epoch="$(date -j -f "%b %d %T %Y %Z" "$enddate" "+%s" 2>/dev/null)"
  [ -z "$end_epoch" ] && { echo -9999; return; }
  now_epoch="$(date +%s)"
  echo $(( (end_epoch - now_epoch) / 86400 ))
}

unbound_processes() {
  pgrep -f '/usr/local/sbin/unbound' 2>/dev/null | awk 'END {print NR+0}'
}

dhcp_leases() {
  leasefile="/var/dhcpd/var/db/dhcpd.leases"
  [ -r "$leasefile" ] || { echo 0; exit 0; }
  awk '/^lease / {c++} END {print c+0}' "$leasefile"
}

# netstat -n -I IFACE -bdi on OPNsense column layout (data row = NR==2):
# Ipkts=$5  Ierrs=$6  Idrop=$7  Ibytes=$8  Opkts=$9  Oerrs=$10  Obytes=$11
if_inerrors() {
  iface="$1"
  netstat -n -I "$iface" -bdi 2>/dev/null | awk 'NR==2 {print $6; found=1} END {if (!found) print 0}'
}

if_idrop() {
  iface="$1"
  netstat -n -I "$iface" -bdi 2>/dev/null | awk 'NR==2 {print $7; found=1} END {if (!found) print 0}'
}

if_outerrors() {
  iface="$1"
  netstat -n -I "$iface" -bdi 2>/dev/null | awk 'NR==2 {print $10; found=1} END {if (!found) print 0}'
}

gateways_json() {
  if command -v configctl >/dev/null 2>&1; then
    configctl interface gateways status 2>/dev/null
  else
    echo "[]"
  fi
}

gateway_discovery() {
  data="$(gateways_json)"
  php -r '
    $in = stream_get_contents(STDIN);
    $j = json_decode($in, true);
    if (!is_array($j)) { echo "{\"data\":[]}"; exit(0); }
    $out = ["data" => []];
    foreach ($j as $gw) {
      if (!is_array($gw) || !isset($gw["name"])) continue;
      $out["data"][] = ["{#GWNAME}" => (string)$gw["name"]];
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES);
  ' <<EOF
$data
EOF
}

gateway_metric() {
  gw="$1"
  metric="$2"
  data="$(gateways_json)"
  php -r '
    $gw = $argv[1];
    $metric = $argv[2];
    $in = stream_get_contents(STDIN);
    $j = json_decode($in, true);
    if (!is_array($j)) { echo ($metric === "status_translated" ? "unknown" : "0"); exit(0); }
    foreach ($j as $row) {
      if (!is_array($row) || !isset($row["name"])) continue;
      if ((string)$row["name"] !== $gw) continue;
      if (!array_key_exists($metric, $row)) {
        echo ($metric === "status_translated" ? "unknown" : "0");
        exit(0);
      }
      $v = trim((string)$row[$metric]);
      if ($metric === "status_translated") {
        echo $v === "" ? "unknown" : $v;
        exit(0);
      }
      if ($v === "~" || $v === "") {
        echo "0";
        exit(0);
      }
      if (preg_match("/([0-9]+(?:\.[0-9]+)?)/", $v, $m)) {
        echo $m[1];
        exit(0);
      }
      echo "0";
      exit(0);
    }
    echo ($metric === "status_translated" ? "unknown" : "0");
  ' "$gw" "$metric" <<EOF
$data
EOF
}

ssl_cert_days_remaining() {
  certfile="${1:-/var/etc/cert.pem}"
  [ -r "$certfile" ] || { echo -9999; return; }
  enddate="$(openssl x509 -enddate -noout -in "$certfile" 2>/dev/null | cut -d= -f2)"
  [ -z "$enddate" ] && { echo -9999; return; }
  end_epoch="$(date -j -f "%b %d %T %Y %Z" "$enddate" "+%s" 2>/dev/null)"
  [ -z "$end_epoch" ] && { echo -9999; return; }
  now_epoch="$(date +%s)"
  echo $(( (end_epoch - now_epoch) / 86400 ))
}

cmd="$1"
shift 2>/dev/null || true

case "$cmd" in
  pf_states_current) pf_states_current ;;
  pf_states_max) pf_states_max ;;
  pf_states_percent) pf_states_percent ;;
  pf_counter) pf_counter "$@" ;;
  pf_error_packets) pf_error_packets ;;

  carp_master_count) carp_master_count ;;
  carp_backup_count) carp_backup_count ;;

  default_route_present) default_route_present ;;

  ipsec_established) ipsec_established ;;
  openvpn_processes) openvpn_processes ;;
  openvpn_cert_discovery) openvpn_cert_discovery ;;
  openvpn_cert_days) openvpn_cert_days "$@" ;;

  unbound_processes) unbound_processes ;;
  dhcp_leases) dhcp_leases ;;

  if_inerrors) if_inerrors "$@" ;;
  if_idrop) if_idrop "$@" ;;
  if_outerrors) if_outerrors "$@" ;;

  gateway_discovery) gateway_discovery ;;
  gateway_metric) gateway_metric "$@" ;;

  ssl_cert_days_remaining) ssl_cert_days_remaining "$@" ;;
  *)
    echo "ZBX_NOTSUPPORTED"
    exit 1
    ;;
esac
