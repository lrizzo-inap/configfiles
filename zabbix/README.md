## OPNsense Zabbix Agent Setup

### 1. Install Zabbix Agent Plugin
Install the **Zabbix Agent plugin** in OPNsense.

---

### 2. Open Zabbix Agent Settings
Navigate to:

Services → Zabbix Agent → Settings

---

### 3. Main Settings

Configure the following:

- **Hostname**
  - Set identical to the hostname configured in Zabbix.

- **Listen IP**
  - Set to the **firewall public IP**.

- **Zabbix Server**
  - Set to the **Zabbix Proxy IP**.

- **Enable sudo root permissions**
  - Enable this option.

- Click **Apply**.

---

### 4. Zabbix Features

Configure:

- **Enable Active Checks**

- **Active Check Server**
  - Set to the **Zabbix Proxy IP**.

- **Encryption**
  - Enable **PSK-based encryption**.

- **PSK Identity**
  - Set identical to the value configured on the **Zabbix Server**.

- **PSK**
  - Set identical to the value configured on the **Zabbix Server**.

- Click **Apply**.

---

### 5. Install Custom Files from GitHub Raw URLs

From the OPNsense shell, retrieve the files directly from GitHub and write them to the expected paths:

```sh
curl https://raw.githubusercontent.com/lrizzo-inap/configfiles/refs/heads/main/zabbix/opnsense-custom.conf > /usr/local/etc/zabbix_agentd.conf.d/opnsense-custom.conf
curl https://raw.githubusercontent.com/lrizzo-inap/configfiles/refs/heads/main/zabbix/opnsense-zabbix.sh > /usr/local/bin/opnsense-zabbix.sh
```
Set the required permissions:

```sh
chmod 644 /usr/local/etc/zabbix_agentd.conf.d/opnsense-custom.conf
chmod 755 /usr/local/bin/opnsense-zabbix.sh
```

---

### 6. Restart Zabbix Agent

Restart the Zabbix agent to apply all changes:

```sh
service zabbix_agentd restart

```

---

### 7. Verify Monitoring

After the restart, verify in Zabbix that the **data fields are being populated correctly**.

---

## Template Reference

The template **OPNsense Firewall by Zabbix agent** (Zabbix 7.2) monitors the areas described below. Items are collected via active Zabbix agent checks unless noted otherwise.

All alert thresholds are controlled by macros. Macros can be overridden per host in Zabbix without modifying the template — this is the recommended way to tune thresholds for a specific site.

---

### System

| Item | Key | Trigger | Condition |
|---|---|---|---|
| Zabbix agent availability | `agent.ping` | Agent unavailable | `last = 0` → **HIGH** |
| Zabbix agent version | `agent.version` | — | Informational only |
| System uptime | `system.uptime` | Firewall rebooted | `last < 600 s` → **WARNING** |

**Notes:**
- `agent.ping` is collected as a simple check from the Zabbix server, not an active check. If the firewall is reachable but the agent is broken, this fires.
- The uptime trigger fires for 10 minutes after any reboot — expected on planned maintenance, so acknowledge it in Zabbix.

---

### ICMP reachability

Collected by the Zabbix server (type SIMPLE — no agent required).

| Item | Key | Trigger | Condition |
|---|---|---|---|
| ICMP ping | `icmpping` | Host unavailable by ICMP | `max(5m) = 0` → **AVERAGE** |
| ICMP packet loss | `icmppingloss` | Loss critically high | `min(5m) > {$OPNSENSE.ICMP.LOSS.HIGH}` → **HIGH** |
| | | Loss high | `min(5m) > {$OPNSENSE.ICMP.LOSS.WARN}` → **WARNING** |
| ICMP response time | `icmppingsec` | RTT critically high | `avg(5m) > ICMP.RTT.HIGH / 1000` → **HIGH** |
| | | RTT high | `avg(5m) > ICMP.RTT.WARN / 1000` → **WARNING** |

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.ICMP.LOSS.HIGH}` | `60` % | ICMP loss threshold for HIGH alert |
| `{$OPNSENSE.ICMP.LOSS.WARN}` | `20` % | ICMP loss threshold for WARNING alert |
| `{$OPNSENSE.ICMP.RTT.HIGH}` | `500` ms | ICMP RTT threshold for HIGH alert (stored in ms, divided by 1000 in expression) |
| `{$OPNSENSE.ICMP.RTT.WARN}` | `150` ms | ICMP RTT threshold for WARNING alert |

---

### CPU

CPU utilization uses a two-item pattern because `system.cpu.util[,total]` is not supported by the Zabbix agent on FreeBSD/OPNsense.

| Item | Key | Type | Notes |
|---|---|---|---|
| CPU idle utilization | `system.cpu.util[,idle,avg1]` | Active | Raw idle %; stored for 7d history / 365d trends; no direct alert |
| CPU utilization | `cpu.util.total` | Calculated | `100 − idle`; used for all CPU triggers |

| Trigger | Condition |
|---|---|
| CPU utilization critically high | `avg(cpu.util.total, 5m) > {$OPNSENSE.CPU.UTIL.HIGH}` → **HIGH** |
| CPU utilization high | `avg(cpu.util.total, 5m) > {$OPNSENSE.CPU.UTIL.WARN}` → **WARNING** |

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.CPU.UTIL.HIGH}` | `95` % | Sustained load near saturation — likely IPS or VPN overload |
| `{$OPNSENSE.CPU.UTIL.WARN}` | `80` % | Elevated but recoverable; investigate traffic patterns |

---

### Memory

| Item | Key | Trigger | Condition |
|---|---|---|---|
| Memory available | `vm.memory.size[available]` | Available memory low | `last < {$OPNSENSE.MEM.AVAIL.MIN}` → **WARNING** |
| Memory used | `vm.memory.size[used]` | — | Informational / graphing only |

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.MEM.AVAIL.MIN}` | `200M` | Minimum free memory in bytes; `200M` = 200 MiB. Increase on systems with large state tables or Suricata. |

---

### Storage

| Item | Key | Trigger | Condition |
|---|---|---|---|
| Root filesystem free | `vfs.fs.size[/,pfree]` | Free space low | `last < {$OPNSENSE.FS.PFREE.MIN}` → **AVERAGE** |
| /var filesystem free | `vfs.fs.size[/var,pfree]` | Free space low | `last < {$OPNSENSE.FS.PFREE.MIN}` → **AVERAGE** |

Both filesystems share the same threshold macro. `/var` is monitored separately because it holds DHCP leases, logs, and service state; filling it can silently break services even when `/` has space.

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.FS.PFREE.MIN}` | `10` % | Applies to both `/` and `/var` |

---

### CARP (High Availability)

Collected every 30 seconds via `ifconfig` output.

| Item | Key | Trigger | Condition |
|---|---|---|---|
| CARP MASTER count | `opnsense.carp.master.count` | Count below minimum | `last < {$OPNSENSE.CARP.MASTER.MIN}` → **AVERAGE** |
| | | Count decreased | `change < 0` → **HIGH** |
| CARP BACKUP count | `opnsense.carp.backup.count` | — | Informational / graphing only |

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.CARP.MASTER.MIN}` | `0` | Set to `0` on non-HA hosts to disable the minimum check. On the primary node of an HA pair, set to the number of CARP VIPs expected to be MASTER on that node. |

**Notes:**
- The `change < 0` trigger (MASTER count decreased) fires immediately on any failover regardless of the minimum setting. It is useful for detecting unexpected demotions.
- On a secondary/backup node where MASTER count is normally 0, set `{$OPNSENSE.CARP.MASTER.MIN}` to `0` and expect the `change < 0` trigger to be silent during normal operation.

---

### Packet Filter (PF)

#### State table

| Item | Key | Notes |
|---|---|---|
| PF current states | `opnsense.pf.states.current` | Raw count from `pfctl -si` |
| PF maximum states | `opnsense.pf.states.max` | Polled every 10 minutes; changes only on config edits |
| PF state table utilization | `opnsense.pf.states.percent` | Calculated as `(current / max) × 100` |

| Trigger | Condition |
|---|---|
| Utilization critically high | `last(states.percent) > {$OPNSENSE.PF.STATES.HIGH}` → **HIGH** |
| Utilization high | `last(states.percent) > {$OPNSENSE.PF.STATES.WARN}` → **WARNING** |
| Exhaustion predicted | `timeleft(states.percent, 1h, 100) < {$OPNSENSE.PF.STATES.TIMETOFULL}` **and** `last(states.percent) > {$OPNSENSE.PF.STATES.PREDICT.FLOOR}` → **HIGH** |

The exhaustion prediction trigger uses `timeleft()`, which fits a linear trend to the past hour of utilization data and returns the estimated seconds until 100% is reached. The `PREDICT.FLOOR` guard suppresses the trigger when the table is lightly loaded (where `timeleft()` would produce unreliable extrapolations from near-zero values).

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.PF.STATES.WARN}` | `80` % | Warning threshold for current utilization |
| `{$OPNSENSE.PF.STATES.HIGH}` | `90` % | High threshold for current utilization |
| `{$OPNSENSE.PF.STATES.TIMETOFULL}` | `7200` s | Alert when exhaustion is predicted within this many seconds (default: 2 hours) |
| `{$OPNSENSE.PF.STATES.PREDICT.FLOOR}` | `40` % | Minimum utilization required before exhaustion prediction is evaluated |

#### PF error counters (individual)

These items read specific named counters from the `pfctl -si` Counters section and use `change() > 0` triggers — they fire the moment the counter increments, regardless of rate.

| Item | Key | Trigger | Notes |
|---|---|---|---|
| PF counter memory | `opnsense.pf.counter.memory` | `change > 0` → **HIGH** | PF could not allocate memory for a state or packet operation |
| PF counter state-limit | `opnsense.pf.counter.state-limit` | `change > 0` → **HIGH** | A rule's per-rule state limit was hit; distinct from the global table limit |

#### PF error packet rate (aggregate)

| Item | Key | Preprocessing | Units |
|---|---|---|---|
| PF error packet rate | `opnsense.pf.counter.dropped` | `CHANGE_PER_SECOND` | pps |

**Data source:** `pf_error_packets()` in `opnsense-zabbix.sh` — sums all Counters section values from `pfctl -si` except `match` (counts all rule hits including pass rules) and `synproxy` (proxy intercept, not a discard). Included counters: `bad-offset`, `fragment`, `short`, `normalize`, `memory`, `bad-timestamp`, `congestion`, `ip-option`, `proto-cksum`, `state-mismatch`, `state-insert`, `state-limit`, `src-limit`, `map-failed`.

**Why not `match`:** The `match` counter increments for every packet that hits any PF rule, including pass rules. It reflects total traffic throughput, not errors.

**Trigger — PF error packet spike detected:**
```
avg(5m) > {$OPNSENSE.PF.DROPPED.RATE.FLOOR}
AND avg(5m) > {$OPNSENSE.PF.DROPPED.SPIKE.FACTOR} × trendavg(1w)
```
Priority: **WARNING**

`trendavg(1w)` is Zabbix's 7-day baseline (hourly averages stored in trend tables). The trigger compares the current 5-minute average rate against a multiple of the site's own historical norm, making it self-calibrating. The floor condition prevents false positives when the baseline rounds to zero (e.g., a newly deployed firewall or one that normally has zero errors).

The trigger will not evaluate during the first hour after deployment because no trend data exists yet — this is the correct behaviour.

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.PF.DROPPED.RATE.FLOOR}` | `2` pps | Minimum absolute rate before spike detection activates. Prevents a single stray packet from satisfying `20 × 0 = 0`. |
| `{$OPNSENSE.PF.DROPPED.SPIKE.FACTOR}` | `20` | How many times above the weekly average the 5-minute rate must be to trigger. Raise this (e.g., to `50`) on sites with naturally variable error rates. |

---

### Routing

| Item | Key | Trigger | Condition |
|---|---|---|---|
| Default route present | `opnsense.route.default.present` | Default route missing | `last = 0` → **DISASTER** |

Returns `1` if `route -n get default` succeeds, `0` otherwise. A missing default route means the firewall cannot forward traffic to the internet.

---

### DNS (Unbound)

| Item | Key | Trigger | Condition |
|---|---|---|---|
| Unbound process count | `opnsense.unbound.processes` | Unbound not running | `max(5m) = 0` → **HIGH** |

Uses `pgrep -f /usr/local/sbin/unbound`. The `max(5m)` window prevents a single missed poll from triggering the alert.

---

### VPN

| Item | Key | Trigger | Condition |
|---|---|---|---|
| Established IPsec SAs | `opnsense.ipsec.established` | SA count below minimum | `last < {$OPNSENSE.VPN.IPSEC.MIN}` → **AVERAGE** |
| OpenVPN process count | `opnsense.openvpn.processes` | Process count below minimum | `last < {$OPNSENSE.OPENVPN.MIN}` → **WARNING** |

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.VPN.IPSEC.MIN}` | `0` | Set to the number of IPsec SAs expected to be up on this host. `0` disables the alert. |
| `{$OPNSENSE.OPENVPN.MIN}` | `0` | Set to the number of OpenVPN processes expected. `0` disables the alert. |

---

### DHCP

| Item | Key | Trigger | Condition |
|---|---|---|---|
| DHCP lease count | `opnsense.dhcp.leases` | Lease count above threshold | `last > {$OPNSENSE.DHCP.LEASES.WARN}` → **INFO** |

Counts `lease { }` blocks in `/var/dhcpd/var/db/dhcpd.leases`. Includes both active and expired leases not yet pruned from the file; intended as a rough capacity indicator.

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.DHCP.LEASES.WARN}` | `200` | Adjust to the expected maximum lease count for the subnet(s) served by this firewall |

---

### SSL Certificate

| Item | Key | Poll | Trigger | Condition |
|---|---|---|---|---|
| Web GUI SSL certificate days remaining | `opnsense.ssl.cert.days` | 1 h | Expires soon (HIGH) | `last < {$OPNSENSE.SSL.CERT.HIGH}` and `last >= 0` → **HIGH** |
| | | | Expires soon (WARNING) | `last < {$OPNSENSE.SSL.CERT.WARN}` and `last >= HIGH` → **WARNING** |

Reads `/var/etc/cert.pem` (OPNsense web GUI certificate) with `openssl x509 -enddate` and returns days remaining as an integer. Returns `-1` if the file is unreadable or the certificate is malformed; the `>= 0` guard in the trigger suppresses alerts in that case.

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.SSL.CERT.HIGH}` | `14` days | Fires HIGH when fewer than this many days remain |
| `{$OPNSENSE.SSL.CERT.WARN}` | `30` days | Fires WARNING when fewer than this many days remain (and above HIGH threshold) |

---

### Network interfaces (LLD)

Interfaces are auto-discovered via `net.if.discovery` (Zabbix built-in). Internal interfaces are excluded by regex: `^(lo[0-9]*|pflog[0-9]*|pfsync[0-9]*|enc[0-9]*)$`.

Per discovered interface `{#IFNAME}`:

| Item | Key | Notes |
|---|---|---|
| Inbound traffic | `net.if.in[{#IFNAME},bytes]` | Bytes/s (Zabbix built-in) |
| Outbound traffic | `net.if.out[{#IFNAME},bytes]` | Bytes/s (Zabbix built-in) |
| Input errors | `opnsense.if.inerrors[{#IFNAME}]` | Cumulative error counter from `netstat` |
| Input drops | `opnsense.if.idrop[{#IFNAME}]` | Cumulative drop counter; NIC ring exhaustion |
| Output errors | `opnsense.if.outerrors[{#IFNAME}]` | Cumulative error counter from `netstat` |

| Trigger | Condition |
|---|---|
| Input errors increased | `change(inerrors) > {$OPNSENSE.IF.ERRORS.WARN}` → **WARNING** |
| Input drops increased | `change(idrop) > {$OPNSENSE.IF.ERRORS.WARN}` → **WARNING** |
| Output errors increased | `change(outerrors) > {$OPNSENSE.IF.ERRORS.WARN}` → **WARNING** |
| Errors or drops increased sharply | `change(inerrors or idrop or outerrors) > {$OPNSENSE.IF.ERRORS.HIGH}` → **HIGH** |

`change()` returns the difference between the current and previous collected values. Because these are cumulative counters, `change()` equals the increase since the last poll.

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.IF.ERRORS.WARN}` | `10` | Per-poll increase in errors/drops before WARNING fires |
| `{$OPNSENSE.IF.ERRORS.HIGH}` | `100` | Per-poll increase before the combined HIGH trigger fires |

---

### Gateways (LLD)

Gateways are auto-discovered via `opnsense.gateway.discovery`, which calls `configctl interface gateways status` and emits a Zabbix LLD JSON payload with `{#GWNAME}` macros.

Per discovered gateway `{#GWNAME}`:

| Item | Key | Units | Notes |
|---|---|---|---|
| Gateway RTT | `opnsense.gateway.delay[{#GWNAME}]` | ms | Round-trip time from DPINGER |
| Gateway packet loss | `opnsense.gateway.loss[{#GWNAME}]` | % | Loss from DPINGER |
| Gateway status | `opnsense.gateway.status[{#GWNAME}]` | string | Status string from OPNsense (e.g. `online`, `down`, `loss`) |

| Trigger | Condition |
|---|---|
| RTT critically high | `last(delay) > {$OPNSENSE.GW.RTT.HIGH}` → **HIGH** |
| RTT high | `last(delay) > {$OPNSENSE.GW.RTT.WARN}` → **WARNING** |
| Packet loss critically high | `last(loss) > {$OPNSENSE.GW.LOSS.HIGH}` → **HIGH** |
| Packet loss high | `last(loss) > {$OPNSENSE.GW.LOSS.WARN}` → **WARNING** |
| Status not healthy | `find(status,,"regexp","(down\|offline\|loss\|delay)") = 1` → **AVERAGE** |
| Gateway flapping | `changecount(status, {$OPNSENSE.GW.FLAP.PERIOD}) >= {$OPNSENSE.GW.FLAP.COUNT}` → **AVERAGE** |

The flap trigger uses `changecount()` to count how many times the status string changed value within the detection window. It fires if the gateway toggled between states (e.g., `online` → `loss` → `online`) at least `FLAP.COUNT` times within `FLAP.PERIOD`, indicating an unstable upstream link rather than a clean outage.

**Macros:**

| Macro | Default | Notes |
|---|---|---|
| `{$OPNSENSE.GW.RTT.WARN}` | `150` ms | RTT warning threshold per gateway |
| `{$OPNSENSE.GW.RTT.HIGH}` | `300` ms | RTT high threshold per gateway |
| `{$OPNSENSE.GW.LOSS.WARN}` | `5` % | Packet loss warning threshold |
| `{$OPNSENSE.GW.LOSS.HIGH}` | `20` % | Packet loss high threshold |
| `{$OPNSENSE.GW.FLAP.COUNT}` | `4` | Number of status changes within the window to classify as flapping |
| `{$OPNSENSE.GW.FLAP.PERIOD}` | `10m` | Detection window for flap counting |
