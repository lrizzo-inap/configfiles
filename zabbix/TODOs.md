## TODOS

### 1. Missing enterprise check: config synchronization / HA split-brain signals
Add HA health checks for config sync and pfsync status

### 2. Missing enterprise check: gateway reachability vs service reachability (DNS/NTP upstream)
Current gateway metrics are link-quality focused; they don’t verify critical control-plane dependencies (DNS recursion and time sync), which often fail before full gateway-down events.
Add DNS and NTP service health checks

### 3. Missing enterprise check: firmware/update posture and reboot-required state
For enterprise operations and security compliance, patch lag is often a top KPI. The template currently has no update/firmware posture indicators.
Monitor firmware update availability and pending reboot state

### 4. Missing enterprise check: configuration backup freshness
A firewall with stale/no recent backup is a major operational risk, especially in regulated environments.

### 5. No explicit nodata()/collection-failure guardrails for critical custom checks
Many critical custom checks (PF counters, route default, VPN processes, gateway metrics) rely on UserParameters. If helper execution breaks (permissions/path/plugin drift), checks may go stale without a dedicated “data missing” trigger per critical metric family, creating false confidence while monitoring is partially blind.

### 6. DHCP monitoring is tied to ISC DHCPv4 lease file only
dhcp_leases() hardcodes /var/dhcpd/var/db/dhcpd.leases. That can miss environments using other DHCP backends/configurations (e.g., Kea or DHCPv6-only scenarios), reducing functional fit for broader monitoring needs.
