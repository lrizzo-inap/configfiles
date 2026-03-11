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
