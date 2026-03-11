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

### 5. Configure User Parameters

Navigate to:

Advanced → User Parameters

Then:

1. Add all **UserParameter entries** contained in the file: **UserParameter-gui.conf**

2. In that file:
- The **key** and **command** are separated by a comma.
- This format is taken directly from the Zabbix agent configuration.

3. Click **Apply** (bottom of the page).

4. Restart **Zabbix Agent** using the button in the **top-right corner**.

---

### 6. Verify Custom Parameters File

Ensure the following file exists:


**/usr/local/etc/zabbix_agentd.conf.d/opnsense.custom.conf**


This file contains additional `UserParameter` entries that use wildcard keys (`[*]`).

---

### 7. Verify OPNsense Zabbix Helper Script

Ensure the following file exists:


**/usr/local/bin/opnsense-zabbix.sh**


and that it is executable (if not run `chmod 755 /usr/local/bin/opnsense-zabbix.sh`)

This file is an helper script used by the Zabbix Agent to gather some of the data from OPNsense.

---

### 8. Restart the Agent

Restart the Zabbix agent once more:


service zabbix_agentd restart


---

### 9. Verify Monitoring

After the restart, verify in Zabbix that the **data fields are being populated correctly**.
