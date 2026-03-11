1) Install Zabbix Agent Plugin in OPNsense
2) Go to Services -> ZAbbix Agent -> Settings
3) in Main settings:
   a) Set hostname identical to the one on zabbix
   b) set FW Public IP as listen IP
   c) Set ZAbbix Proxy IP as Zabbix Server
   d) enable sudo root permissions
   e) APPLY
4) in zabbix Features
   a) Enable Active Checks
   b) set Zabbix Proxy IP as Active Check Server
   c) Enable PSK based encryption
   d) Set PSK identity the same as the one on teh Zabbix Server
   e) Set PSK identicval to the one on teh Zabbix Server
5) In Advanced -> User Parameters
   a) Add all of the UserParameters present in the UserParameter-gui.conf file (User Parameter key and command are separated by a coma in that file, as it is grabbed directly from the zabbix agent config file)
   b) Apply (bottom pf the page) and restart Zabbix Agent (Top right of the page)
6) Ensure that opnsense.custom.conf is in /usr/local/etc/zabbix_agentd.conf.d/
7) Restart zabbix agent once more and admire the data fields being populated 
