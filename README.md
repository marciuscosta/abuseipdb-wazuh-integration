# abuseipdb-wazuh-integration
Integration of AbuseIPDB in Wazuh with a local cache database and the possibility of using more than one API key in the same integration.


Full article about this integration, you can see [here](https://marcius.pro/index.php/2024/02/27/integrando-o-abuseipdb-ao-wazuh-com-cache-local/)

### Installation
1. Make download of the necessary files into your Wazuh Manager node master
```
sudo wget https://raw.githubusercontent.com/marciuscosta/abuseipdb-wazuh-integration/main/custom-abuseipdb.py -O /var/ossec/integrations/custom-abuseipdb.py
sudo wget https://raw.githubusercontent.com/marciuscosta/abuseipdb-wazuh-integration/main/custom-abuseipdb -O /var/ossec/integrations/custom-abuseipdb
sudo wget https://raw.githubusercontent.com/marciuscosta/abuseipdb-wazuh-integration/main/1600-abuseipdb-integration_decoders.xml -O /var/ossec/etc/decoders/1600-abuseipdb-integration_decoders.xml
```
2. Adjust permissions
```
sudo chmod 750 /var/ossec/integrations/custom-abuseipdb
sudo chown root:wazuh /var/ossec/integrations/custom-abuseipdb
sudo chmod 750 /var/ossec/integrations/custom-abuseipdb.py
sudo chown root:wazuh /var/ossec/integrations/custom-abuseipdb.py
sudo chmod 660 /var/ossec/etc/decoders/1600-abuseipdb-integration_decoders.xml && sudo chown wazuh: /var/ossec/etc/decoders/1600-abuseipdb-integration_decoders.xml
```
3. Create integration in your ossec.conf adding the code below between "<ossec_config>" and "</ossec_config>"
```
<integration>
    <name>custom-abuseipdb.py</name>
    <group>abuseipdb_integration,</group> <!-- this is an just example of use, you can use any rules groups that you want -->
    <alert_format>json</alert_format>
</integration>

<localfile>
    <location>/var/ossec/logs/integrations.log</location>
    <log_format>syslog</log_format>
</localfile>
```
4. Restart your Wazuh Manager
```
sudo /var/ossec/bin/wazuh-control restart
```
5. Add your first API key into local cache database used by this script.
```
sudo /var/ossec/integrations/custom-abuseipdb apikey add PUT_YOUR_API_KEY_HERE
```
You can add more than one API key, and this script will use all the API keys one at a time until you exceed the daily limit, where it will use the next API key saved in the local cache database

6. If you want use blacklist of AbuseIPDB in this integration, you need enable it in custom-abuseipdb.py file, change the variable "blacklist_enabled" to "True" (with T in uppercase)

7. To download manually blacklist, make this
```
sudo /var/ossec/integrations/custom-abuseipdb blacklist
```

### Others commands

To list all API Keys saved in local cache database:
```
sudo /var/ossec/integrations/custom-abuseipdb apikey list
```

To remove an API key from local cache database:
```
sudo /var/ossec/integrations/custom-abuseipdb apikey remove YOUR_API_KEY_HERE
```
