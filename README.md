# Blue Team Setup
This repository contains configuration files and instructions for setting up a Blue Team security environment using Wazuh, Suricata, VirusTotal integration, and system hardening techniques. 
## Wazuh

### Wazuh Installation & Configuration

Wazuh installation instructions are available at [Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html).

```bash
# Agent
#
# Configuraiton File
/var/ossec/etc/ossec.conf

# Wazuh Manager 
# 
# Custom Rules
/var/ossec/etc/rules/local_rules.xml
# Custom Decoders
/var/ossec/etc/decoders/local_decoder.xml
# Config File 
/var/ossec/etc/ossec.conf
# Default Rules 
/var/ossec/ruleset/rules/
```

Active response can be configured in the wazuh-manager configuration file. 

```bash
# Wazuh Server Config 
# /var/ossec/etc/ossec.conf

<active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100100</rules_id>
    <timeout>60</timeout>
</active-response>
```

My used configuration : 
- [ossec.conf (manager)](./config/ossec-manager.conf)
- [ossec.conf (agent)](./config/ossec-agent.conf)
- [local_rules.xml](./config/local_rules.xml)
- [local_decoder.xml](./config/local_decoder.xml)

### Suricata Installation

Suricata installation instructions are available at [Suricata Installation Guide](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html).


```bash
# Settings location
/etc/suricata/suricata.yaml
# Rules Directory  
/etc/suricata/rules/

# Rule Format 
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET";
    http.uri; content:"rule";
    fast_pattern; 
    classtype:bad-unknown; 
    sid:123; 
    rev:1;
)
```

```bash
# /var/ossec/etc/ossec.conf
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
```
My configuration:
- [suricata.yaml](./config/suricata.yaml)
### VirusTotal Configuration

Virus configuration instructions are available at [Virus Configuration Guide](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html).

It is required to possess a VirusTotal API key. You can obtain one by signing up at [VirusTotal](https://www.virustotal.com/).

```bash
# Wazuh Server Config 
# /var/ossec/etc/ossec.conf
<integration>
  <name>virustotal</name>
  <api_key>API_KEY</api_key> <!-- Replace with your VirusTotal API key -->
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>

# Add Directory Monitoring
<syscheck>
  <directories check_all="yes" realtime="yes">/media/user/software</directories>
</syscheck>
```


## System Hardening

### [Lynis](https://cisofy.com/lynis/)
Lynis is a battle-tested security tool for systems running Linux, macOS, or Unix-based operating system. It performs an extensive health scan of your systems to support system hardening and compliance testing.

<img src="https://cisofy.com/static/lynis-screenshot.png" alt="Lynis Logo">

### Alternative Checks
```bash
# Check for scheduled tasks that might re-execute malware.
ls -la /etc/cron.* /etc/crontab
cat /etc/crontab

# List services enabled on startup. Look for names that mimic real services (e.g., 'systemd-helper').
systemctl list-unit-files --type=service | grep enabled

# Inspect keys to ensure only known keys are present. 
grep -r "ssh-rsa" /home/*/.ssh/authorized_keys
grep -r "ssh-rsa" /root/.ssh/authorized_keys

# Check /etc/resolv.conf and host
cat /etc/resolv.conf
cat /etc/hosts
```

### Firewall Rules
```bash
# Drop Existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

# Set Default Policies to DROP (Whitelist mode)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Output 
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80  -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s X.X.X.X -m conntrack --ctstate NEW -j ACCEPT

# Loopback Enabled 
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Wazuh Ip white list 
iptables -A INPUT -p tcp --dport 1514 -j ACCEPT # Agent connection
iptables -A INPUT -p tcp --dport 1515 -j ACCEPT # Enrollment
iptables -A INPUT -p tcp --dport 55000 -j ACCEPT # API (if Manager)

# Drop Invalid Packet to prevent scan
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# TCP scans
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP   # NULL scan
iptables -A INPUT -p tcp --tcp-flags ALL ALL  -j DROP   # XMAS scan
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Block ICMP to prevent Scan 
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT


# Log of block rules
iptables -A INPUT  -m limit --limit 5/min --limit-burst 10 \
  -j LOG --log-prefix "[IPTABLES-INPUT-DROP] " --log-level 4
iptables -A OUTPUT -m limit --limit 5/min --limit-burst 10 \
  -j LOG --log-prefix "[IPTABLES-OUTPUT-DROP] " --log-level 4
```

## Playbooks

**Future Work**:
- [ ] Create Ansible playbook to automate the hardening and setup process.
- [ ] Playbook for BruteForce Attack.
- [ ] Playbook for Malware Detection and Quarantine.
- [ ] Playbook for Network Intrusion Detection.
