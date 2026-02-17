# fortivpnchecker

Automated VPN security monitoring that queries connecting IPs against AbuseIPDB threat intelligence and automatically blocks malicious sources at the FortiGate firewall.
What it does
Monitors FortiGate alert emails via Gmail for VPN connection attempts and administrator logins. For each connection:
	1.	Extracts the source IP address from the alert email
	2.	Queries AbuseIPDB API for threat intelligence on that IP
	3.	If abuse confidence score exceeds threshold, automatically creates a firewall block rule
	4.	Maintains PYTHONVPN_GROUP address group with all blocked IPs
	5.	Logs all actions with timestamps for audit trail
This creates real-time threat protection — malicious IPs are blocked immediately upon first connection attempt, before they can probe or attack internal systems.
Setup
Configuration:
Edit the config section at the top of the script:
	∙	HOST: FortiGate firewall IP address
	∙	PORT: Management port
	∙	VDOM: VDOM name
	∙	check_duration: Scan interval in seconds (default: 5)
	∙	AbuseIPDB API key (line with 'Key': '########')
Gmail API Setup:
Requires Gmail API credentials (credentials.json) with modify permissions to read FortiGate alert emails.
Initial Setup:
	1.	Run the program to create PYTHONVPN_GROUP (includes temporary APIPA placeholder since FortiGate requires non-empty groups)
	2.	Add PYTHONVPN_GROUP to your firewall block policies to activate blocking
Note: This solution was retired after migrating from SSL-VPN to IPsec VPN with FortiClient EMS Cloud and SAML-based MFA, which addressed the underlying security concerns through infrastructure improvements rather than reactive blocking.
