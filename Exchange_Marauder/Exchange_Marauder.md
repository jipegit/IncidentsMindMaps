# Exchange Marauder


## Tools

### Vulnerability Scanners

- Triage

	- https://github.com/dpaulson45/HealthChecker#download

- Microsoft

	- https://github.com/GossiTheDog/scanning/blob/main/http-vuln-exchange.nse

	- https://github.com/microsoft/CSS-Exchange/blob/main/Security/http-vuln-cve2021-26855.nse

### Detection / Hunting

- Rapid7

	- https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/

- CrowdStrike

	- https://www.crowdstrike.com/blog/falcon-complete-stops-microsoft-exchange-server-zero-day-exploits/

- FireEye

	- https://www.fireeye.com/blog/threat-research/2021/03/detection-response-to-exploitation-of-microsoft-exchange-zero-day-vulnerabilities.html

- Microsoft

	- 365-Defender-Hunting-Queries

		- https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/exchange-iis-worker-dropping-webshell.md

	- IOC Feed

		- https://github.com/Azure/Azure-Sentinel/tree/master/Sample%20Data/Feeds

	- https://github.com/microsoft/CSS-Exchange/blob/main/Security/src/Test-ProxyLogon.ps1

- CERT-LV

	- https://github.com/cert-lv/exchange_webshell_detection/blob/main/detect_webshells.ps1

- Neo23x0

	- https://github.com/Neo23x0/signature-base/blob/master/yara/apt_hafnium.yar#L172

- Unit221b

	- https://checkmyowa.unit221b.com/

- Trustedsec

	- https://github.com/trustedsec/defensive-scripts

### Mitigation

- Microsoft

	- https://github.com/microsoft/CSS-Exchange/blob/main/Security/src/ExchangeMitigations.ps1

	- https://msrc-blog.microsoft.com/2021/03/15/one-click-microsoft-exchange-on-premises-mitigation-tool-march-2021/

### Remediation

- Microsoft

	- https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download

## Attribution

### Microsoft

- https://blogs.microsoft.com/on-the-issues/2021/03/02/new-nation-state-cyberattacks/

	- HAFNIUM

## Implants

### ChinaChopper

- https://twitter.com/jhencinski/status/1367225483407089665

- https://twitter.com/noottrak/status/1367276764741963780

## Emulation

### Praetorian

- https://www.praetorian.com/blog/reproducing-proxylogon-exploit/

## Exploits

### CVE-2021-26855

- jsdryan

	- https://github.com/jsdryan/CVE-2021-26855/blob/main/CVE-2021-26855.go

- Rapid7

	- https://github.com/rapid7/metasploit-framework/blob/f7fe97a1458df7b45562013af3a70f5bd0a8cf7b/modules/auxiliary/gather/exchange_proxylogon_collector.rb

### Information Gathering

- https://github.com/sophoslabs/metasploit_gather_exchange

### CVE-2021-26855 & CVE-2021-27065

- https://github.com/hausec/ProxyLogon

- https://gitlab.com/gvillegas/ohwaa/

## Security Advisories

### Microsoft

- https://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/

	- CVE-2021-26855  
	  CVE-2021-26857  
	  CVE-2021-26858  
	  CVE-2021-27065

- https://msrc-blog.microsoft.com/2021/03/05/microsoft-exchange-server-vulnerabilities-mitigations-march-2021/

- https://techcommunity.microsoft.com/t5/exchange-team-blog/released-march-2021-exchange-server-security-updates/ba-p/2175901

### CISA

- https://us-cert.cisa.gov/ncas/alerts/aa20-352a

### https://proxylogon.com

- CVE-2021-26855 

- CVE-2021-27065

## Incidents

### Volexity

- https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/

### Microsoft

- https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

	- TTP

		- Command & Control

			- https://github.com/cobbr/Covenant

		- Exfiltration

			- MEGA

		- Execution

			- Nishang

				- https://github.com/samratashok/nishang

### Truesec

- https://blog.truesec.com/2021/03/07/exchange-zero-day-proxylogon-and-hafnium/

### RedCanary

- https://redcanary.com/blog/microsoft-exchange-attacks/

### PaloAlto Unit42

- https://unit42.paloaltonetworks.com/china-chopper-webshell/

### DomainTools

- https://www.domaintools.com/resources/blog/examining-exchange-exploitation-and-its-lessons-for-defenders

### ESET

- https://www.welivesecurity.com/2021/03/10/exchange-servers-under-siege-10-apt-groups/

