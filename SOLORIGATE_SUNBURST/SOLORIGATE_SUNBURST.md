# SOLORIGATE


## Attribution

### https://www.recordedfuture.com/solarwinds-attribution/

### https://www.domaintools.com/resources/blog/the-devils-in-the-details-sunburst-attribution

### KAZUAR / TURLA

## Victims

### FireEye

- Breach Investigation

	- https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html

		- Initial discovery 

			- https://news.yahoo.com/hackers-last-year-conducted-a-dry-run-of-solar-winds-breach-215232815.html

	- https://www.fireeye.com/blog/threat-research/2020/12/sunburst-additional-technical-details.html

- Remediation & Hardening

	- https://www.fireeye.com/blog/threat-research/2021/01/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452.html

### Microsoft

- Solorigate Resources Center 🧭 READ FIRST

	- https://msrc-blog.microsoft.com/2020/12/21/december-21st-2020-solorigate-resource-center/

- Breach Investigation

	- https://msrc-blog.microsoft.com/2020/12/31/microsoft-internal-solorigate-investigation-update/

- Advisory

	- https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/

- Guidance & Best Practices

	- https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/

	- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610

	- https://www.microsoft.com/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/

- Detection

	- cf. Hunting / Detection

- Hardening

	- https://www.microsoft.com/security/blog/2020/12/15/ensuring-customers-are-protected-from-solorigate/

	- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/protecting-microsoft-365-from-on-premises-attacks/ba-p/1751754

	- https://www.microsoft.com/security/blog/2021/01/14/increasing-resilience-against-solorigate-and-other-sophisticated-attacks-with-microsoft-defender/

- Policy

	- https://blogs.microsoft.com/on-the-issues/2020/12/17/cyberattacks-cybersecurity-solarwinds-fireeye/

### Unnamed Think Tank

- https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/

### Solarwinds

- https://orangematter.solarwinds.com/2021/01/11/new-findings-from-our-investigation-of-sunburst/

### Malwarebytes

- https://blog.malwarebytes.com/malwarebytes-news/2021/01/malwarebytes-targeted-by-nation-state-actor-implicated-in-solarwinds-breach-evidence-suggests-abuse-of-privileged-access-to-microsoft-office-365-and-azure-environments/

### FidelisSecurity

- https://fidelissecurity.com/threatgeek/data-protection/ongoing-analysis-solarwinds-impact/

### Qualys & Palo Alto Networks 

- https://www.forbes.com/sites/thomasbrewster/2021/01/25/solarwinds-hacks-virginia-regulator-and-5-billion-cybersecurity-firm-confirmed-as-targets/

### Mimecast

- https://www.mimecast.com/blog/important-update-from-mimecast/

- https://www.mimecast.com/blog/important-security-update/

### Google

- https://cloud.google.com/blog/products/identity-security/how-were-helping-reshape-software-supply-chain-ecosystem-securely

### Failed attempts

- CrowdStrike

	- Cf. CrowdStrike Reporting Tool for Azure blog post

### List from Stage2 pDNS

## Hunting / Detection

### Hunting w/ Sentinel

- https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095

### Detection & IR w/ Microsoft 365 Defender

- https://www.microsoft.com/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/

### Microsoft Defender for Identity

- https://techcommunity.microsoft.com/t5/microsoft-security-and/microsoft-defender-for-identity-expands-support-to-ad-fs-servers/ba-p/2058511

### Azure AD Monitor

- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/azure-ad-workbook-to-help-you-assess-solorigate-risk/ba-p/2010718

### Hunting w/ Splunk

- https://www.splunk.com/en_us/blog/security/sunburst-backdoor-detections-in-splunk.html

### Yara

- https://github.com/fireeye/red_team_tool_countermeasures

### ATT&CK

- https://medium.com/mitre-attack/identifying-unc2452-related-techniques-9f7b6c7f3714

- https://www.picussecurity.com/resource/blog/ttps-used-in-the-solarwinds-breach

### Zeek

- https://corelight.blog/2020/12/22/detecting-sunburst-solarigate-activity-in-retrospect-with-zeek-a-practical-example/

### CrowdStrike Reporting Tool for Azure

- https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/

	- https://github.com/CrowdStrike/CRT

### CISA - Sparrow

- https://github.com/cisagov/Sparrow

	- https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/

### Host - C2 match

- https://www.trustedsec.com/blog/risingsun-decoding-sunburst-c2-to-identify-infected-hosts-without-network-telemetry/

### Generic Playbook

- https://www.trustedsec.com/blog/solarwinds-backdoor-sunburst-incident-response-playbook/

## Security Advisory

### https://www.solarwinds.com/securityadvisory

### https://us-cert.cisa.gov/ncas/alerts/aa21-008a

### https://us-cert.cisa.gov/ncas/alerts/aa20-352a

### https://cyber.dhs.gov/ed/21-01/

### https://us-cert.cisa.gov/ncas/analysis-reports/ar21-027a

### https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2451159/nsa-cybersecurity-advisory-malicious-actors-abuse-authentication-mechanisms-to/

### Cf. Victims / Microsoft / Advisory

## Implants

### SUNBURST

- FireEye

	- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

- Microsoft

	- https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/

- Mcafee

	- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/additional-analysis-into-the-sunburst-backdoor/

- CadoSecurity

	- https://www.cadosecurity.com/post/responding-to-solarigate

- SentinelOne

	- https://labs.sentinelone.com/solarwinds-sunburst-backdoor-inside-the-stealthy-apt-campaign/

- Truesec

	- https://blog.truesec.com/2020/12/17/the-solarwinds-orion-sunburst-supply-chain-attack/

- ReversingLabs

	- https://blog.reversinglabs.com/blog/sunburst-the-next-level-of-stealth

- Prevasio

	- https://blog.prevasio.com/2020/12/sunburst-backdoor-deeper-look-into.html

- GuidePoint Security

	- https://www.guidepointsecurity.com/analysis-of-the-solarwinds-supply-chain-attack/

- RedDrip Team, QiAnXin Technology

	- https://twitter.com/reddrip7/status/1341654583886508037

- Netresec

	- https://www.netresec.com/?page=Blog&month=2020-12&post=Reassembling-Victim-Domain-Fragments-from-SUNBURST-DNS

	- https://www.netresec.com/?page=Blog&month=2021-01&post=Robust-Indicators-of-Compromise-for-SUNBURST

- Symantec

	- Cf. teardrop analysis 

	- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-sunburst-sending-data

- Kaspersky

	- https://securelist.com/sunburst-backdoor-kazuar/99981/

	- « do not infect » domain hashes

		- https://pastebin.com/KD4f4w5V

		- https://twitter.com/craiu/status/1341005999273091077

- DNS Infrastructure

	- Kaspersky

		- https://securelist.com/sunburst-connecting-the-dots-in-the-dns-requests/99862/

	- Netresec

		- https://www.netresec.com/?page=Blog&month=2020-12&post=Reassembling-Victim-Domain-Fragments-from-SUNBURST-DNS

		- https://www.netresec.com/?page=Blog&month=2021-01&post=Finding-Targeted-SUNBURST-Victims-with-pDNS

		- https://www.netresec.com/?page=Blog&month=2021-01&post=Twenty-three-SUNBURST-Targets-Identified

		- https://www.netresec.com/?page=Blog&month=2021-02&post=Targeting-Process-for-the-SolarWinds-Backdoor

	- Cloudflare

		- https://blog.cloudflare.com/a-quirk-in-the-sunburst-dga-algorithm/

	- RedDrip Team, QiAnXin Technology

		- https://twitter.com/reddrip7/status/1339168187619790848

	- DomainTools

		- https://www.domaintools.com/resources/blog/continuous-eruption-further-analysis-of-the-solarwinds-supply-incident

			- https://pastebin.com/T0SRGkWq

		- https://www.domaintools.com/resources/blog/change-in-perspective-on-the-utility-of-sunburst-related-network-indicators

	- Prevasio

		- https://blog.prevasio.com/2020/12/sunburst-backdoor-part-ii-dga-list-of.html

		- https://blog.prevasio.com/2020/12/sunburst-backdoor-part-iii-dga-security.html

	- « DGA » Decoder

		- RedDrip Team, QiAnXin Technology

			- https://github.com/RedDrip7/SunBurst_DGA_Decode

		- igosha

			- https://github.com/2igosha/sunburst_dga

	- Symantec

		- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-attacks-stealthy-attackers-attempted-evade-detection

		- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-unique-dga

	- VriesHD

		- https://vrieshd.medium.com/finding-sunburst-victims-and-targets-by-using-passivedns-osint-68f5704a3cdc

- FNV-1a-XOR Hashes

	- https://twitter.com/tychotithonus/status/1340474080831688707?s=21

		- https://docs.google.com/spreadsheets/d/1u0_Df5OMsdzZcTkBDiaAtObbIOkMa5xbeXdKk_k0vWs/htmlview

- Deobfuscated RE

	- https://github.com/ITAYC0HEN/SUNBURST-Cracked/blob/main/OrionImprovementBusinessLayer_modified.cs

### TEARDROP

- Symantec

	- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/sunburst-supply-chain-attack-solarwinds

- CheckPoint

	- https://research.checkpoint.com/2020/sunburst-teardrop-and-the-netsec-new-normal/

		- https://twitter.com/_cpresearch_/status/1339952318717063168

- PaloAltoNetworks

	- https://unit42.paloaltonetworks.com/solarstorm-supply-chain-attack-timeline/

	- IOC

		- https://twitter.com/theenergystory/status/1346096298311741440

- Microsoft

	- https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/

### SUNSPOT

- CrowdStrike

	- https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/

### RAINDROP

- Symantec

	- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-raindrop-malware

- Microsoft

### CobaltStrike

- Microsoft

