# SOLORIGATE


## Attribution

### https://www.recordedfuture.com/solarwinds-attribution/

### KAZUAR / TURLA

## Victims

### FireEye

- https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html

	- Initial discovery 

		- https://news.yahoo.com/hackers-last-year-conducted-a-dry-run-of-solar-winds-breach-215232815.html

- https://www.fireeye.com/blog/threat-research/2020/12/sunburst-additional-technical-details.html

### Microsoft

- 🧭 READ FIRST: https://msrc-blog.microsoft.com/2020/12/21/december-21st-2020-solorigate-resource-center/

	- Breach impact

		- https://msrc-blog.microsoft.com/2020/12/31/microsoft-internal-solorigate-investigation-update/

- https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/

	- https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/

	- https://blogs.microsoft.com/on-the-issues/2020/12/17/cyberattacks-cybersecurity-solarwinds-fireeye/

- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610

- Hardening

	- https://www.microsoft.com/security/blog/2020/12/15/ensuring-customers-are-protected-from-solorigate/

	- https://techcommunity.microsoft.com/t5/azure-active-directory-identity/protecting-microsoft-365-from-on-premises-attacks/ba-p/1751754

- IR

	- https://www.microsoft.com/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/

### Unnamed Think Tank

- https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/

## Hunting / Detection

### Hunting w/ Sentinel

- https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095

### Detection & IR w/ Microsoft 365 Defender

- https://www.microsoft.com/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/

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

- https://github.com/CrowdStrike/CRT

### CISA - Sparrow

- https://github.com/cisagov/Sparrow

	- https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/

## Security Avisory

### https://www.solarwinds.com/securityadvisory

### https://us-cert.cisa.gov/ncas/alerts/aa20-352a

### https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2451159/nsa-cybersecurity-advisory-malicious-actors-abuse-authentication-mechanisms-to/

## Implants

### SUNBURST

- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

- https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/

- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/additional-analysis-into-the-sunburst-backdoor/

- https://www.cadosecurity.com/post/responding-to-solarigate

- https://labs.sentinelone.com/solarwinds-sunburst-backdoor-inside-the-stealthy-apt-campaign/

- https://blog.truesec.com/2020/12/17/the-solarwinds-orion-sunburst-supply-chain-attack/

- https://blog.reversinglabs.com/blog/sunburst-the-next-level-of-stealth

- https://blog.prevasio.com/2020/12/sunburst-backdoor-deeper-look-into.html

- https://www.guidepointsecurity.com/analysis-of-the-solarwinds-supply-chain-attack/

- https://twitter.com/reddrip7/status/1341654583886508037?s=21

- https://www.netresec.com/?page=Blog&month=2020-12&post=Reassembling-Victim-Domain-Fragments-from-SUNBURST-DNS

- « do not infect » domain hashes

	- https://pastebin.com/KD4f4w5V

	- https://twitter.com/craiu/status/1341005999273091077

- DNS Infrastructure

	- https://securelist.com/sunburst-connecting-the-dots-in-the-dns-requests/99862/

	- https://www.netresec.com/?page=Blog&month=2020-12&post=Reassembling-Victim-Domain-Fragments-from-SUNBURST-DNS

	- https://blog.cloudflare.com/a-quirk-in-the-sunburst-dga-algorithm/

	- https://twitter.com/reddrip7/status/1339168187619790848

	- https://www.domaintools.com/resources/blog/continuous-eruption-further-analysis-of-the-solarwinds-supply-incident

		- https://pastebin.com/T0SRGkWq

	- https://blog.prevasio.com/2020/12/sunburst-backdoor-part-ii-dga-list-of.html

	- https://blog.prevasio.com/2020/12/sunburst-backdoor-part-iii-dga-security.html

	- DGA Decoder

		- https://github.com/2igosha/sunburst_dga

		- https://github.com/RedDrip7/SunBurst_DGA_Decode

	- https://www.netresec.com/?page=Blog&month=2021-01&post=Finding-Targeted-SUNBURST-Victims-with-pDNS

- Hashes

	- https://twitter.com/tychotithonus/status/1340474080831688707?s=21

		- https://docs.google.com/spreadsheets/d/1u0_Df5OMsdzZcTkBDiaAtObbIOkMa5xbeXdKk_k0vWs/htmlview

- Deobfuscated RE

	- https://github.com/ITAYC0HEN/SUNBURST-Cracked/blob/main/OrionImprovementBusinessLayer_modified.cs

- https://securelist.com/sunburst-backdoor-kazuar/99981/

### TEARDROP

- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/sunburst-supply-chain-attack-solarwinds

- https://research.checkpoint.com/2020/sunburst-teardrop-and-the-netsec-new-normal/

	- https://twitter.com/_cpresearch_/status/1339952318717063168

- https://unit42.paloaltonetworks.com/solarstorm-supply-chain-attack-timeline/

- IOC

	- https://twitter.com/theenergystory/status/1346096298311741440?s=21

