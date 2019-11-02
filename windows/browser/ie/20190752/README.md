# CVE-2019-0752
* Date : April 2019
* Credit : Simon Zuckerbraun

## Description
**Microsoft Internet Explorer Windows 10 1809 17763.316 - Scripting Engine Memory Corruption**

A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer. The vulnerability could corrupt memory in such a way that an attacker could execute arbitrary code in the context of the current user. An attacker who successfully exploited the vulnerability could gain the same user rights as the current user. If the current user is logged on with administrative user rights, an attacker who successfully exploited the vulnerability could take control of an affected system. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.

In a web-based attack scenario, an attacker could host a specially crafted website that is designed to exploit the vulnerability through Internet Explorer and then convince a user to view the website. An attacker could also embed an ActiveX control marked "safe for initialization" in an application or Microsoft Office document that hosts the IE rendering engine. The attacker could also take advantage of compromised websites and websites that accept or host user-provided content or advertisements. These websites could contain specially crafted content that could exploit the vulnerability.

The security update addresses the vulnerability by modifying how the scripting engine handles objects in memory.

## Vulnerable App

Microsoft Internet Explorer Windows 10 1809 17763.316

## Reference
[Microsoft Security Update Guide](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0752)
[MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0752)
[Exploit Database](https://www.exploit-db.com/exploits/46928)