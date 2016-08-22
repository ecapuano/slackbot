# A Virustotal integration for Slack

## Intro
A simple Slack integration that allows you to query Virustotal from Slack.

VERY beta product and I am not a Python expert by any means, I just build things to make my life easier. If you see problems / areas to improve, feel free to contribute.

## Pre-reqs
All you really need for this to work is a free Virustotal API key. Read more here: https://www.virustotal.com/en/documentation/public-api/

## Usage
As of now, it only supports passing a URL or a file hash like so;
`/virustotal http://malware.ru` 
or 
`/virustotal 99017f6eebbac24f351415dd410d522d`

Results for a hash query are returned in the following format:
```
Scan Results for:     <slack username>
MD5:     99017f6eebbac24f351415dd410d522d
Detected Malicious by:     51/56
Sophos:     Troj/VBHost-A
Kaspersky:     Trojan.Win32.Hosts2.gen
ESET-NOD32:     a variant of Win32/Qhost.Banker.BP
AegisLab:     Troj.W32.VB.acgy!c
AVG:     VBCrypt.AWJ
Ad-Aware:     Generic.Malware.V!w.7232B058
Avast:     Win32:VB-ZOF [Spy]
BitDefender:     Generic.Malware.V!w.7232B058
F-Secure:     Generic.Malware.V!w.7232B058
Fortinet:     W32/Vb.HT!tr
McAfee:     RDN/Generic Qhost
Microsoft:     Trojan:Win32/Comame!gmb
Symantec:     Trojan.KillAV
Scanned on:     2016-08-21 20:09:47
https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1471810187/
```
URL query response:
```
Results for Site:     http://malware.ru/
Determined Malicious by:     1/65
PhishLabs:     unrated site
Sophos:     unrated site
Kaspersky:     phishing site
Sophos:     unrated site
Scanned on:     2015-10-25 07:48:27
https://www.virustotal.com/url/a1e96fb159e1eb82c4cbb8ca342a2652ce97c16f8b214d792f9ca7262224240c/analysis/1445759307/
```


You can mess with the hardcoded parser in order to show the vendors that you prefer, but either way you still get a "total count" ie. `Detected Malicious by:     51/56`
