**Disclaimer:** *This report is for educational and informational purposes only. The findings presented are based on point-in-time analysis using Open Source Intelligence (OSINT) and passive reconnaissance techniques. No active exploitation or unauthorized access was performed. All Indicators of Compromise (IoCs) are provided "as-is" for defensive and research purposes.*

## Overview
This repository contains the technical artifacts, Indicators of Compromise (IoCs), and defense rules related to the investigation of a shared hosting infrastructure used to deploy multiple financial fraud campaigns (identified with the code 001).

The investigation started from a suspected HYIP (High-Yield Investment Program) domain (`netcapitalglobe[.]com`) and, through infrastructure pivoting, uncovered a hidden, active fraudulent Credit Union portal (`heritagecommunitycredit[.]com`) hosted on the same IP.

## Key Findings and Clustering
* **Primary IP:** `199.188.200.89` (Namecheap Shared Hosting)
* **Target A (HYIP Scam):** `netcapitalglobe[.]com` uses a Bootstrap/jQuery stack and features an anomalous Yandex telemetry tracker alongside a live chat widget for manual social engineering.
* **Target B (Credential Harvesting):** `heritagecommunitycredit[.]com` targets retail banking victims using a completely different framework (`Livewire/Alpine.js`), demonstrating the Threat Actor's active management of diverse Phishing Kits on a single low-cost node.

## MITRE ATT&CK Mapping
* **TA0042 - Resource Development**
  * **T1583.003 (Acquire Infrastructure: Virtual Private Server):** Use of low-cost shared hosting to centralize malicious domains.
  * **T1587.004 (Develop Capabilities: Phishing Material):** Deployment of diverse phishing kits for different victim demographics.
* **TA0001 - Initial Access**
  * **T1566.002 (Phishing: Spearphishing Link):** Driving traffic to fraudulent landing pages for credential harvesting.

## Repository Contents
* `001-IoCs.csv`: The list of malicious IP and domains.
* `NCG_HCC_PhishingKit.yara`: A YARA rule designed to detect the HTML source code of the Credit Union phishing kit.
