# SOC Automation Toolkit

A Python-based automation toolkit for Tier 1/2 SOC analyst workflows - built to reduce manual threat intel lookup time during alert triage.

## Overview

SOC analysts spend a large portion of their day manually checking IPs, domains, URLs, and file hashes against threat intelligence sources during alert triage and incident investigation. This toolkit automates that lookup-and-score process, mirroring real analyst workflow.

**Current module: IOC Triage Tool**
Takes any indicator of compromise (IOC) and returns a clean verdict - MALICIOUS, SUSPICIOUS, or CLEAN - by cross-referencing two independent threat intelligence sources.

## Features

- **Automatic IOC type detection** - identifies IP addresses, domains, URLs, and file hashes (MD5/SHA1/SHA256) from raw input using pattern matching
- **Multi-source threat intelligence** - queries both [VirusTotal](https://www.virustotal.com) (70+ antivirus engine consensus) and [AbuseIPDB](https://www.abuseipdb.com) (community abuse reports) for IP addresses
- **Combined verdict scoring** - reconciles disagreements between sources rather than trusting a single feed, catching cases where one source alone would miss a threat
- **Clean CLI reporting** - readable terminal output designed for fast analyst triage, not raw JSON dumps
- **Graceful error handling** - rate limiting, network failures, and malformed input are handled without crashing

## Tech Stack

- **Language:** Python 3
- **APIs:** VirusTotal API v3, AbuseIPDB API v2
- **Libraries:** `requests`, `python-dotenv`, `argparse`

## Installation

```bash
git clone https://github.com/mmanish7634/soc-automation-toolkit.git
cd soc-automation-toolkit
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your own free API keys:
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register

```
VT_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

## Usage

```bash
# Check an IP address (queries both VirusTotal and AbuseIPDB)
python main.py --ioc 8.8.8.8

# Check a domain
python main.py --ioc example.com

# Check a URL
python main.py --ioc "https://example.com/page"

# Check a file hash (MD5/SHA1/SHA256)
python main.py --ioc 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### Example Output

```
==================================================
  IOC TRIAGE REPORT
==================================================
  Indicator : 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  Type      : hash
  Verdict   : MALICIOUS
  Reason    : 62 security vendors flagged this as malicious
--------------------------------------------------
  VirusTotal malicious votes : 62
  VirusTotal suspicious votes: 0
  File type : Powershell
  Known names: ['eicar.com-25996', 'eicar.com-21631', 'xekar007.exe']
==================================================
```

## Architecture

```
soc-automation-toolkit/
├── main.py                      # CLI entry point
├── ioc_triage/
│   ├── ioc_utils.py              # IOC type detection (regex-based)
│   ├── vt_client.py              # VirusTotal API integration
│   ├── abuseipdb_client.py       # AbuseIPDB API integration
│   └── verdict.py                # Verdict scoring logic
├── shared/
│   └── config.py                 # Centralized API key loading
├── .env.example                  # Template for API keys (never commit real .env)
└── requirements.txt
```

## Design Decisions

- **Why two threat intel sources instead of one?** No single feed is complete. Testing showed cases where VirusTotal alone reported an IP as clean, but AbuseIPDB flagged it based on recent abuse reports - the combined verdict logic catches these single-source blind spots.
- **Why separate API client files per source?** If an API changes its endpoint structure or response format, only one file needs updating - the rest of the codebase doesn't need to know how the data was fetched.
- **Why explicit status code handling instead of just `response.json()`?** Real-world API calls fail - rate limits, network timeouts, unknown indicators. A tool used in a SOC environment needs to degrade gracefully, not crash.

## Roadmap

- [ ] Log Parser + Enricher module - parse raw logs and auto-enrich suspicious IPs
- [ ] Phishing Email Analyzer module - SPF/DKIM/DMARC validation, header forensics
- [ ] Batch IOC processing (CSV input/output)
- [ ] Simple web dashboard (Streamlit)

## Author

Manish - B.Tech Cybersecurity, Lloyd Institute of Engineering & Technology
[GitHub](https://github.com/M-Kay7634/Soc-Automation-Toolkit) | [LinkedIn](www.linkedin.com/in/mmanish7634)