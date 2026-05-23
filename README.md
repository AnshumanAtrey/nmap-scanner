# nmap — Network Port Scanner & Service Detection

📦 **Open source · MIT:** [github.com/AnshumanAtrey/nmap-scanner](https://github.com/AnshumanAtrey/nmap-scanner)


Cloud-hosted [nmap](https://nmap.org) (the industry-standard network scanner by Fyodor / Insecure.Com). Run port scans, service/version detection, OS fingerprinting (limited), and the full library of [Nmap Scripting Engine (NSE)](https://nmap.org/book/nse.html) scripts against any target you're authorized to scan.

Results are streamed into the Apify dataset as **structured records** — one row per open port, one per host, one per NSE script result, plus a summary. The raw nmap XML is also saved to the key-value store for downstream tooling.

## Authorization disclaimer

You **must** be authorized to scan the target. Port scanning unowned hosts without permission may violate the [Computer Fraud and Abuse Act](https://en.wikipedia.org/wiki/Computer_Fraud_and_Abuse_Act) (US) and equivalent laws elsewhere. Use this actor for: your own infrastructure, bug bounty targets within scope, lawful penetration tests, security research, and the official permitted target `scanme.nmap.org`.

## Quick start

```json
{
  "target": "scanme.nmap.org",
  "scanProfile": "standard"
}
```

This scans the top 1000 TCP ports with service/version detection. Takes ~30-60 seconds.

## Apify sandbox constraints

Apify containers run **unprivileged** — no root, no `CAP_NET_RAW`. This means:

| Scan type | Available? | Reason |
|---|---|---|
| TCP Connect (`-sT`) | ✅ Yes (default) | Standard sockets work fine |
| TCP SYN (`-sS`) | ❌ No | Requires raw sockets / root |
| UDP (`-sU`) | ❌ No | Requires raw sockets / root |
| Service detection (`-sV`) | ✅ Yes | Works over TCP connect |
| Default scripts (`-sC`) | ✅ Yes | Most NSE scripts work unprivileged |
| Vuln scripts (`--script vuln`) | ✅ Yes | Same as above |
| OS detection (`-O`) | ❌ No | Requires raw sockets / root |

If you need SYN/UDP/OS scans, run nmap locally with `sudo` — this actor is for the unprivileged scan types that cover ~80% of real-world use cases.

## Scan profiles

| Profile | What it runs | Use when |
|---|---|---|
| `quick` | `--top-ports 100` | Fast triage |
| `standard` (default) | `--top-ports 1000 -sV` | Most use cases |
| `thorough` | `-p- -sV -sC` (all 65535 ports + scripts) | Full asset inventory |
| `web` | HTTP ports + `http-*` NSE scripts | Web app recon |
| `vuln` | `-sV --script vuln` | Vulnerability sweep |
| `custom` | Use `ports`/`customScripts`/`customArgs` | Power users |

## Output structure

Each scan produces multiple dataset records with a `recordType` discriminator:

| recordType | Fields | When |
|---|---|---|
| `port` | `host`, `address`, `port`, `protocol`, `state`, `service`, `product`, `version` | One per port scanned |
| `host` | `host`, `address`, `hostname`, `status`, `openPorts` | One per scanned host |
| `script` | `host`, `port`, `scriptId`, `output` | One per NSE script result |
| `summary` | `hostsUp`, `openPortsTotal`, `scanDuration`, `cmd`, ... | Always last record |

Filter by `recordType` in the Apify Console table view to see one category at a time.

The raw nmap XML is saved to the key-value store as `nmap-output.xml` — drop into your own XML parser, Metasploit's `db_import`, or any nmap-aware tool.

## Pricing

$0.005 per dataset record produced. A typical `standard` scan against a host with ~20 open services produces ~22 records ($0.11).

## FAQ

### Why can't I run SYN or UDP scans?
Apify containers run unprivileged (no root, no `CAP_NET_RAW`). SYN/UDP/OS-detection all need raw sockets which require root. The TCP-connect path covers ~80% of real-world use cases — for the other 20%, run nmap locally with `sudo`.

### Can I scan my home network?
Only if your home network is reachable from the public internet — nmap on Apify is a cloud scanner, not a LAN scanner. For internal scans, use the [Apify Proxy](https://docs.apify.com/platform/proxy) to route through a residential IP, or run nmap on a private box.

### What's the difference between `standard` and `thorough`?
`standard` scans the top 1000 TCP ports with version detection — completes in ~1 minute and catches 95% of services. `thorough` hits all 65535 ports plus default scripts — takes 15-45 minutes per host. Use thorough only when you genuinely need a complete inventory.

### Will Apify block my port scans?
Apify allows outbound port scans, but the **target** may block you. Apify Residential Proxy rotates IPs to mitigate this. Some firewalls also fingerprint nmap traffic specifically — to bypass, use `customArgs` with `--scan-delay 1s -T2` (slower but stealthier).

### Can I import the XML into Metasploit / Greenbone / Nessus?
Yes — the raw nmap XML is saved to the key-value store as `nmap-output.xml`. Download it and `db_import nmap-output.xml` in `msfconsole`, or import into Greenbone/Nessus directly.

## Pairs nicely with

Bundle for full attack-surface recon:

- **[theHarvester](https://apify.com/anshumanatrey/theharvester-osint)** — Discover subdomains first, then port-scan each one with nmap
- **[NetIntel](https://apify.com/anshumanatrey/netintel)** — WHOIS, DNS, GeoIP, SSL context for every IP nmap finds
- **[Bug Bounty Finder](https://apify.com/anshumanatrey/bug-bounty-finder)** — Confirm the target has a bounty program before sending vuln reports
- **[Holehe Email OSINT](https://apify.com/anshumanatrey/holehe-email-osint)** — OSINT the email addresses on services nmap discovers
- **[Social Analyzer](https://apify.com/anshumanatrey/social-analyzer)** — Find usernames of admins/developers exposed in service banners
- **[Zomato Restaurant Scraper](https://apify.com/anshumanatrey/zomato-restaurant-scraper)** — Restaurant lead lists (separate B2B use case)

## Credits

Built on top of [nmap](https://nmap.org) by Gordon Lyon (Fyodor). nmap is licensed under the Nmap Public Source License Version 0.95 — please review before commercial use.
