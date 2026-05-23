"""
nmap Apify Actor — wraps the official nmap CLI for cloud-hosted network scanning.

Apify constraint: containers run unprivileged. Only TCP connect scans (-sT) work.
SYN, UDP, OS-detection scans require root and are not available.
"""
import asyncio
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from apify import Actor


OUTPUT_XML = '/tmp/nmap-output.xml'
KV_STORE_RAW_KEY = 'nmap-output.xml'


SCAN_PROFILES = {
    'quick':    ['--top-ports', '100'],
    'standard': ['--top-ports', '1000', '-sV'],
    'thorough': ['-p-', '-sV', '-sC'],
    'web':      ['-p', '80,443,8080,8443,8000,8888,3000,5000,8001,8888,9000,9090', '-sV', '--script', 'http-title,http-headers,http-methods,ssl-cert,ssl-enum-ciphers'],
    'vuln':     ['-sV', '--script', 'vuln'],
}


def build_command(input_data: dict) -> tuple:
    """Build the nmap argv. Returns (cmd, scan_type_label)."""
    target = input_data['target']
    cmd = ['nmap', '-sT', '-oX', OUTPUT_XML]

    # Always skip host discovery if requested (recommended in Apify)
    if input_data.get('skipHostDiscovery', True):
        cmd.append('-Pn')

    # Timing
    timing = input_data.get('timing', 'T4')
    cmd.append(f'-{timing}')

    # Scan profile presets
    profile = input_data.get('scanProfile', 'standard')
    if profile in SCAN_PROFILES:
        cmd.extend(SCAN_PROFILES[profile])
    else:
        profile = 'custom'

    # Custom port spec overrides profile ports
    if input_data.get('ports'):
        ports = input_data['ports'].strip()
        if ports.startswith('top-'):
            cmd.extend(['--top-ports', ports.split('-', 1)[1]])
        elif ports == 'all':
            cmd.append('-p-')
        else:
            cmd.extend(['-p', ports])

    # Service / version detection (additive — already in some profiles)
    if input_data.get('serviceDetection') and '-sV' not in cmd:
        cmd.append('-sV')

    # Default NSE scripts (-sC = --script default)
    if input_data.get('defaultScripts') and '-sC' not in cmd:
        cmd.append('-sC')

    # Custom NSE scripts
    if input_data.get('customScripts'):
        cmd.extend(['--script', input_data['customScripts'].strip()])

    # Exclude ports
    if input_data.get('excludePorts'):
        cmd.extend(['--exclude-ports', input_data['excludePorts'].strip()])

    # Only show open ports — cleaner output
    if input_data.get('openPortsOnly', True):
        cmd.append('--open')

    # Custom extra args (advanced)
    custom_args = input_data.get('customArgs', '').strip()
    if custom_args:
        cmd.extend(custom_args.split())

    # Target last — supports space-separated multi-target
    cmd.extend(target.split())

    return cmd, profile


def parse_nmap_xml(xml_path: str) -> dict:
    """Parse nmap -oX XML into structured records: hosts, ports, scripts, plus aggregate stats."""
    result = {'hosts': [], 'ports': [], 'scripts': [], 'stats': {}}

    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, FileNotFoundError) as e:
        result['parse_error'] = str(e)
        return result

    root = tree.getroot()

    # Top-level scan info
    result['stats']['scanner'] = root.attrib.get('scanner')
    result['stats']['version'] = root.attrib.get('version')
    result['stats']['args'] = root.attrib.get('args')
    result['stats']['startedAt'] = root.attrib.get('startstr')

    # Per-host
    for host_el in root.findall('host'):
        addr_el = host_el.find('address')
        address = addr_el.attrib.get('addr') if addr_el is not None else None
        addrtype = addr_el.attrib.get('addrtype') if addr_el is not None else None

        hostnames = []
        hostnames_el = host_el.find('hostnames')
        if hostnames_el is not None:
            for hn in hostnames_el.findall('hostname'):
                hostnames.append(hn.attrib.get('name'))
        hostname_primary = hostnames[0] if hostnames else None

        status_el = host_el.find('status')
        status = status_el.attrib.get('state') if status_el is not None else 'unknown'

        # Ports
        host_open_ports = 0
        ports_el = host_el.find('ports')
        if ports_el is not None:
            for port_el in ports_el.findall('port'):
                portid = int(port_el.attrib.get('portid', 0))
                protocol = port_el.attrib.get('protocol')
                state_el = port_el.find('state')
                port_state = state_el.attrib.get('state') if state_el is not None else 'unknown'
                if port_state == 'open':
                    host_open_ports += 1

                service_el = port_el.find('service')
                service_name = service_el.attrib.get('name') if service_el is not None else None
                product = service_el.attrib.get('product') if service_el is not None else None
                version = service_el.attrib.get('version') if service_el is not None else None
                extra = service_el.attrib.get('extrainfo') if service_el is not None else None

                result['ports'].append({
                    'host': hostname_primary or address,
                    'address': address,
                    'port': portid,
                    'protocol': protocol,
                    'state': port_state,
                    'service': service_name,
                    'product': product,
                    'version': version,
                    'extraInfo': extra,
                })

                # Per-port NSE scripts
                for script_el in port_el.findall('script'):
                    result['scripts'].append({
                        'host': hostname_primary or address,
                        'address': address,
                        'port': portid,
                        'protocol': protocol,
                        'scriptId': script_el.attrib.get('id'),
                        'output': script_el.attrib.get('output'),
                    })

        # Host-level scripts (NSE pre/post-scripts)
        hostscript_el = host_el.find('hostscript')
        if hostscript_el is not None:
            for script_el in hostscript_el.findall('script'):
                result['scripts'].append({
                    'host': hostname_primary or address,
                    'address': address,
                    'port': None,
                    'protocol': None,
                    'scriptId': script_el.attrib.get('id'),
                    'output': script_el.attrib.get('output'),
                })

        result['hosts'].append({
            'host': hostname_primary or address,
            'address': address,
            'addressType': addrtype,
            'hostname': hostname_primary,
            'allHostnames': hostnames,
            'status': status,
            'openPorts': host_open_ports,
        })

    # Run stats (totals)
    runstats = root.find('runstats')
    if runstats is not None:
        finished = runstats.find('finished')
        hosts = runstats.find('hosts')
        if finished is not None:
            result['stats']['elapsed'] = float(finished.attrib.get('elapsed', 0))
            result['stats']['summary'] = finished.attrib.get('summary')
        if hosts is not None:
            result['stats']['hostsUp'] = int(hosts.attrib.get('up', 0))
            result['stats']['hostsDown'] = int(hosts.attrib.get('down', 0))
            result['stats']['hostsTotal'] = int(hosts.attrib.get('total', 0))

    return result


async def main() -> None:
    async with Actor:
        Actor.log.info('nmap Apify Actor starting')

        input_data = await Actor.get_input() or {}
        target = input_data.get('target')
        if not target:
            await Actor.fail(status_message='target is required (IP, hostname, CIDR, or space-separated list)')
            return

        cmd, profile = build_command(input_data)
        Actor.log.info(f'Target: {target}')
        Actor.log.info(f'Scan profile: {profile}')
        Actor.log.info(f'Command: {" ".join(cmd)}')

        timeout = int(input_data.get('timeout', 1800))
        timestamp = datetime.now(timezone.utc).isoformat()
        start_wall = datetime.now(timezone.utc)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            await Actor.fail(status_message=f'nmap timed out after {timeout}s')
            return
        except FileNotFoundError as e:
            await Actor.fail(status_message=f'nmap binary not found: {e}')
            return

        Actor.log.info(f'nmap exit code: {result.returncode} (stdout {len(result.stdout)} chars, stderr {len(result.stderr)} chars)')

        # Surface the last lines of stdout — nmap prints its summary near the end
        if result.stdout:
            for line in [l for l in result.stdout.splitlines() if l.strip()][-30:]:
                Actor.log.info(line)
        if result.stderr:
            for line in [l for l in result.stderr.splitlines() if l.strip()][-20:]:
                Actor.log.warning(line)

        # Save raw XML to KV store regardless of parse success
        if os.path.exists(OUTPUT_XML):
            try:
                with open(OUTPUT_XML, 'rb') as f:
                    await Actor.set_value(KV_STORE_RAW_KEY, f.read(), content_type='application/xml')
                Actor.log.info(f'Raw XML saved to key-value store as {KV_STORE_RAW_KEY}')
            except Exception as e:
                Actor.log.warning(f'Failed to save raw XML to KV store: {e}')

        if result.returncode != 0 and not os.path.exists(OUTPUT_XML):
            await Actor.push_data({
                'recordType': 'summary',
                'target': target,
                'scanProfile': profile,
                'success': False,
                'error': 'nmap exited with non-zero status and no XML produced',
                'exitCode': result.returncode,
                'stderr': result.stderr[-500:],
                'timestamp': timestamp,
            })
            return

        # Parse XML and push records
        parsed = parse_nmap_xml(OUTPUT_XML)

        if 'parse_error' in parsed:
            await Actor.push_data({
                'recordType': 'summary',
                'target': target,
                'scanProfile': profile,
                'success': False,
                'error': f'XML parse failed: {parsed["parse_error"]}',
                'exitCode': result.returncode,
                'timestamp': timestamp,
            })
            return

        # Push individual records: hosts, ports, scripts
        for host in parsed['hosts']:
            await Actor.push_data({
                'recordType': 'host',
                'timestamp': timestamp,
                **host,
            })

        for port in parsed['ports']:
            await Actor.push_data({
                'recordType': 'port',
                'timestamp': timestamp,
                **port,
            })

        for script in parsed['scripts']:
            await Actor.push_data({
                'recordType': 'script',
                'timestamp': timestamp,
                **script,
            })

        wall_duration = (datetime.now(timezone.utc) - start_wall).total_seconds()
        open_ports_total = sum(1 for p in parsed['ports'] if p['state'] == 'open')

        summary = {
            'recordType': 'summary',
            'target': target,
            'scanProfile': profile,
            'scanType': 'tcp-connect',
            'success': True,
            'hostsUp': parsed['stats'].get('hostsUp', 0),
            'hostsDown': parsed['stats'].get('hostsDown', 0),
            'hostsTotal': parsed['stats'].get('hostsTotal', 0),
            'openPortsTotal': open_ports_total,
            'portsScanned': len(parsed['ports']),
            'scriptsRun': len(parsed['scripts']),
            'scanDuration': parsed['stats'].get('elapsed'),
            'wallDuration': round(wall_duration, 2),
            'nmapVersion': parsed['stats'].get('version'),
            'cmd': parsed['stats'].get('args'),
            'finishedSummary': parsed['stats'].get('summary'),
            'timestamp': timestamp,
        }
        await Actor.push_data(summary)

        Actor.log.info(f'Scan complete: {parsed["stats"].get("hostsUp", 0)} hosts up, {open_ports_total} open ports, {len(parsed["scripts"])} script results')


if __name__ == '__main__':
    asyncio.run(main())
