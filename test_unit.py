"""Unit + integration test. Runs a real nmap scan against scanme.nmap.org (the official permitted target)."""
import sys, types, os, subprocess

# Stub the apify module so we can import src.main without the real SDK
apify_stub = types.ModuleType('apify')
class _ActorLog:
    def info(self, m): print(f'[INFO ] {m}')
    def warning(self, m): print(f'[WARN ] {m}')
    def error(self, m): print(f'[ERROR] {m}')
class _Actor:
    log = _ActorLog()
apify_stub.Actor = _Actor()
sys.modules['apify'] = apify_stub

sys.path.insert(0, os.path.dirname(__file__))
from src.main import build_command, parse_nmap_xml, SCAN_PROFILES, OUTPUT_XML


print('=' * 60)
print('TEST 1: build_command — standard profile, default options')
print('=' * 60)
cmd, profile = build_command({'target': 'scanme.nmap.org'})
print(f'  cmd: {cmd}')
print(f'  profile: {profile}')
assert cmd[0] == 'nmap'
assert '-sT' in cmd
assert '-oX' in cmd
assert '-Pn' in cmd          # skipHostDiscovery default True
assert '-T4' in cmd          # default timing
assert '--top-ports' in cmd  # standard profile
assert '1000' in cmd
assert '-sV' in cmd          # standard profile includes service detection
assert '--open' in cmd       # openPortsOnly default True
assert 'scanme.nmap.org' in cmd
print('  ✓ OK')

print()
print('=' * 60)
print('TEST 2: build_command — all knobs turned on (custom)')
print('=' * 60)
cmd, profile = build_command({
    'target': '10.0.0.1 10.0.0.2',
    'scanProfile': 'custom',
    'ports': '22,80,443',
    'serviceDetection': True,
    'defaultScripts': True,
    'customScripts': 'http-title,ssl-cert',
    'timing': 'T3',
    'skipHostDiscovery': False,
    'excludePorts': '9100',
    'openPortsOnly': False,
    'customArgs': '--max-retries 1 --host-timeout 30s',
    'serviceDetection': True,
})
print(f'  cmd: {cmd}')
assert '-p' in cmd and '22,80,443' in cmd
assert '-sV' in cmd
assert '-sC' in cmd
assert '--script' in cmd and 'http-title,ssl-cert' in cmd
assert '-T3' in cmd
assert '-Pn' not in cmd  # skipHostDiscovery False
assert '--exclude-ports' in cmd and '9100' in cmd
assert '--open' not in cmd  # openPortsOnly False
assert '--max-retries' in cmd and '1' in cmd
assert '10.0.0.1' in cmd and '10.0.0.2' in cmd  # multi-target
print('  ✓ All flags wired correctly')

print()
print('=' * 60)
print('TEST 3: build_command — top-N ports parsed correctly')
print('=' * 60)
cmd, _ = build_command({'target': 'x.x', 'scanProfile': 'custom', 'ports': 'top-50'})
assert '--top-ports' in cmd
idx = cmd.index('--top-ports')
assert cmd[idx + 1] == '50', f'Expected 50, got {cmd[idx+1]}'
print(f'  top-50 → --top-ports 50 ✓')

cmd, _ = build_command({'target': 'x.x', 'scanProfile': 'custom', 'ports': 'all'})
assert '-p-' in cmd
print(f'  all → -p- ✓')

print()
print('=' * 60)
print('TEST 4: SCAN_PROFILES sanity check')
print('=' * 60)
for name in ['quick', 'standard', 'thorough', 'web', 'vuln']:
    assert name in SCAN_PROFILES, f'Missing profile: {name}'
    print(f'  {name}: {SCAN_PROFILES[name]}')
print('  ✓ All 5 profiles defined')

print()
print('=' * 60)
print('TEST 5: REAL nmap scan against scanme.nmap.org')
print('=' * 60)
test_xml = '/tmp/test_nmap_unit.xml'
real_cmd = ['nmap', '-sT', '-Pn', '-T4', '--top-ports', '20', '--open', '-oX', test_xml, 'scanme.nmap.org']
print(f'  running: {" ".join(real_cmd)}')
proc = subprocess.run(real_cmd, capture_output=True, text=True, timeout=120)
print(f'  exit={proc.returncode}, stdout={len(proc.stdout)} chars')
assert proc.returncode == 0, f'nmap failed: {proc.stderr}'
assert os.path.exists(test_xml), 'no XML output'

parsed = parse_nmap_xml(test_xml)
print(f'  hosts: {len(parsed["hosts"])}')
print(f'  ports: {len(parsed["ports"])}')
print(f'  scripts: {len(parsed["scripts"])}')
print(f'  stats: hostsUp={parsed["stats"].get("hostsUp")} elapsed={parsed["stats"].get("elapsed")}s')
print(f'  nmap version: {parsed["stats"].get("version")}')
print()
print(f'  Open ports found:')
for p in parsed['ports']:
    print(f'    {p["address"]}:{p["port"]}/{p["protocol"]} {p["state"]:8s} {p.get("service") or "":15s} {p.get("product") or ""} {p.get("version") or ""}')

assert len(parsed['hosts']) >= 1, 'expected at least 1 host'
assert len(parsed['ports']) >= 1, 'expected at least 1 port (scanme should have 22 + 80 open)'
print('  ✓ Real scan parsed correctly')

print()
print('ALL TESTS PASS ✓')
os.unlink(test_xml)
