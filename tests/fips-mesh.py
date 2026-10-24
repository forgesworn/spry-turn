#!/usr/bin/env python3
"""Real Spry TURN through FIPS and two simulated NATs. No external network."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import selectors
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--fips-dir', type=Path, required=True)
    parser.add_argument('--image', default='spry-fips-fixture:0.4.1')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary, fips = args.binary.resolve(), args.fips_dir.resolve()
    label = 'spry-fips-' + secrets.token_hex(5)
    names, networks, children, logs = [], [], [], []
    agents, bridges = [], []
    scratch = ROOT / '.local'
    scratch.mkdir(exist_ok=True)
    snapshot = scratch / (label + '-mesh-node')
    snapshot.write_bytes(binary.read_bytes())
    snapshot.chmod(0o755)
    binary_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest()

    def docker(*values):
        return subprocess.check_output(['docker', *values], text=True, stderr=subprocess.PIPE, timeout=30)

    def read(child):
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdout, selectors.EVENT_READ)
            if not poll.select(20):
                raise TimeoutError('FIPS fixture reply timed out; inspect private logs')
        line = child.stdout.readline(16385)
        if not line or len(line) > 16384:
            raise RuntimeError('FIPS fixture exited or exceeded bounds')
        return json.loads(line)

    def write(child, value):
        child.stdin.write(json.dumps(value) + '\n')
        child.stdin.flush()

    def ask(child, value):
        write(child, value)
        return read(child)

    def exchange(values):
        for child, value in zip(bridges, values):
            write(child, value)
        return [read(child) for child in bridges]

    def spawn(name, options, script):
        names.append(name)
        log = (scratch / (name + '.log')).open('w')
        logs.append(log)
        child = subprocess.Popen(['docker', 'run', '--rm', '-i', '--name', name,
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--memory', '128m', '--cpus', '1', '--pids-limit', '64',
            '--tmpfs', '/tmp:size=8m', '--tmpfs', '/run:size=4m',
            '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--mount', f'type=bind,source={ROOT / "tests"},target=/fixture/tests,readonly',
            *options, args.image, 'python3', '-u', '/fixture/tests/' + script],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        children.append(child)
        return child

    def ip(name, network):
        return json.loads(docker('inspect', name))[0]['NetworkSettings']['Networks'][network]['IPAddress']

    try:
        for index in range(3):
            network = label + '-net' + str(index)
            subnet = 'fc' + secrets.token_hex(1) + ':' + secrets.token_hex(2) + ':' + secrets.token_hex(2) + '::/64'
            docker('network', 'create', *(['--internal'] if index == 0 else []), '--ipv6', '--subnet', subnet, network)
            networks.append(network)
        wan = networks[0]
        anchor_name = label + '-anchor'
        agents.append(spawn(anchor_name, ['--network', wan, '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
            '--device', '/dev/net/tun', '--mount', f'type=bind,source={fips / "fips"},target=/fixture/fips,readonly', '--mount', f'type=bind,source={fips / "fipsctl"},target=/fixture/fipsctl,readonly'], 'fips-node.py'))
        anchor = read(agents[0])
        anchor_ip = ip(anchor_name, wan)
        routers = []
        for index, lan in enumerate(networks[1:]):
            router = label + '-router' + str(index)
            names.append(router)
            docker('run', '-d', '--name', router, '--network', wan, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                '--read-only', '--memory', '64m', '--cpus', '0.5', '--pids-limit', '16',
                '--sysctl', 'net.ipv4.ip_forward=1', args.image, 'python3', '-c', 'import time;time.sleep(900)')
            configuration = json.loads(docker('network', 'inspect', lan))[0]['IPAM']['Config']
            subnet = next(ipaddress.ip_network(value['Subnet']) for value in configuration if ':' not in value['Subnet'])
            gateway = str(subnet.network_address + 254)
            docker('network', 'connect', '--ip', gateway, lan, router)
            # Docker internal bridges reject routed traffic even to our own
            # NAT router. LAN bridges use only this router; remove its Internet
            # defaults and keep the WAN internal with no published host ports.
            for family in ['-4', '-6']:
                routes = json.loads(docker('exec', router, 'ip', '-j', family, 'route'))
                if any(route.get('dst') == 'default' for route in routes):
                    docker('exec', router, 'ip', family, 'route', 'del', 'default')
                assert not any(route.get('dst') == 'default' for route in json.loads(docker('exec', router, 'ip', '-j', family, 'route')))

            addresses = json.loads(docker('exec', router, 'ip', '-j', '-4', 'address', 'show'))
            def interface(address):
                return next(item['ifname'] for item in addresses if any(entry.get('local') == address for entry in item['addr_info']))
            wan_interface = interface(ip(router, wan))
            lan_interface = interface(gateway)
            rules = f'''table ip spry_fixture {{
 chain post {{ type nat hook postrouting priority srcnat; policy accept; ip saddr {subnet} oifname "{wan_interface}" counter masquerade; }}
 chain forward {{ type filter hook forward priority 0; policy drop; ct state established,related accept; iifname "{lan_interface}" oifname "{wan_interface}" accept; }}
}}'''
            subprocess.run(['docker', 'exec', '-i', router, 'nft', '-f', '-'], input=rules, text=True, check=True, timeout=10)
            routers.append(router)
            node_name = label + '-edge' + str(index)
            node = spawn(node_name, ['--network', lan, '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
                '--device', '/dev/net/tun', '--mount', f'type=bind,source={fips / "fips"},target=/fixture/fips,readonly', '--mount', f'type=bind,source={fips / "fipsctl"},target=/fixture/fipsctl,readonly'], 'fips-node.py')
            agents.append(node)
            card = read(node)
            docker('exec', node_name, 'ip', 'route', 'replace', 'default', 'via', gateway)
            if any(route.get('dst') == 'default' for route in json.loads(docker('exec', node_name, 'ip', '-j', '-6', 'route'))):
                docker('exec', node_name, 'ip', '-6', 'route', 'del', 'default')
            assert ask(node, {'action': 'connect', 'npub': anchor['public'], 'address': anchor_ip + ':8443'})['ok']
            bridge = spawn(label + '-spry' + str(index), ['--network', 'container:' + node_name,
                '--env', 'FIXTURE_CLIENT_IP=' + ip(node_name, lan), '--env', 'FIXTURE_IP6=' + card['address'],
                '--env', 'FIXTURE_PEER_NAME=' + card['public'] + '.fips', '--env', 'FIXTURE_PEER_RESOLVER=[::1]:5354',
                '--mount', f'type=bind,source={snapshot},target=/fixture/mesh-node,readonly'], 'mesh-node.py')
            bridges.append(bridge)
        deadline = time.monotonic() + 30
        while True:
            states = [ask(agent, {})['status'] for agent in agents]
            if states[0]['peer_count'] == 2 and all(state['peer_count'] == 1 for state in states[1:]):
                break
            if time.monotonic() > deadline:
                raise TimeoutError('FIPS outbound peering through NAT did not finish')
            time.sleep(.1)
        print('FIPS fixture: two outbound-only simulated home NATs reached a separate mesh anchor', flush=True)
        cards = [read(bridge)['card'] for bridge in bridges]
        exchange([{'action': 'peers', 'peers': [cards[1]]}, {'action': 'peers', 'peers': [cards[0]]}])
        deadline = time.monotonic() + 30
        while True:
            states = exchange([{'action': 'status'}] * 2)
            if all(state['healthy'] and state['connected'] == 1 for state in states):
                break
            if time.monotonic() > deadline:
                raise TimeoutError('Spry did not connect through the host mesh resolver')
            time.sleep(.1)
        print('FIPS fixture: signed Spry links connected through the existing host resolver', flush=True)
        allocated = exchange([{'action': 'allocate'}] * 2)
        exchange([{'action': 'prepare', 'relays': allocated[1]['relays']}, {'action': 'prepare', 'relays': allocated[0]['relays']}])
        for _ in range(3):
            payload = secrets.token_bytes(1280).hex()
            exchange([{'action': 'send', 'payload': payload}] * 2)
            assert all(reply['received'] == 2 for reply in exchange([{'action': 'receive', 'payload': payload}] * 2))
        print('FIPS fixture: bidirectional UDP/TCP TURN traffic passed through both NATs', flush=True)
        ask(bridges[0], {'action': 'peers', 'peers': []})
        time.sleep(.2)
        ask(bridges[1], {'action': 'send', 'payload': secrets.token_bytes(128).hex()})
        assert ask(bridges[0], {'action': 'silent'})['silent'] is True
        counters = []
        for router in routers:
            rules = json.loads(docker('exec', router, 'nft', '-j', 'list', 'table', 'ip', 'spry_fixture'))
            count = sum(expr.get('counter', {}).get('packets', 0) for entry in rules['nftables'] for expr in entry.get('rule', {}).get('expr', []))
            assert count > 0
            counters.append(count)
        receipt = {'schema': 1, 'passed': True, 'scope': 'real-fips-two-simulated-home-nats-spry-udp-tcp',
            'binarySha256': binary_hash, 'fipsBinarySha256': hashlib.sha256((fips / 'fips').read_bytes()).hexdigest(),
            'fipsVersion': '0.4.1', 'twoSimulatedNats': True, 'natPacketCounters': counters,
            'externalNetworkingDisabled': True, 'isolatedWan': True, 'internetDefaultRoutesRemoved': True, 'publishedHostPorts': False, 'spryExtraCapabilities': False,
            'meshHostCapabilities': ['NET_ADMIN', 'NET_RAW'], 'explicitLocalResolver': True,
            'signedPeerLinks': True, 'udpTurnBidirectional': True, 'tcpTurnBidirectional': True,
            'withdrawalStopsForwarding': True, 'payloadBytes': 1280, 'rounds': 3,
            'limits': ['Local Linux namespaces and generated traffic with a separate fixture mesh anchor',
                'No physical broadband, public anchor, installed Archipelago or browser-media proof in this receipt']}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    except Exception:
        diagnostics = {}
        for name in names:
            commands = [('ip', '-j', '-4', 'route'), ('ip', '-j', '-4', 'address'), ('nft', '-j', 'list', 'ruleset'), ('tail', '-n', '25', '/tmp/fips.log')]
            values = []
            for command in commands:
                try: values.append({'command': command, 'output': docker('exec', name, *command)[-8000:]})
                except Exception: pass
            diagnostics[name] = values
        (scratch / (label + '-diagnostics.json')).write_text(json.dumps(diagnostics, indent=2))
        raise
    finally:
        for child in reversed(children):
            child.stdin.close()
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            child.stdout.close()
        for name in reversed(names):
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for network in reversed(networks):
            subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for log in logs:
            log.close()
        snapshot.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
