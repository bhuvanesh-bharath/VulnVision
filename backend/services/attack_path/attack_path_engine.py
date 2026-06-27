"""
VulnVision Attack Path Engine.
Generates potential attack chains by analyzing host relationships, vulnerabilities, and network exposure.
"""
import uuid
import json
import ipaddress
from datetime import datetime, timezone
from backend.models.base import db
from backend.models.host import Host
from backend.models.port import Port
from backend.models.vulnerability import Vulnerability
from backend.models.attack_path import AttackPath
from backend.utils.logger import get_scan_logger

logger = get_scan_logger()


class AttackPathEngine:
    """Generates and scores attack paths from scan results."""

    HIGH_VALUE_SERVICES = {'mysql', 'mssql', 'postgresql', 'mongodb', 'redis',
                           'smb', 'rdp', 'vnc', 'ssh', 'ldap'}
    ENTRY_SERVICES = {'http', 'https', 'ftp', 'ssh', 'telnet', 'rdp', 'smb'}

    def generate(self, scan_id):
        """Generate attack paths for a completed scan.

        Args:
            scan_id: Database ID of the scan.

        Returns:
            List of created AttackPath model instances.
        """
        hosts = Host.query.filter_by(scan_id=scan_id).all()
        vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()

        if not hosts or not vulns:
            logger.info('No hosts or vulnerabilities found for scan %d', scan_id)
            return []

        graph = self._build_network_graph(hosts, vulns)
        entry_points = self._identify_entry_points(hosts, vulns)
        targets = self._identify_targets(hosts, vulns)

        if not entry_points or not targets:
            logger.info('No entry points or targets identified')
            return []

        chains = self._enumerate_paths(graph, entry_points, targets, max_depth=5)
        attack_paths = []

        for chain in chains:
            score_data = self._score_path(chain)
            path = self._persist_path(scan_id, chain, score_data)
            if path:
                attack_paths.append(path)

        logger.info('Generated %d attack paths for scan %d', len(attack_paths), scan_id)
        return attack_paths

    def _build_network_graph(self, hosts, vulnerabilities):
        """Build an adjacency graph of hosts based on network relationships.

        Args:
            hosts: List of Host instances.
            vulnerabilities: List of Vulnerability instances.

        Returns:
            Dict mapping host_id to list of connected host_ids with edge info.
        """
        graph = {}
        vuln_map = {}
        for v in vulnerabilities:
            vuln_map.setdefault(v.host_id, []).append(v)

        for host in hosts:
            ports = Port.query.filter_by(host_id=host.id, state='open').all()
            graph[host.id] = {
                'host': host,
                'ports': ports,
                'vulns': vuln_map.get(host.id, []),
                'edges': []
            }

        host_list = list(graph.keys())
        for i, hid1 in enumerate(host_list):
            for hid2 in host_list[i + 1:]:
                h1 = graph[hid1]['host']
                h2 = graph[hid2]['host']

                try:
                    ip1 = ipaddress.ip_address(h1.ip_address)
                    ip2 = ipaddress.ip_address(h2.ip_address)
                    net1 = ipaddress.ip_network(f'{h1.ip_address}/24', strict=False)
                    if ip2 in net1:
                        graph[hid1]['edges'].append({'target': hid2, 'type': 'network_proximity'})
                        graph[hid2]['edges'].append({'target': hid1, 'type': 'network_proximity'})
                except ValueError:
                    pass

                services1 = {p.service_name for p in graph[hid1]['ports'] if p.service_name}
                services2 = {p.service_name for p in graph[hid2]['ports'] if p.service_name}
                shared = services1 & services2
                if shared:
                    graph[hid1]['edges'].append({'target': hid2, 'type': 'shared_services', 'services': list(shared)})
                    graph[hid2]['edges'].append({'target': hid1, 'type': 'shared_services', 'services': list(shared)})

        return graph

    def _identify_entry_points(self, hosts, vulnerabilities):
        """Identify hosts that could serve as initial entry points.

        Args:
            hosts: List of Host instances.
            vulnerabilities: List of Vulnerability instances.

        Returns:
            List of host_id values.
        """
        entry_points = []
        vuln_map = {}
        for v in vulnerabilities:
            vuln_map.setdefault(v.host_id, []).append(v)

        for host in hosts:
            ports = Port.query.filter_by(host_id=host.id, state='open').all()
            services = {p.service_name for p in ports if p.service_name}

            if services & self.ENTRY_SERVICES:
                entry_points.append(host.id)
            elif vuln_map.get(host.id):
                high_vulns = [v for v in vuln_map[host.id] if v.severity in ('critical', 'high')]
                if high_vulns:
                    entry_points.append(host.id)

        return entry_points

    def _identify_targets(self, hosts, vulnerabilities):
        """Identify high-value target hosts.

        Args:
            hosts: List of Host instances.
            vulnerabilities: List of Vulnerability instances.

        Returns:
            List of host_id values.
        """
        targets = []
        for host in hosts:
            ports = Port.query.filter_by(host_id=host.id, state='open').all()
            services = {p.service_name for p in ports if p.service_name}

            if services & self.HIGH_VALUE_SERVICES:
                targets.append(host.id)
            elif host.risk_score and host.risk_score >= 5.0:
                targets.append(host.id)

        return targets

    def _enumerate_paths(self, graph, entry_points, targets, max_depth=5):
        """Enumerate attack chains using DFS.

        Args:
            graph: Network graph dict.
            entry_points: List of entry point host IDs.
            targets: List of target host IDs.
            max_depth: Maximum chain length.

        Returns:
            List of chain dicts.
        """
        chains = []

        for entry in entry_points:
            for target in targets:
                if entry == target:
                    if graph[entry]['vulns']:
                        chain = self._build_direct_chain(graph, entry)
                        if chain:
                            chains.append(chain)
                    continue

                found_paths = []
                self._dfs(graph, entry, target, [entry], set(), found_paths, max_depth)
                for path in found_paths:
                    chain = self._build_chain_from_path(graph, path)
                    if chain:
                        chains.append(chain)

        unique_chains = []
        seen = set()
        for chain in chains:
            key = tuple(s['host_id'] for s in chain['steps'])
            if key not in seen:
                seen.add(key)
                unique_chains.append(chain)

        return unique_chains[:20]

    def _dfs(self, graph, current, target, path, visited, found_paths, max_depth):
        """Depth-first search for paths between two hosts."""
        if len(path) > max_depth:
            return
        if current == target:
            found_paths.append(list(path))
            return

        visited.add(current)
        if current in graph:
            for edge in graph[current]['edges']:
                neighbor = edge['target']
                if neighbor not in visited:
                    path.append(neighbor)
                    self._dfs(graph, neighbor, target, path, visited, found_paths, max_depth)
                    path.pop()
        visited.discard(current)

    def _build_direct_chain(self, graph, host_id):
        """Build a chain for direct exploitation of a single host."""
        node = graph[host_id]
        host = node['host']
        vulns = node['vulns']
        if not vulns:
            return None

        steps = []
        for v in sorted(vulns, key=lambda x: x.cvss_score or 0, reverse=True)[:3]:
            steps.append(self._generate_chain_step(host, v, 'exploit'))

        return {
            'name': f'Direct exploitation of {host.ip_address}',
            'description': f'Direct attack on {host.ip_address} via {len(steps)} vulnerability(ies)',
            'steps': steps,
            'entry_point': host.ip_address,
            'target': host.ip_address,
        }

    def _build_chain_from_path(self, graph, path):
        """Build a chain from a DFS path."""
        steps = []
        for hid in path:
            node = graph[hid]
            host = node['host']
            vulns = node['vulns']
            if vulns:
                best = max(vulns, key=lambda v: v.cvss_score or 0)
                action = 'initial_access' if hid == path[0] else ('target' if hid == path[-1] else 'lateral_movement')
                steps.append(self._generate_chain_step(host, best, action))
            else:
                steps.append({
                    'host_id': hid,
                    'host_ip': host.ip_address,
                    'action': 'pivot',
                    'description': f'Pivot through {host.ip_address}',
                    'vulnerability': None,
                    'severity': 'info',
                })

        if not steps:
            return None

        entry_host = graph[path[0]]['host']
        target_host = graph[path[-1]]['host']

        return {
            'name': f'Attack path: {entry_host.ip_address} → {target_host.ip_address}',
            'description': f'{len(steps)}-step attack chain from {entry_host.ip_address} to {target_host.ip_address}',
            'steps': steps,
            'entry_point': entry_host.ip_address,
            'target': target_host.ip_address,
        }

    def _generate_chain_step(self, host, vulnerability, action):
        """Generate a single step in an attack chain."""
        return {
            'host_id': host.id,
            'host_ip': host.ip_address,
            'action': action,
            'description': f'{action.replace("_", " ").title()}: {vulnerability.title}',
            'vulnerability': vulnerability.title,
            'severity': vulnerability.severity,
            'cvss_score': vulnerability.cvss_score,
        }

    def _score_path(self, chain):
        """Score an attack path based on its steps.

        Args:
            chain: Chain dict with steps.

        Returns:
            Dict with risk_score, likelihood, impact, attack_complexity.
        """
        steps = chain.get('steps', [])
        if not steps:
            return {'risk_score': 0, 'likelihood': 0, 'impact': 0, 'attack_complexity': 'high'}

        severity_scores = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2, 'info': 0.5}
        cvss_scores = [s.get('cvss_score', 0) or 0 for s in steps]
        severity_vals = [severity_scores.get(s.get('severity', 'info'), 0) for s in steps]

        max_cvss = max(cvss_scores) if cvss_scores else 0
        avg_severity = sum(severity_vals) / len(severity_vals) if severity_vals else 0
        path_length = len(steps)

        length_penalty = max(0, (path_length - 1) * 0.5)
        risk_score = min(10, (max_cvss * 0.5 + avg_severity * 0.3 + 2) - length_penalty)
        risk_score = max(0, risk_score)

        likelihood = min(10, avg_severity * 0.8 + (10 - path_length) * 0.2) if path_length <= 10 else 1
        impact = max_cvss

        if path_length <= 2:
            complexity = 'low'
        elif path_length <= 4:
            complexity = 'medium'
        else:
            complexity = 'high'

        return {
            'risk_score': round(risk_score, 2),
            'likelihood': round(max(0, likelihood), 2),
            'impact': round(impact, 2),
            'attack_complexity': complexity
        }

    def _persist_path(self, scan_id, chain, score_data):
        """Persist an attack path to the database.

        Args:
            scan_id: Parent scan ID.
            chain: Chain dict.
            score_data: Score data dict.

        Returns:
            Created AttackPath instance.
        """
        try:
            path = AttackPath(
                scan_id=scan_id,
                name=chain['name'][:200],
                description=chain.get('description', '')[:500],
                chain=chain.get('steps', []),
                risk_score=score_data['risk_score'],
                likelihood=score_data['likelihood'],
                impact=score_data['impact'],
                attack_complexity=score_data['attack_complexity'],
                entry_point=chain.get('entry_point', ''),
                target_asset=chain.get('target', ''),
                path_length=len(chain.get('steps', [])),
            )
            db.session.add(path)
            db.session.commit()
            return path
        except Exception as e:
            db.session.rollback()
            logger.error('Failed to persist attack path: %s', str(e))
            return None
