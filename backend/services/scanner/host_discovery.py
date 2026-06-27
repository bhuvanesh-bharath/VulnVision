"""
VulnVision Host Discovery Service.
Discovers live hosts on a network using ARP, ICMP, and TCP probes.
"""
import socket
import subprocess
import ipaddress
import platform
import concurrent.futures
from backend.utils.logger import get_scan_logger
from backend.config import Config

logger = get_scan_logger()


class HostDiscovery:
    """Discovers live hosts on a network using multiple discovery methods."""

    def __init__(self):
        self.timeout = Config.SCANNER_TIMEOUT

    def discover_hosts(self, target, methods=None):
        """Discover live hosts on the target network.

        Args:
            target: IP address, CIDR range, or IP range string.
            methods: List of methods to use ('arp', 'icmp', 'tcp'). Defaults to all.

        Returns:
            List of dicts with keys: ip, hostname, mac, discovery_method, status.
        """
        if methods is None:
            methods = ['icmp', 'tcp']

        ips = self._parse_target(target)
        logger.info('Discovering hosts for target %s (%d IPs to check)', target, len(ips))

        discovered = {}

        if 'arp' in methods:
            for host in self._arp_discovery(target):
                discovered[host['ip']] = host

        if 'icmp' in methods:
            for host in self._icmp_discovery(ips):
                if host['ip'] not in discovered:
                    discovered[host['ip']] = host

        if 'tcp' in methods:
            for host in self._tcp_discovery(ips):
                if host['ip'] not in discovered:
                    discovered[host['ip']] = host

        results = list(discovered.values())
        logger.info('Discovered %d live hosts', len(results))
        return results

    def _parse_target(self, target):
        """Parse target specification into a list of IP address strings.

        Supports:
            - Single IP: '192.168.1.1'
            - CIDR: '192.168.1.0/24'
            - Range: '192.168.1.1-50'
            - Comma list: '192.168.1.1,192.168.1.2'

        Args:
            target: Target specification string.

        Returns:
            List of IP address strings.
        """
        target = target.strip()
        ips = []

        if ',' in target:
            for part in target.split(','):
                ips.extend(self._parse_target(part.strip()))
            return ips

        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            except ValueError:
                logger.warning('Invalid CIDR notation: %s', target)
                return []

        if '-' in target and not target.startswith('-'):
            parts = target.rsplit('-', 1)
            if len(parts) == 2:
                try:
                    base_ip = parts[0]
                    end_octet = int(parts[1])
                    base_parts = base_ip.split('.')
                    if len(base_parts) == 4:
                        start_octet = int(base_parts[3])
                        base = '.'.join(base_parts[:3])
                        for i in range(start_octet, end_octet + 1):
                            ip_str = f'{base}.{i}'
                            try:
                                ipaddress.ip_address(ip_str)
                                ips.append(ip_str)
                            except ValueError:
                                continue
                        return ips
                except (ValueError, IndexError):
                    pass

        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            try:
                resolved = socket.gethostbyname(target)
                return [resolved]
            except socket.gaierror:
                logger.warning('Cannot resolve target: %s', target)
                return []

    def _arp_discovery(self, target):
        """Discover hosts using ARP requests (requires root/admin).

        Args:
            target: Network target for ARP scan.

        Returns:
            List of discovered host dicts.
        """
        hosts = []
        try:
            from scapy.all import ARP, Ether, srp
            arp_request = ARP(pdst=target)
            broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
            packet = broadcast / arp_request
            answered, _ = srp(packet, timeout=self.timeout, verbose=False)

            for sent, received in answered:
                hostname = self._resolve_hostname(received.psrc)
                hosts.append({
                    'ip': received.psrc,
                    'hostname': hostname,
                    'mac': received.hwsrc,
                    'discovery_method': 'arp',
                    'status': 'up'
                })
            logger.info('ARP discovery found %d hosts', len(hosts))
        except ImportError:
            logger.debug('Scapy not available, skipping ARP discovery')
        except PermissionError:
            logger.debug('Insufficient permissions for ARP discovery')
        except Exception as e:
            logger.debug('ARP discovery failed: %s', str(e))
        return hosts

    def _icmp_discovery(self, ips):
        """Discover hosts using ICMP echo requests (ping).

        Args:
            ips: List of IP address strings.

        Returns:
            List of discovered host dicts.
        """
        hosts = []
        is_windows = platform.system().lower() == 'windows'

        def ping_host(ip):
            try:
                if is_windows:
                    cmd = ['ping', '-n', '1', '-w', str(self.timeout * 1000), ip]
                else:
                    cmd = ['ping', '-c', '1', '-W', str(self.timeout), ip]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout + 2
                )
                if result.returncode == 0:
                    hostname = self._resolve_hostname(ip)
                    return {
                        'ip': ip,
                        'hostname': hostname,
                        'mac': None,
                        'discovery_method': 'icmp',
                        'status': 'up'
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(Config.SCANNER_MAX_THREADS, len(ips) or 1)
        ) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in ips}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    hosts.append(result)

        logger.info('ICMP discovery found %d hosts', len(hosts))
        return hosts

    def _tcp_discovery(self, ips, ports=None):
        """Discover hosts by attempting TCP connections.

        Args:
            ips: List of IP address strings.
            ports: List of ports to try. Defaults to common ports.

        Returns:
            List of discovered host dicts.
        """
        if ports is None:
            ports = [80, 443, 22, 445, 3389, 8080]

        hosts = {}

        def try_connect(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return ip
            except (socket.error, OSError):
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(Config.SCANNER_MAX_THREADS, len(ips) * len(ports) or 1)
        ) as executor:
            futures = {}
            for ip in ips:
                for port in ports:
                    future = executor.submit(try_connect, ip, port)
                    futures[future] = ip

            for future in concurrent.futures.as_completed(futures):
                ip = future.result()
                if ip and ip not in hosts:
                    hostname = self._resolve_hostname(ip)
                    hosts[ip] = {
                        'ip': ip,
                        'hostname': hostname,
                        'mac': None,
                        'discovery_method': 'tcp',
                        'status': 'up'
                    }

        result_list = list(hosts.values())
        logger.info('TCP discovery found %d hosts', len(result_list))
        return result_list

    def _resolve_hostname(self, ip):
        """Attempt reverse DNS lookup for an IP address.

        Args:
            ip: IP address string.

        Returns:
            Hostname string or None.
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None
