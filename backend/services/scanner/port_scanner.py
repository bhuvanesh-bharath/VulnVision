"""
VulnVision Port Scanner Service.
Scans TCP ports on discovered hosts using concurrent socket connections.
"""
import socket
import concurrent.futures
from backend.utils.logger import get_scan_logger
from backend.config import Config

logger = get_scan_logger()


class PortScanner:
    """Scans TCP ports on target hosts using connect scanning."""

    def __init__(self):
        self.timeout = Config.SCANNER_TIMEOUT
        self.max_threads = Config.SCANNER_MAX_THREADS
        self.default_ports = Config.SCANNER_DEFAULT_PORTS

    def scan_ports(self, ip, ports='default', timeout=None):
        """Scan ports on a target IP address.

        Args:
            ip: Target IP address.
            ports: Port specification string ('default', 'full', '80', '1-1024', '80,443').
            timeout: Connection timeout in seconds.

        Returns:
            List of dicts with keys: port, protocol, state, service_name, banner.
        """
        if timeout is None:
            timeout = self.timeout

        port_list = self._parse_port_range(ports)
        logger.info('Scanning %d ports on %s', len(port_list), ip)

        results = self._concurrent_scan(ip, port_list, timeout)

        open_ports = [r for r in results if r['state'] == 'open']
        logger.info('Found %d open ports on %s', len(open_ports), ip)
        return results

    def _parse_port_range(self, ports):
        """Parse port specification into list of integers.

        Supports:
            - 'default': Common ports from config.
            - 'full': Ports 1-65535.
            - Single: '80'.
            - Range: '1-1024'.
            - List: '80,443,8080'.
            - Mixed: '22,80,443,1000-2000'.

        Args:
            ports: Port specification string.

        Returns:
            Sorted list of unique port integers.
        """
        if ports == 'default':
            return sorted(set(int(p) for p in self.default_ports.split(',')))

        if ports == 'full':
            return list(range(1, 65536))

        result = set()
        for part in str(ports).split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = part.split('-', 1)
                    start, end = int(start), int(end)
                    for p in range(max(1, start), min(65535, end) + 1):
                        result.add(p)
                except ValueError:
                    continue
            else:
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        result.add(p)
                except ValueError:
                    continue

        return sorted(result)

    def _tcp_connect_scan(self, ip, port, timeout):
        """Attempt TCP connect to a single port.

        Args:
            ip: Target IP address.
            port: Port number.
            timeout: Connection timeout.

        Returns:
            Dict with port scan result.
        """
        result = {
            'port': port,
            'protocol': 'tcp',
            'state': 'closed',
            'service_name': None,
            'banner': None
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            conn_result = sock.connect_ex((ip, port))

            if conn_result == 0:
                result['state'] = 'open'
                banner = self._grab_banner(sock, timeout)
                if banner:
                    result['banner'] = banner
            sock.close()
        except socket.timeout:
            result['state'] = 'filtered'
        except ConnectionRefusedError:
            result['state'] = 'closed'
        except OSError:
            result['state'] = 'filtered'

        return result

    def _grab_banner(self, sock, timeout):
        """Attempt to read a service banner from a connected socket.

        Args:
            sock: Connected socket object.
            timeout: Read timeout.

        Returns:
            Banner string or None.
        """
        try:
            sock.settimeout(min(timeout, 3))
            sock.send(b'HEAD / HTTP/1.1\r\nHost: target\r\n\r\n')
            banner = sock.recv(1024)
            if banner:
                return banner.decode('utf-8', errors='replace').strip()[:500]
        except (socket.timeout, OSError, UnicodeDecodeError):
            pass
        return None

    def _concurrent_scan(self, ip, ports, timeout):
        """Scan multiple ports concurrently using ThreadPoolExecutor.

        Args:
            ip: Target IP address.
            ports: List of port numbers.
            timeout: Connection timeout.

        Returns:
            List of port scan result dicts.
        """
        results = []
        max_workers = min(self.max_threads, len(ports) or 1)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._tcp_connect_scan, ip, port, timeout): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result['state'] == 'open':
                        results.append(result)
                except Exception as e:
                    logger.debug('Port scan error: %s', str(e))

        return sorted(results, key=lambda x: x['port'])
