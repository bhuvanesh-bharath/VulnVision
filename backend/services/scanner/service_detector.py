"""
VulnVision Service Detector.
Identifies services running on open ports via port mapping, banner analysis, and HTTP probing.
"""
import re
import socket
import requests
from backend.utils.logger import get_scan_logger

logger = get_scan_logger()


class ServiceDetector:
    """Identifies services running on discovered open ports."""

    PORT_SERVICE_MAP = {
        20: ('ftp-data', 'FTP Data'), 21: ('ftp', 'FTP'), 22: ('ssh', 'SSH'),
        23: ('telnet', 'Telnet'), 25: ('smtp', 'SMTP'), 53: ('dns', 'DNS'),
        67: ('dhcp', 'DHCP'), 69: ('tftp', 'TFTP'), 80: ('http', 'HTTP'),
        110: ('pop3', 'POP3'), 111: ('rpcbind', 'RPCBind'), 119: ('nntp', 'NNTP'),
        123: ('ntp', 'NTP'), 135: ('msrpc', 'MS-RPC'), 137: ('netbios-ns', 'NetBIOS-NS'),
        138: ('netbios-dgm', 'NetBIOS-DGM'), 139: ('netbios-ssn', 'NetBIOS-SSN'),
        143: ('imap', 'IMAP'), 161: ('snmp', 'SNMP'), 162: ('snmptrap', 'SNMP Trap'),
        389: ('ldap', 'LDAP'), 443: ('https', 'HTTPS'), 445: ('smb', 'SMB'),
        465: ('smtps', 'SMTPS'), 514: ('syslog', 'Syslog'), 515: ('lpd', 'LPD'),
        587: ('submission', 'SMTP Submission'), 636: ('ldaps', 'LDAPS'),
        993: ('imaps', 'IMAPS'), 995: ('pop3s', 'POP3S'), 1080: ('socks', 'SOCKS'),
        1433: ('mssql', 'MS SQL Server'), 1434: ('mssql-m', 'MS SQL Monitor'),
        1521: ('oracle', 'Oracle DB'), 1723: ('pptp', 'PPTP'),
        2049: ('nfs', 'NFS'), 2082: ('cpanel', 'cPanel'), 2083: ('cpanels', 'cPanel SSL'),
        3306: ('mysql', 'MySQL'), 3389: ('rdp', 'RDP'), 3690: ('svn', 'SVN'),
        5432: ('postgresql', 'PostgreSQL'), 5631: ('pcanywhere', 'PCAnywhere'),
        5900: ('vnc', 'VNC'), 5901: ('vnc-1', 'VNC :1'), 6379: ('redis', 'Redis'),
        6667: ('irc', 'IRC'), 8080: ('http-proxy', 'HTTP Proxy'),
        8443: ('https-alt', 'HTTPS Alt'), 8888: ('http-alt', 'HTTP Alt'),
        9090: ('webmin', 'Webmin'), 9200: ('elasticsearch', 'Elasticsearch'),
        11211: ('memcached', 'Memcached'), 27017: ('mongodb', 'MongoDB'),
        27018: ('mongodb-s', 'MongoDB Shard'), 5672: ('amqp', 'RabbitMQ'),
        6443: ('kubernetes', 'Kubernetes API'), 8081: ('http-alt2', 'HTTP Alt'),
        9000: ('cslistener', 'PHP-FPM'), 9092: ('kafka', 'Kafka'),
        2181: ('zookeeper', 'ZooKeeper'), 4444: ('metasploit', 'Metasploit'),
    }

    BANNER_PATTERNS = [
        (r'SSH-[\d.]+-(OpenSSH[_\s][\w.]+)', 'ssh', 'OpenSSH'),
        (r'SSH-[\d.]+-(dropbear[_\s][\w.]+)', 'ssh', 'Dropbear'),
        (r'SSH-', 'ssh', 'SSH'),
        (r'220.*\bvsftpd\s+([\d.]+)', 'ftp', 'vsftpd'),
        (r'220.*\bProFTPD\s+([\d.]+)', 'ftp', 'ProFTPD'),
        (r'220.*\bPure-FTPd', 'ftp', 'Pure-FTPd'),
        (r'220.*\bFileZilla Server', 'ftp', 'FileZilla'),
        (r'220.*\bFTP', 'ftp', 'FTP'),
        (r'Server:\s*Apache/([\d.]+)', 'http', 'Apache'),
        (r'Server:\s*nginx/([\d.]+)', 'http', 'nginx'),
        (r'Server:\s*Microsoft-IIS/([\d.]+)', 'http', 'IIS'),
        (r'Server:\s*lighttpd/([\d.]+)', 'http', 'lighttpd'),
        (r'Server:\s*LiteSpeed', 'http', 'LiteSpeed'),
        (r'Server:\s*Caddy', 'http', 'Caddy'),
        (r'HTTP/[\d.]+\s+\d+', 'http', 'HTTP Server'),
        (r'MySQL', 'mysql', 'MySQL'),
        (r'MariaDB', 'mysql', 'MariaDB'),
        (r'PostgreSQL', 'postgresql', 'PostgreSQL'),
        (r'Microsoft SQL Server', 'mssql', 'MS SQL Server'),
        (r'redis_version:([\d.]+)', 'redis', 'Redis'),
        (r'\+OK.*POP3', 'pop3', 'POP3'),
        (r'\* OK.*IMAP', 'imap', 'IMAP'),
        (r'220.*\bSMTP', 'smtp', 'SMTP'),
        (r'220.*\bPostfix', 'smtp', 'Postfix'),
        (r'220.*\bExim', 'smtp', 'Exim'),
        (r'RFB\s+([\d.]+)', 'vnc', 'VNC'),
        (r'MongoDB', 'mongodb', 'MongoDB'),
    ]

    def detect_service(self, ip, port, banner=None):
        """Detect the service running on a specific port.

        Args:
            ip: Target IP address.
            port: Port number.
            banner: Pre-captured banner string.

        Returns:
            Dict with keys: service_name, service_version, confidence.
        """
        result = {'service_name': None, 'service_version': None, 'confidence': 0}

        banner_result = None
        if banner:
            banner_result = self._identify_by_banner(banner)

        if banner_result and banner_result.get('service_name'):
            result = banner_result
            result['confidence'] = min(result.get('confidence', 80), 100)
        else:
            port_result = self._identify_by_port(port)
            result.update(port_result)

            if port in (80, 443, 8080, 8443):
                http_result = self._probe_http(ip, port)
                if http_result.get('service_name'):
                    result['service_version'] = http_result.get('service_version')
                    result['confidence'] = max(result['confidence'], http_result.get('confidence', 0))
                    if http_result.get('server_header'):
                        result['server_header'] = http_result['server_header']

        return result

    def _identify_by_port(self, port):
        """Identify service by well-known port number.

        Args:
            port: Port number.

        Returns:
            Dict with service_name and confidence.
        """
        if port in self.PORT_SERVICE_MAP:
            name, display = self.PORT_SERVICE_MAP[port]
            return {
                'service_name': name,
                'service_version': None,
                'confidence': 50,
                'display_name': display
            }
        return {'service_name': f'unknown-{port}', 'service_version': None, 'confidence': 10}

    def _identify_by_banner(self, banner):
        """Identify service by analyzing the banner string.

        Args:
            banner: Service banner string.

        Returns:
            Dict with service_name, service_version, and confidence.
        """
        if not banner:
            return {'service_name': None, 'service_version': None, 'confidence': 0}

        for pattern, service, product in self.BANNER_PATTERNS:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                return {
                    'service_name': service,
                    'service_version': f'{product} {version}' if version else product,
                    'confidence': 90 if version else 75,
                    'product': product
                }

        return {'service_name': None, 'service_version': None, 'confidence': 0}

    def _probe_http(self, ip, port):
        """Probe an HTTP/HTTPS port to identify the web server.

        Args:
            ip: Target IP address.
            port: Port number.

        Returns:
            Dict with service details from HTTP response.
        """
        result = {'service_name': None, 'service_version': None, 'confidence': 0}
        scheme = 'https' if port in (443, 8443) else 'http'
        url = f'{scheme}://{ip}:{port}/'

        try:
            resp = requests.get(url, timeout=5, verify=False, allow_redirects=False,
                                headers={'User-Agent': 'VulnVision/1.0 Security Scanner'})
            server = resp.headers.get('Server', '')
            powered_by = resp.headers.get('X-Powered-By', '')

            result['service_name'] = 'http' if scheme == 'http' else 'https'
            result['confidence'] = 70

            if server:
                result['service_version'] = server
                result['server_header'] = server
                result['confidence'] = 85

            if powered_by:
                result['powered_by'] = powered_by

        except requests.exceptions.SSLError:
            result['service_name'] = 'https'
            result['service_version'] = 'SSL/TLS enabled'
            result['confidence'] = 60
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                requests.exceptions.RequestException):
            pass

        return result
