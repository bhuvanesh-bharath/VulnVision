"""
VulnVision OS Fingerprint Service.
Estimates the operating system of a host based on open ports, banners, and TTL values.
"""
import re
import subprocess
import platform
from backend.utils.logger import get_scan_logger

logger = get_scan_logger()


class OSFingerprint:
    """Estimates the operating system of discovered hosts."""

    WINDOWS_INDICATORS = {
        'ports': {135, 139, 445, 3389, 5985, 5986, 49152, 49153, 49154},
        'banners': ['microsoft', 'windows', 'iis', 'win32', 'win64', 'ms-wbt-server'],
        'ttl_range': (120, 128)
    }

    LINUX_INDICATORS = {
        'ports': {22, 111, 2049, 631},
        'banners': ['ubuntu', 'debian', 'centos', 'fedora', 'red hat', 'openssh',
                     'apache', 'nginx', 'linux'],
        'ttl_range': (60, 64)
    }

    MACOS_INDICATORS = {
        'ports': {22, 548, 5900, 3689, 5353},
        'banners': ['darwin', 'macos', 'mac os x', 'apple'],
        'ttl_range': (60, 64)
    }

    NETWORK_DEVICE_INDICATORS = {
        'ports': {22, 23, 80, 443, 161, 162},
        'banners': ['cisco', 'juniper', 'mikrotik', 'fortigate', 'panos',
                     'sonicwall', 'checkpoint'],
        'ttl_range': (250, 255)
    }

    def estimate_os(self, ip, open_ports, banners):
        """Estimate the operating system of a host.

        Args:
            ip: Target IP address.
            open_ports: List of open port numbers.
            banners: Dict mapping port numbers to banner strings.

        Returns:
            Dict with os_guess, os_family, and confidence.
        """
        candidates = []

        port_candidates = self._analyze_ports(open_ports)
        candidates.extend(port_candidates)

        banner_candidates = self._analyze_banners(banners)
        candidates.extend(banner_candidates)

        ttl_guess = self._analyze_ttl(ip)
        if ttl_guess:
            candidates.append({'os': ttl_guess, 'confidence': 30, 'source': 'ttl'})

        return self._calculate_confidence(candidates)

    def _analyze_ports(self, open_ports):
        """Analyze open ports to guess OS.

        Args:
            open_ports: List of open port numbers.

        Returns:
            List of OS candidate dicts.
        """
        candidates = []
        port_set = set(open_ports)

        win_match = len(port_set & self.WINDOWS_INDICATORS['ports'])
        if win_match >= 2:
            candidates.append({
                'os': 'Windows', 'confidence': min(win_match * 15, 70),
                'source': 'ports', 'details': f'{win_match} Windows-associated ports'
            })
        if 3389 in port_set:
            candidates.append({
                'os': 'Windows', 'confidence': 60, 'source': 'ports',
                'details': 'RDP port 3389 detected'
            })

        linux_match = len(port_set & self.LINUX_INDICATORS['ports'])
        has_ssh = 22 in port_set
        has_no_windows = len(port_set & self.WINDOWS_INDICATORS['ports']) == 0

        if has_ssh and has_no_windows:
            candidates.append({
                'os': 'Linux', 'confidence': 45,
                'source': 'ports', 'details': 'SSH without Windows ports'
            })
        if linux_match >= 2:
            candidates.append({
                'os': 'Linux', 'confidence': min(linux_match * 15, 65),
                'source': 'ports', 'details': f'{linux_match} Linux-associated ports'
            })

        mac_match = len(port_set & self.MACOS_INDICATORS['ports'])
        if 548 in port_set:
            candidates.append({
                'os': 'macOS', 'confidence': 55,
                'source': 'ports', 'details': 'AFP port 548 detected'
            })
        if mac_match >= 3:
            candidates.append({
                'os': 'macOS', 'confidence': 50,
                'source': 'ports', 'details': f'{mac_match} macOS-associated ports'
            })

        net_match = len(port_set & self.NETWORK_DEVICE_INDICATORS['ports'])
        if net_match >= 3 and 22 in port_set and 23 in port_set:
            candidates.append({
                'os': 'Network Device', 'confidence': 55,
                'source': 'ports', 'details': 'SSH+Telnet+HTTP common in network devices'
            })

        return candidates

    def _analyze_banners(self, banners):
        """Analyze service banners for OS indicators.

        Args:
            banners: Dict mapping port numbers to banner strings.

        Returns:
            List of OS candidate dicts.
        """
        candidates = []
        if not banners:
            return candidates

        all_banners = ' '.join(str(b) for b in banners.values() if b).lower()

        for keyword in self.WINDOWS_INDICATORS['banners']:
            if keyword in all_banners:
                candidates.append({
                    'os': 'Windows', 'confidence': 75,
                    'source': 'banner', 'details': f'Keyword "{keyword}" found in banner'
                })
                version_match = re.search(r'windows\s+(server\s+)?(\d{4}|\d+\.?\d*)', all_banners)
                if version_match:
                    ver = version_match.group(0).title()
                    candidates.append({
                        'os': ver, 'confidence': 85,
                        'source': 'banner', 'details': f'Version detected: {ver}'
                    })
                break

        for keyword in self.LINUX_INDICATORS['banners']:
            if keyword in all_banners:
                candidates.append({
                    'os': 'Linux', 'confidence': 70,
                    'source': 'banner', 'details': f'Keyword "{keyword}" found in banner'
                })
                for distro in ['ubuntu', 'debian', 'centos', 'fedora', 'red hat']:
                    if distro in all_banners:
                        candidates.append({
                            'os': f'Linux ({distro.title()})', 'confidence': 80,
                            'source': 'banner', 'details': f'Distribution: {distro.title()}'
                        })
                        break
                break

        for keyword in self.MACOS_INDICATORS['banners']:
            if keyword in all_banners:
                candidates.append({
                    'os': 'macOS', 'confidence': 75,
                    'source': 'banner', 'details': f'Keyword "{keyword}" found'
                })
                break

        for keyword in self.NETWORK_DEVICE_INDICATORS['banners']:
            if keyword in all_banners:
                candidates.append({
                    'os': f'Network Device ({keyword.title()})', 'confidence': 80,
                    'source': 'banner', 'details': f'Device vendor: {keyword.title()}'
                })
                break

        return candidates

    def _analyze_ttl(self, ip):
        """Analyze TTL value from ping response to guess OS family.

        Args:
            ip: Target IP address.

        Returns:
            OS family string or None.
        """
        try:
            is_windows = platform.system().lower() == 'windows'
            if is_windows:
                cmd = ['ping', '-n', '1', '-w', '2000', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '2', ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                ttl_match = re.search(r'TTL[=:](\d+)', result.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if 120 <= ttl <= 128:
                        return 'Windows'
                    elif 60 <= ttl <= 64:
                        return 'Linux/macOS'
                    elif 250 <= ttl <= 255:
                        return 'Network Device'
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return None

    def _calculate_confidence(self, candidates):
        """Calculate the best OS guess from all candidates.

        Args:
            candidates: List of candidate dicts with os, confidence, source.

        Returns:
            Dict with os_guess, os_family, and confidence.
        """
        if not candidates:
            return {'os_guess': 'Unknown', 'os_family': 'Unknown', 'confidence': 0}

        scores = {}
        for c in candidates:
            os_name = c['os']
            family = os_name.split('(')[0].strip().split(' ')[0]
            if family not in scores:
                scores[family] = {'total_confidence': 0, 'best_guess': os_name, 'best_conf': 0}
            scores[family]['total_confidence'] += c['confidence']
            if c['confidence'] > scores[family]['best_conf']:
                scores[family]['best_conf'] = c['confidence']
                scores[family]['best_guess'] = os_name

        best_family = max(scores, key=lambda k: scores[k]['total_confidence'])
        best = scores[best_family]

        return {
            'os_guess': best['best_guess'],
            'os_family': best_family,
            'confidence': min(best['best_conf'], 95)
        }
