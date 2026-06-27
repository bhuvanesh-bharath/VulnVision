"""
VulnVision API Endpoint Tests.
Tests for all Flask API routes and page endpoints.
"""
import json
import pytest


class TestPageRoutes:
    """Test HTML page routes return 200."""

    def test_dashboard_page(self, client):
        response = client.get('/')
        assert response.status_code == 200

    def test_scans_page(self, client):
        response = client.get('/scans')
        assert response.status_code == 200

    def test_hosts_page(self, client):
        response = client.get('/hosts')
        assert response.status_code == 200

    def test_vulnerabilities_page(self, client):
        response = client.get('/vulnerabilities')
        assert response.status_code == 200

    def test_attack_paths_page(self, client):
        response = client.get('/attack-paths')
        assert response.status_code == 200

    def test_security_debt_page(self, client):
        response = client.get('/security-debt')
        assert response.status_code == 200

    def test_reports_page(self, client):
        response = client.get('/reports')
        assert response.status_code == 200

    def test_remediation_page(self, client):
        response = client.get('/remediation')
        assert response.status_code == 200


class TestScanAPI:
    """Test /api/scans endpoints."""

    def test_list_scans(self, client):
        response = client.get('/api/scans/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scans' in data

    def test_create_scan(self, client):
        response = client.post('/api/scans/', json={
            'name': 'Test Scan',
            'target': '192.168.1.1',
            'scan_type': 'quick'
        })
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'scan' in data
        assert data['scan']['name'] == 'Test Scan'

    def test_create_scan_missing_fields(self, client):
        response = client.post('/api/scans/', json={})
        assert response.status_code == 400

    def test_get_scan(self, client, sample_scan):
        response = client.get(f'/api/scans/{sample_scan.scan_id}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scan' in data

    def test_get_scan_not_found(self, client):
        response = client.get('/api/scans/nonexistent-uuid')
        assert response.status_code == 404

    def test_scan_statistics(self, client):
        response = client.get('/api/scans/statistics')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_scans' in data

    def test_delete_scan(self, client, sample_scan):
        response = client.delete(f'/api/scans/{sample_scan.scan_id}')
        assert response.status_code == 200


class TestHostAPI:
    """Test /api/hosts endpoints."""

    def test_list_hosts(self, client):
        response = client.get('/api/hosts/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'hosts' in data

    def test_get_host(self, client, sample_host):
        response = client.get(f'/api/hosts/{sample_host.host_id}')
        assert response.status_code == 200

    def test_host_statistics(self, client):
        response = client.get('/api/hosts/statistics')
        assert response.status_code == 200


class TestVulnerabilityAPI:
    """Test /api/vulnerabilities endpoints."""

    def test_list_vulnerabilities(self, client):
        response = client.get('/api/vulnerabilities/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'vulnerabilities' in data

    def test_vulnerability_statistics(self, client):
        response = client.get('/api/vulnerabilities/statistics')
        assert response.status_code == 200

    def test_severity_distribution(self, client):
        response = client.get('/api/vulnerabilities/severity-distribution')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'distribution' in data

    def test_update_vulnerability_status(self, client, sample_vulnerability):
        response = client.patch(
            f'/api/vulnerabilities/{sample_vulnerability.vuln_id}/status',
            json={'status': 'resolved'}
        )
        assert response.status_code == 200


class TestAttackPathAPI:
    """Test /api/attack-paths endpoints."""

    def test_list_attack_paths(self, client):
        response = client.get('/api/attack-paths/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'attack_paths' in data

    def test_attack_path_statistics(self, client):
        response = client.get('/api/attack-paths/statistics')
        assert response.status_code == 200


class TestSecurityDebtAPI:
    """Test /api/security-debt endpoints."""

    def test_get_latest_debt(self, client):
        response = client.get('/api/security-debt/')
        assert response.status_code == 200

    def test_debt_history(self, client):
        response = client.get('/api/security-debt/history')
        assert response.status_code == 200

    def test_debt_trend(self, client):
        response = client.get('/api/security-debt/trend')
        assert response.status_code == 200


class TestReportAPI:
    """Test /api/reports endpoints."""

    def test_list_reports(self, client):
        response = client.get('/api/reports/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'reports' in data


class TestRemediationAPI:
    """Test /api/remediation endpoints."""

    def test_get_remediation(self, client):
        response = client.get('/api/remediation/')
        assert response.status_code == 200

    def test_get_priorities(self, client):
        response = client.get('/api/remediation/priorities')
        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling."""

    def test_404_handler(self, client):
        response = client.get('/api/nonexistent-endpoint')
        assert response.status_code == 404
