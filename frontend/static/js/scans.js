/**
 * VulnVision - Scans Page JavaScript
 * Handles new scan creation, deletion, and progress polling.
 */

function openNewScanModal() {
    document.getElementById('scanName').value = '';
    document.getElementById('scanTarget').value = '';
    document.getElementById('scanType').value = 'quick';
    document.getElementById('scanPorts').value = '';
    showModal('newScanModal');
}

async function submitNewScan() {
    const name = document.getElementById('scanName').value.trim();
    const target = document.getElementById('scanTarget').value.trim();
    const scanType = document.getElementById('scanType').value;
    const ports = document.getElementById('scanPorts').value.trim();

    if (!name || !target) {
        showToast('Please provide a scan name and target', 'error');
        return;
    }

    const data = {
        name: name,
        target: target,
        scan_type: scanType,
        configuration: {}
    };

    if (ports) {
        data.configuration.ports = ports;
    }

    try {
        const result = await apiPost('/api/scans/', data);
        showToast('Scan started successfully', 'success');
        hideModal('newScanModal');
        setTimeout(() => location.reload(), 1000);
    } catch (error) {
        showToast(`Failed to start scan: ${error.message}`, 'error');
    }
}

async function deleteScan(scanId) {
    if (!confirmAction('Are you sure you want to delete this scan? All associated data will be removed.')) {
        return;
    }

    try {
        await apiDelete(`/api/scans/${scanId}`);
        showToast('Scan deleted', 'success');
        setTimeout(() => location.reload(), 500);
    } catch (error) {
        showToast(`Failed to delete scan: ${error.message}`, 'error');
    }
}

function refreshScanStatus(scanId) {
    apiGet(`/api/scans/${scanId}`)
        .then(data => {
            const scan = data.scan;
            if (scan) {
                updateProgressBar(scanId, scan.progress || 0);
                if (scan.status === 'completed' || scan.status === 'failed') {
                    location.reload();
                }
            }
        })
        .catch(() => {});
}

function updateProgressBar(scanId, progress) {
    const bar = document.querySelector(`[data-scan-id="${scanId}"] .progress-fill`);
    if (bar) {
        bar.style.width = `${progress}%`;
    }
    const text = document.querySelector(`[data-scan-id="${scanId}"] .progress-text`);
    if (text) {
        text.textContent = `${progress}%`;
    }
}

// Auto-refresh running scans
document.addEventListener('DOMContentLoaded', function() {
    const runningScans = document.querySelectorAll('[data-status="running"]');
    if (runningScans.length > 0) {
        startScanAutoRefresh();
    }
});
