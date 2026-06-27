/**
 * VulnVision - Reports Page JavaScript
 * Handles report generation, download, and deletion.
 */

function openReportModal() {
    document.getElementById('reportName').value = '';
    document.getElementById('reportScanId').value = '';
    document.getElementById('reportType').value = 'full';
    document.getElementById('reportFormat').value = 'pdf';
    showModal('reportModal');
}

async function submitReport() {
    const name = document.getElementById('reportName').value.trim();
    const scanId = parseInt(document.getElementById('reportScanId').value);
    const reportType = document.getElementById('reportType').value;
    const format = document.getElementById('reportFormat').value;

    if (!name || !scanId) {
        showToast('Please fill all required fields', 'error');
        return;
    }

    const data = {
        name: name,
        scan_id: scanId,
        report_type: reportType,
        format: format,
        include_findings: true,
        include_attack_paths: true,
        include_remediation: true,
        include_executive_summary: true
    };

    try {
        const result = await apiPost('/api/reports/', data);
        showToast('Report generated successfully', 'success');
        hideModal('reportModal');
        setTimeout(() => location.reload(), 1000);
    } catch (error) {
        showToast(`Failed to generate report: ${error.message}`, 'error');
    }
}

function downloadReport(reportId) {
    window.open(`/api/reports/${reportId}/download`, '_blank');
}

async function deleteReport(reportId) {
    if (!confirmAction('Are you sure you want to delete this report?')) {
        return;
    }

    try {
        await apiDelete(`/api/reports/${reportId}`);
        showToast('Report deleted', 'success');
        setTimeout(() => location.reload(), 500);
    } catch (error) {
        showToast(`Failed to delete report: ${error.message}`, 'error');
    }
}
