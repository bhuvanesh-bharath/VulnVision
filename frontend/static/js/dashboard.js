/**
 * VulnVision - Dashboard Page JavaScript
 * Initializes dashboard charts and handles auto-refresh.
 */

document.addEventListener('DOMContentLoaded', function() {
    initDashboardCharts();
    setInterval(refreshDashboard, 30000);
});

function initDashboardCharts() {
    initSeverityChart();
    initTrendChart();
}

function initSeverityChart() {
    const el = document.getElementById('severityChart');
    if (!el) return;

    const dataEl = document.getElementById('severityData');
    if (!dataEl) return;

    let data;
    try {
        data = JSON.parse(dataEl.textContent);
    } catch (e) {
        return;
    }

    createDoughnutChart('severityChart', {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
            data: [
                data.critical || 0,
                data.high || 0,
                data.medium || 0,
                data.low || 0,
                data.info || 0,
            ],
            backgroundColor: [
                chartColorScheme.critical,
                chartColorScheme.high,
                chartColorScheme.medium,
                chartColorScheme.low,
                chartColorScheme.info,
            ],
            borderWidth: 0,
            hoverOffset: 8,
        }]
    });
}

function initTrendChart() {
    const el = document.getElementById('trendChart');
    if (!el) return;

    const dataEl = document.getElementById('trendData');
    if (!dataEl) return;

    let data;
    try {
        data = JSON.parse(dataEl.textContent);
    } catch (e) {
        return;
    }

    if (!data.labels || data.labels.length === 0) return;

    createLineChart('trendChart', data.labels, [{
        label: 'Vulnerabilities',
        data: data.values,
        borderColor: chartColorScheme.primary,
        backgroundColor: 'rgba(99, 102, 241, 0.1)',
        fill: true,
    }]);
}

async function refreshDashboard() {
    try {
        const data = await apiGet('/api/scans/?status=running');
        if (data.scans && data.scans.length > 0) {
            const indicator = document.querySelector('.status-indicator');
            if (indicator) {
                indicator.classList.add('active');
                indicator.title = `${data.scans.length} scan(s) running`;
            }
        }
    } catch (e) {
        // Silent fail
    }
}
