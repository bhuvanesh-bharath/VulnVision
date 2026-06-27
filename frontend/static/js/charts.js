/**
 * VulnVision - Shared Chart Utilities
 * Chart.js configuration, color schemes, and reusable chart creation functions.
 */

const chartColorScheme = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#f59e0b',
    low: '#3b82f6',
    info: '#6b7280',
    success: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    primary: '#6366f1',
    primaryLight: '#818cf8',
    background: '#0f1117',
    cardBg: '#1a1d29',
    border: '#2d3148',
    textPrimary: '#e2e8f0',
    textSecondary: '#94a3b8',
    gridColor: 'rgba(45, 49, 72, 0.6)',
};

const defaultChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            labels: {
                color: chartColorScheme.textPrimary,
                font: { family: 'Inter, sans-serif', size: 12 },
                padding: 16,
            }
        },
        tooltip: {
            backgroundColor: chartColorScheme.cardBg,
            titleColor: chartColorScheme.textPrimary,
            bodyColor: chartColorScheme.textSecondary,
            borderColor: chartColorScheme.border,
            borderWidth: 1,
            cornerRadius: 8,
            padding: 12,
            titleFont: { family: 'Inter, sans-serif', weight: '600' },
            bodyFont: { family: 'Inter, sans-serif' },
        }
    },
    scales: {
        x: {
            ticks: { color: chartColorScheme.textSecondary, font: { family: 'Inter, sans-serif', size: 11 } },
            grid: { color: chartColorScheme.gridColor, drawBorder: false }
        },
        y: {
            ticks: { color: chartColorScheme.textSecondary, font: { family: 'Inter, sans-serif', size: 11 } },
            grid: { color: chartColorScheme.gridColor, drawBorder: false },
            beginAtZero: true
        }
    }
};

/**
 * Create a doughnut chart.
 */
function createDoughnutChart(canvasId, data, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
        type: 'doughnut',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: chartColorScheme.textPrimary,
                        font: { family: 'Inter, sans-serif', size: 12 },
                        padding: 16,
                        usePointStyle: true,
                        pointStyleWidth: 10,
                    }
                },
                tooltip: defaultChartOptions.plugins.tooltip,
            },
            ...options,
        }
    });
}

/**
 * Create a line chart.
 */
function createLineChart(canvasId, labels, datasets, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const formattedDatasets = datasets.map((ds, i) => ({
        ...ds,
        borderWidth: 2,
        pointRadius: 3,
        pointHoverRadius: 5,
        tension: 0.3,
        fill: ds.fill !== undefined ? ds.fill : false,
    }));

    return new Chart(ctx, {
        type: 'line',
        data: { labels, datasets: formattedDatasets },
        options: {
            ...defaultChartOptions,
            ...options,
        }
    });
}

/**
 * Create a bar chart.
 */
function createBarChart(canvasId, labels, data, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor: [
                    chartColorScheme.critical,
                    chartColorScheme.high,
                    chartColorScheme.medium,
                    chartColorScheme.low,
                    chartColorScheme.info,
                ],
                borderRadius: 4,
                borderSkipped: false,
            }]
        },
        options: {
            ...defaultChartOptions,
            plugins: {
                ...defaultChartOptions.plugins,
                legend: { display: false }
            },
            ...options,
        }
    });
}

/**
 * Create a gauge-style chart (half doughnut).
 */
function createGaugeChart(canvasId, value, max = 100, colors = null) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    if (!colors) {
        colors = value >= 70 ? chartColorScheme.danger :
                 value >= 40 ? chartColorScheme.warning :
                 chartColorScheme.success;
    }

    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [value, max - value],
                backgroundColor: [colors, chartColorScheme.border],
                borderWidth: 0,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            rotation: -90,
            circumference: 180,
            cutout: '75%',
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
        }
    });
}
