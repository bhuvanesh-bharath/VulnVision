/**
 * VulnVision - Main Application JavaScript
 * Core utilities, API helpers, toast notifications, modal management, and sidebar logic.
 */

/* ============================================================
   API Utility Functions
   ============================================================ */

async function apiGet(url) {
    const response = await fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
    });
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Request failed: ${response.status}`);
    }
    return response.json();
}

async function apiPost(url, data) {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || errorData.error || `Request failed: ${response.status}`);
    }
    return response.json();
}

async function apiPatch(url, data) {
    const response = await fetch(url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Request failed: ${response.status}`);
    }
    return response.json();
}

async function apiDelete(url) {
    const response = await fetch(url, {
        method: 'DELETE',
        headers: { 'Accept': 'application/json' }
    });
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Request failed: ${response.status}`);
    }
    return response.json();
}

/* ============================================================
   Toast Notifications
   ============================================================ */

function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;top:1.5rem;right:1.5rem;z-index:10000;display:flex;flex-direction:column;gap:0.5rem;';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const iconMap = {
        success: '✓', error: '✕', warning: '⚠', info: 'ℹ'
    };
    const colorMap = {
        success: '#10b981', error: '#ef4444', warning: '#f59e0b', info: '#3b82f6'
    };

    toast.style.cssText = `
        display:flex;align-items:center;gap:0.75rem;padding:0.875rem 1.25rem;
        background:var(--bg-card,#1a1d29);border:1px solid ${colorMap[type] || colorMap.info};
        border-radius:8px;color:var(--text-primary,#e2e8f0);font-size:0.9rem;
        box-shadow:0 8px 24px rgba(0,0,0,0.4);min-width:280px;max-width:420px;
        animation:slideInRight 0.3s ease;
    `;
    toast.innerHTML = `
        <span style="font-size:1.1rem;color:${colorMap[type]}">${iconMap[type] || iconMap.info}</span>
        <span style="flex:1">${message}</span>
        <button onclick="this.parentElement.remove()" style="background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1.1rem;">&times;</button>
    `;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

/* ============================================================
   Modal Management
   ============================================================ */

function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('open');
        document.body.style.overflow = 'hidden';
    }
}

function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('open');
        document.body.style.overflow = '';
    }
}

/* ============================================================
   Formatting Utilities
   ============================================================ */

function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return dateString;
    return date.toLocaleDateString('en-US', {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function formatDuration(seconds) {
    if (!seconds || seconds < 0) return '-';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
    return `${bytes.toFixed(1)} ${units[i]}`;
}

/* ============================================================
   Confirmation Dialog
   ============================================================ */

function confirmAction(message) {
    return confirm(message);
}

/* ============================================================
   Sidebar Toggle
   ============================================================ */

document.addEventListener('DOMContentLoaded', function() {
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');

    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            if (mainContent) mainContent.classList.toggle('sidebar-collapsed');
        });
    }

    // Close modals on backdrop click
    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
        backdrop.addEventListener('click', function(e) {
            if (e.target === this) {
                this.classList.remove('open');
                document.body.style.overflow = '';
            }
        });
    });

    // Close modals on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-backdrop.open').forEach(modal => {
                modal.classList.remove('open');
            });
            document.body.style.overflow = '';
        }
    });
});

/* ============================================================
   Auto-refresh for Running Scans
   ============================================================ */

let scanRefreshInterval = null;

function startScanAutoRefresh() {
    if (scanRefreshInterval) return;
    scanRefreshInterval = setInterval(async () => {
        try {
            const data = await apiGet('/api/scans/?status=running');
            if (data.scans && data.scans.length > 0) {
                data.scans.forEach(scan => {
                    const progressBar = document.querySelector(`[data-scan-id="${scan.scan_id}"] .progress-fill`);
                    if (progressBar) {
                        progressBar.style.width = `${scan.progress}%`;
                    }
                    const statusBadge = document.querySelector(`[data-scan-id="${scan.scan_id}"] .scan-status`);
                    if (statusBadge) {
                        statusBadge.textContent = scan.status;
                    }
                });
            } else {
                stopScanAutoRefresh();
                location.reload();
            }
        } catch (e) {
            // Silently fail on refresh errors
        }
    }, 5000);
}

function stopScanAutoRefresh() {
    if (scanRefreshInterval) {
        clearInterval(scanRefreshInterval);
        scanRefreshInterval = null;
    }
}

/* ============================================================
   CSS Animations (injected)
   ============================================================ */

const styleSheet = document.createElement('style');
styleSheet.textContent = `
    @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOutRight {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(styleSheet);
