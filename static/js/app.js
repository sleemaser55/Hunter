/**
 * Security Hunter - Common JavaScript functionality
 */

// Global configuration
const APP_CONFIG = {
    refreshInterval: 60000, // 1 minute
    maxRetries: 3,
    animationDuration: 300
};

// Initialize common functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    initializeTooltips();

    // Initialize error handling for AJAX requests
    setupAjaxErrorHandling();
});

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Set up global error handling for AJAX requests
 */
function setupAjaxErrorHandling() {
    document.addEventListener('ajaxError', function(event) {
        const error = event.detail;
        console.error('AJAX Error:', error);
        
        // Display error notification
        showNotification('Error', error.message || 'An error occurred during the request.', 'danger');
    });
}

/**
 * Show a notification message
 * @param {string} title - Notification title
 * @param {string} message - Notification message
 * @param {string} type - Bootstrap alert type (success, info, warning, danger)
 * @param {number} duration - Duration to show in milliseconds (0 for permanent)
 */
function showNotification(title, message, type = 'info', duration = 5000) {
    const notificationContainer = document.getElementById('notification-container');
    
    // Create container if it doesn't exist
    if (!notificationContainer) {
        const container = document.createElement('div');
        container.id = 'notification-container';
        container.className = 'position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '5000';
        document.body.appendChild(container);
    }
    
    // Create notification element
    const id = 'notification-' + Date.now();
    const html = `
        <div id="${id}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-${type} text-white">
                <strong class="me-auto">${title}</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    // Add to container
    document.getElementById('notification-container').insertAdjacentHTML('beforeend', html);
    
    // Initialize and show toast
    const toastElement = document.getElementById(id);
    const toast = new bootstrap.Toast(toastElement, {
        autohide: duration > 0,
        delay: duration
    });
    
    toast.show();
    
    // Remove from DOM after hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

/**
 * Format a date string for display
 * @param {string} dateString - Date string to format
 * @returns {string} Formatted date string
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
        return dateString;
    }
    
    return date.toLocaleString();
}

/**
 * Format a number with commas for thousands separator
 * @param {number} num - Number to format
 * @returns {string} Formatted number string
 */
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Truncate a string to a specified length with ellipsis
 * @param {string} str - String to truncate
 * @param {number} length - Maximum length
 * @returns {string} Truncated string
 */
function truncateString(str, length = 100) {
    if (!str || str.length <= length) {
        return str;
    }
    
    return str.substring(0, length) + '...';
}

/**
 * Check if Splunk is connected
 * @returns {Promise<boolean>} Promise resolving to connection status
 */
function checkSplunkConnection() {
    return fetch('/splunk/test')
        .then(response => response.json())
        .then(data => {
            const statusBadge = document.getElementById('splunk-status');
            if (statusBadge) {
                if (data.success) {
                    statusBadge.className = 'badge bg-success me-2';
                    statusBadge.textContent = 'Connected';
                } else {
                    statusBadge.className = 'badge bg-danger me-2';
                    statusBadge.textContent = 'Disconnected';
                }
            }
            return data.success;
        })
        .catch(error => {
            console.error('Error checking Splunk connection:', error);
            const statusBadge = document.getElementById('splunk-status');
            if (statusBadge) {
                statusBadge.className = 'badge bg-danger me-2';
                statusBadge.textContent = 'Error';
            }
            return false;
        });
}

/**
 * Escape HTML special characters
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Download data as a file
 * @param {string} content - File content
 * @param {string} fileName - File name
 * @param {string} contentType - Content MIME type
 */
function downloadFile(content, fileName, contentType) {
    const a = document.createElement('a');
    const file = new Blob([content], {type: contentType});
    a.href = URL.createObjectURL(file);
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(a.href);
}

/**
 * Convert data to CSV format
 * @param {Array} data - Array of objects to convert
 * @param {Array} headers - Array of header names
 * @returns {string} CSV string
 */
function convertToCSV(data, headers) {
    if (!data || !data.length) {
        return '';
    }
    
    const headerRow = headers.join(',');
    const rows = data.map(item => {
        return headers.map(header => {
            // Get property by header
            let value = item[header];
            
            // Handle different types of values
            if (value === null || value === undefined) {
                return '';
            } else if (typeof value === 'object') {
                value = JSON.stringify(value);
            } else {
                value = String(value);
            }
            
            // Escape quotes and wrap in quotes
            value = value.replace(/"/g, '""');
            return `"${value}"`;
        }).join(',');
    });
    
    return [headerRow, ...rows].join('\n');
}
