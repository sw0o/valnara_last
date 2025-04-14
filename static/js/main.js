/**
 * Valnara Security Scanner - Main JS file
 * Handles real-time updates, scan status polling, and UI interactions
 */

// Global variables
let pollIntervalId = null;
let vulnerabilityChart = null;

/**
 * Initialize the scan status page
 */
function initScanStatus() {
    const scanStatusElement = document.getElementById('scan-status-container');
    
    if (!scanStatusElement) {
        return; // Not on the scan status page
    }
    
    const scanId = scanStatusElement.dataset.scanId;
    const scanStatus = scanStatusElement.dataset.scanStatus;
    
    console.log(`Initializing scan status page for scan ${scanId} with status ${scanStatus}`);
    
    // Initialize chart if the element exists
    initVulnerabilityChart();
    
    // If scan is running, start polling for updates
    if (scanStatus === 'running') {
        console.log('Scan is running, starting polling');
        startPolling(scanId);
    }
    
    // Handle scan start form submission
    const startScanForm = document.getElementById('start-scan-form');
    if (startScanForm) {
        startScanForm.addEventListener('submit', function(event) {
            event.preventDefault();
            startScan(scanId);
        });
    }
    
    // Show manual results link after 15 seconds for running scans
    if (scanStatus === 'running') {
        setTimeout(() => {
            const manualLink = document.getElementById('manual-results-link');
            if (manualLink) {
                manualLink.style.display = 'block';
            }
        }, 35000);
    }
}

/**
 * Initialize the vulnerability chart on the scan status page
 */
function initVulnerabilityChart() {
    const chartElement = document.getElementById('vulnerabilityChart');
    
    if (!chartElement) {
        return; // Chart element not found
    }
    
    const ctx = chartElement.getContext('2d');
    vulnerabilityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low', 'Informational'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#dc3545', // High - red
                    '#ffc107', // Medium - yellow
                    '#17a2b8', // Low - cyan
                    '#198754'  // Info - green
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            },
            cutout: '70%'
        }
    });
}

/**
 * Start the security scan
 * @param {string} scanId - The ID of the scan to start
 */
function startScan(scanId) {
    const startButton = document.querySelector('#start-scan-form button[type="submit"]');
    const originalButtonText = startButton.innerHTML;
    
    // Update button state
    startButton.disabled = true;
    startButton.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Starting scan...`;
    
    // Update status badge immediately
    const statusBadge = document.querySelector('h5.mt-3 .badge');
    if (statusBadge) {
        statusBadge.textContent = 'Running';
        statusBadge.className = 'badge bg-primary pulse';
    }
    
    console.log(`Starting scan ${scanId}`);
    
    // Send start scan request
    fetch(`/start_scan/${scanId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log('Scan start response:', data);
        
        if (data.status === 'completed') {
            // Scan already completed, force redirect to results
            window.location.href = data.redirect;
        } else {
            // Just reload the page to show updated status
            window.location.reload();
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        alert('Error starting scan. Please try again.');
        startButton.disabled = false;
        startButton.innerHTML = originalButtonText;
        
        // Revert status badge if there was an error
        if (statusBadge) {
            statusBadge.textContent = 'Pending';
            statusBadge.className = 'badge bg-secondary';
        }
    });
}

/**
 * Start polling for scan status updates
 * @param {string} scanId - The ID of the scan to poll for
 */
function startPolling(scanId) {
    // Clear any existing interval
    if (pollIntervalId) {
        clearInterval(pollIntervalId);
    }
    
    // Poll immediately
    pollScanStatus(scanId);
    
    // Then set up interval (every 3 seconds)
    pollIntervalId = setInterval(() => {
        pollScanStatus(scanId);
    }, 10000);
    
    console.log(`Polling started for scan ${scanId}`);
}

/**
 * Stop polling for scan status updates
 */
function stopPolling() {
    if (pollIntervalId) {
        clearInterval(pollIntervalId);
        pollIntervalId = null;
        console.log('Polling stopped');
    }
}

/**
 * Safely redirect to results page
 * @param {string} redirectUrl - URL to redirect to
 * @param {string} scanId - Scan ID (used as fallback)
 */
// In the redirectToResults function in main.js

function redirectToResults(redirectUrl, scanId) {
    console.log('Attempting to redirect to results...');
    
    // Don't make another API call, just redirect directly
    setTimeout(() => {
        try {
            if (redirectUrl) {
                console.log(`Redirecting to: ${redirectUrl}`);
                window.location.href = redirectUrl;
            } else {
                console.log('No redirect URL provided, using fallback');
                window.location.href = `/results/${scanId}`;
            }
        } catch (e) {
            console.error('Redirect error:', e);
            // Show manual redirect button
            const manualLink = document.getElementById('manual-results-link');
            if (manualLink) {
                manualLink.style.display = 'block';
            }
        }
    }, 1000); // Give a 1 second delay to ensure data is saved
}

/**
 * Poll for scan status updates
 * @param {string} scanId - The ID of the scan to poll for
 */
function pollScanStatus(scanId) {
    console.log(`Polling scan status for ${scanId}`);
    
    fetch(`/api/scan_status/${scanId}`)
        .then(response => response.json())
        .then(data => {
            console.log('Polling response:', data);
            
            // Update progress if available
            if (data.progress !== undefined) {
                updateProgressBar(data.progress);
            }
            
            // Check scan status
            if (data.status === 'running') {
                // Scan still running, check for results
                if (data.results) {
                    updateVulnerabilityFeed(data.results.alerts || []);
                    updateVulnerabilitySummary(data.results.summary || {});
                }
            } else if (data.status === 'completed') {
                // Scan completed, redirect to results
                console.log('Scan completed, stopping polling and redirecting');
                stopPolling();
                
                // Show completed status before redirect
                const progressBar = document.getElementById('scan-progress');
                if (progressBar) {
                    progressBar.style.width = '100%';
                    progressBar.textContent = '100% Complete';
                    progressBar.classList.remove('progress-bar-animated');
                    progressBar.classList.add('bg-success');
                }
                
                // Redirect to results page
                redirectToResults(data.redirect, scanId);
            } else if (data.status === 'error') {
                // Display error
                console.error('Scan error:', data.message);
                stopPolling();
                alert('Scan error: ' + data.message);
                window.location.reload();
            }
        })
        .catch(error => {
            console.error('Error polling scan status:', error);
            // Don't stop polling on error, just log it and continue
        });
}

/**
 * Update the scan progress bar
 * @param {number} progress - Percentage of scan completion (0-100)
 */
function updateProgressBar(progress) {
    const progressBar = document.getElementById('scan-progress');
    
    if (!progressBar) {
        return;
    }
    
    // Ensure progress is between 0 and 100
    const safeProgress = Math.min(100, Math.max(0, progress));
    
    // Update progress bar
    progressBar.style.width = `${safeProgress}%`;
    progressBar.textContent = `${safeProgress}% Complete`;
    
    // If progress is 100%, add success class
    if (safeProgress === 100) {
        progressBar.classList.remove('progress-bar-animated');
        progressBar.classList.add('bg-success');
    }
}

/**
 * Update the vulnerability feed with new findings
 * @param {Array} vulnerabilities - Array of vulnerability objects
 */
function updateVulnerabilityFeed(vulnerabilities) {
    const feedContainer = document.getElementById('vulnerabilities-feed');
    
    if (!feedContainer) {
        return;
    }
    
    console.log(`Updating vulnerability feed with ${vulnerabilities.length} items`);
    
    if (vulnerabilities.length === 0) {
        feedContainer.innerHTML = `
            <div class="list-group-item text-center py-4">
                <i class="bi bi-shield-check text-success fs-1 mb-3"></i>
                <p class="mb-0">No vulnerabilities detected yet.</p>
            </div>
        `;
        return;
    }
    
    // Check if we have new vulnerabilities to add
    const currentCount = feedContainer.querySelectorAll('.vulnerability-item').length;
    
    if (currentCount === vulnerabilities.length) {
        // No new vulnerabilities, nothing to update
        return;
    }
    
    // Clear container if it only has the loading/no vulnerabilities message
    if (currentCount === 0 || !feedContainer.querySelector('.vulnerability-item')) {
        feedContainer.innerHTML = '';
    }
    
    // Add new vulnerabilities
    for (let i = currentCount; i < vulnerabilities.length; i++) {
        const vuln = vulnerabilities[i];
        
        let severityClass = '';
        let severityIcon = '';
        
        switch(vuln.risk) {
            case 'High':
                severityClass = 'text-danger';
                severityIcon = 'bi-exclamation-triangle-fill';
                break;
            case 'Medium':
                severityClass = 'text-warning';
                severityIcon = 'bi-exclamation-triangle';
                break;
            case 'Low':
                severityClass = 'text-info';
                severityIcon = 'bi-info-circle';
                break;
            default:
                severityClass = 'text-success';
                severityIcon = 'bi-info';
        }
        
        const vulnerabilityItem = document.createElement('div');
        vulnerabilityItem.className = 'list-group-item vulnerability-item fade-in';
        vulnerabilityItem.innerHTML = `
            <div class="d-flex justify-content-between align-items-center mb-2">
                <h6 class="mb-0 ${severityClass}">
                    <i class="bi ${severityIcon} me-2"></i>${vuln.name}
                </h6>
                <span class="badge bg-${vuln.risk === 'High' ? 'danger' : 
                                vuln.risk === 'Medium' ? 'warning' : 
                                vuln.risk === 'Low' ? 'info' : 'success'}">${vuln.risk}</span>
            </div>
            <p class="mb-0 small text-muted">${vuln.url}</p>
            ${vuln.solution ? `
            <div class="mt-2">
                <p class="mb-0 fw-bold">Remediation:</p>
                <p class="mb-0 small">${vuln.solution}</p>
            </div>
            ` : ''}
        `;
        
        feedContainer.appendChild(vulnerabilityItem);
    }
    
    // Scroll to the bottom to show new items
    feedContainer.scrollTop = feedContainer.scrollHeight;
}

/**
 * Update vulnerability counts and chart
 * @param {Object} summary - Object with counts for each severity level
 */
function updateVulnerabilitySummary(summary) {
    console.log('Updating vulnerability summary:', summary);
    
    // Update count elements
    const highCount = document.getElementById('high-count');
    const mediumCount = document.getElementById('medium-count');
    const lowCount = document.getElementById('low-count');
    const infoCount = document.getElementById('info-count');
    
    if (highCount) highCount.textContent = summary.High || 0;
    if (mediumCount) mediumCount.textContent = summary.Medium || 0;
    if (lowCount) lowCount.textContent = summary.Low || 0;
    if (infoCount) infoCount.textContent = summary.Informational || 0;
    
    // Update chart if it exists
    if (vulnerabilityChart) {
        vulnerabilityChart.data.datasets[0].data = [
            summary.High || 0,
            summary.Medium || 0,
            summary.Low || 0,
            summary.Informational || 0
        ];
        vulnerabilityChart.update();
    }
}

/**
 * Initialize the results page
 */
function initResultsPage() {
    const resultsContainer = document.getElementById('results-container');
    
    if (!resultsContainer) {
        return; // Not on the results page
    }
    
    console.log('Initializing results page');
    
    // Initialize chart
    const chartElement = document.getElementById('vulnerabilityChart');
    if (chartElement) {
        const high = parseInt(chartElement.dataset.high || 0);
        const medium = parseInt(chartElement.dataset.medium || 0);
        const low = parseInt(chartElement.dataset.low || 0);
        const info = parseInt(chartElement.dataset.info || 0);
        
        console.log(`Chart data: High=${high}, Medium=${medium}, Low=${low}, Info=${info}`);
        
        const ctx = chartElement.getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['High', 'Medium', 'Low', 'Informational'],
                datasets: [{
                    data: [high, medium, low, info],
                    backgroundColor: [
                        '#dc3545', // High - red
                        '#ffc107', // Medium - yellow
                        '#17a2b8', // Low - cyan
                        '#198754'  // Info - green
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                },
                cutout: '70%'
            }
        });
    }
}

// Initialize when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing Valnara UI');
    
    // Check which page we're on and initialize accordingly
    if (document.getElementById('scan-status-container')) {
        initScanStatus();
    } else if (document.getElementById('results-container')) {
        initResultsPage();
    }
    
    // Enable tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
});