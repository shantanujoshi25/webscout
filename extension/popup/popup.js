document.addEventListener('DOMContentLoaded', function() {
  // Get DOM elements
  const scanButton = document.getElementById('scanButton');
  const rescanButton = document.getElementById('rescanButton');
  const exportButton = document.getElementById('exportButton');
  const settingsButton = document.getElementById('settingsButton');
  const helpButton = document.getElementById('helpButton');
  const statusArea = document.getElementById('statusArea');
  const resultsArea = document.getElementById('resultsArea');
  const summaryArea = document.getElementById('summaryArea');
  const vulnerabilitiesArea = document.getElementById('vulnerabilitiesArea');
  const loadingArea = document.getElementById('loadingArea');
  const helpModal = document.getElementById('helpModal');
  const settingsModal = document.getElementById('settingsModal');
  const saveSettingsButton = document.getElementById('saveSettings');
  const filterButtons = document.querySelectorAll('.filter-button');
  const progressFill = document.querySelector('.progress-fill');
  const closeButtons = document.querySelectorAll('.close-button');

  // Settings
  let settings = {
    scanDepth: 'standard',
    aiDetection: true,
    autoScan: false
  };

  // Load settings from storage
  chrome.storage.local.get(['settings'], function(result) {
    if (result.settings) {
      settings = result.settings;
      updateSettingsUI();
    }
  });

  // Update settings UI
  function updateSettingsUI() {
    document.getElementById('scanDepth').value = settings.scanDepth;
    document.getElementById('aiDetection').checked = settings.aiDetection;
    document.getElementById('autoScan').checked = settings.autoScan;
  }

  // Save settings
  function saveSettings() {
    settings.scanDepth = document.getElementById('scanDepth').value;
    settings.aiDetection = document.getElementById('aiDetection').checked;
    settings.autoScan = document.getElementById('autoScan').checked;
    
    chrome.storage.local.set({ settings: settings }, function() {
      settingsModal.style.display = 'none';
      showNotification('Settings saved successfully');
    });
  }

  // Init event listeners
  function initEventListeners() {
    // Scan button
    scanButton.addEventListener('click', startScan);
    
    // Rescan button
    if (rescanButton) {
      rescanButton.addEventListener('click', startScan);
    }
    
    // Export button
    if (exportButton) {
      exportButton.addEventListener('click', exportResults);
    }
    
    // Settings button
    if (settingsButton) {
      settingsButton.addEventListener('click', function() {
        updateSettingsUI();
        settingsModal.style.display = 'flex';
      });
    }
    
    // Help button
    if (helpButton) {
      helpButton.addEventListener('click', function() {
        helpModal.style.display = 'flex';
      });
    }
    
    // Save settings button
    if (saveSettingsButton) {
      saveSettingsButton.addEventListener('click', saveSettings);
    }
    
    // Close buttons for modals
    closeButtons.forEach(button => {
      button.addEventListener('click', function() {
        const modal = button.closest('.modal');
        if (modal) {
          modal.style.display = 'none';
        }
      });
    });
    
    // Filter buttons
    filterButtons.forEach(button => {
      button.addEventListener('click', function() {
        // Remove active class from all buttons
        filterButtons.forEach(btn => btn.classList.remove('active'));
        
        // Add active class to clicked button
        this.classList.add('active');
        
        // Filter vulnerabilities
        filterVulnerabilities(this.dataset.filter);
      });
    });
    
    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
      if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
      }
    });
  }

  // Start scan
  function startScan() {
    // Show loading state
    statusArea.textContent = 'Scanning...';
    loadingArea.style.display = 'block';
    resultsArea.style.display = 'none';
    scanButton.disabled = true;
    
    if (progressFill) {
      // Reset and start progress animation
      progressFill.style.width = '0%';
      setTimeout(() => {
        progressFill.style.transition = 'width 3s ease-in-out';
        progressFill.style.width = '90%';
      }, 100);
    }

    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      const activeTab = tabs[0];
      
      chrome.scripting.executeScript({
        target: {tabId: activeTab.id},
        function: capturePageSource
      }, function(results) {
        if (chrome.runtime.lastError) {
          showError('Error accessing page: ' + chrome.runtime.lastError.message);
          scanButton.disabled = false;
          return;
        }

        const pageSource = results[0].result;
        const pageUrl = activeTab.url;
        
        // Send to backend for analysis
        sendToBackend(pageSource, pageUrl);
      });
    });
  }

  function capturePageSource() {
    return document.documentElement.outerHTML;
  }

  function sendToBackend(source, url) {
    // Add a timeout to prevent hanging
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Request timeout after 45 seconds')), 45000);
    });

    // Make the fetch request
    const fetchPromise = fetch('http://127.0.0.1:5000/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        source: source,
        url: url,
        settings: settings // Send settings to the backend
      })
    });

    // Race between fetch and timeout
    Promise.race([fetchPromise, timeoutPromise])
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok: ' + response.status);
        }
        return response.json();
      })
      .then(data => {
        // Complete the progress bar animation
        if (progressFill) {
          progressFill.style.width = '100%';
        }
        
        // Slight delay to show completed progress
        setTimeout(() => {
          displayResults(data);
        }, 500);
      })
      .catch(error => {
        showError('Error communicating with analysis server: ' + error.message);
      })
      .finally(() => {
        scanButton.disabled = false;
      });
  }

  function displayResults(data) {
    loadingArea.style.display = 'none';
    resultsArea.style.display = 'block';
    
    // Calculate vulnerability statistics
    const totalVulnerabilities = data.vulnerabilities.length;
    const highCount = data.vulnerabilities.filter(v => v.severity.toLowerCase() === 'high').length;
    const mediumCount = data.vulnerabilities.filter(v => v.severity.toLowerCase() === 'medium').length;
    const lowCount = data.vulnerabilities.filter(v => v.severity.toLowerCase() === 'low').length;
    
    // Display vulnerability count with enhanced severity breakdown
    summaryArea.innerHTML = `
      <p>Analysis for <strong>${truncateUrl(data.url)}</strong></p>
      <div class="severity-breakdown">
        <div class="severity-stat">
          <div class="severity-number high-count">${highCount}</div>
          <div class="severity-label">High</div>
        </div>
        <div class="severity-stat">
          <div class="severity-number medium-count">${mediumCount}</div>
          <div class="severity-label">Medium</div>
        </div>
        <div class="severity-stat">
          <div class="severity-number low-count">${lowCount}</div>
          <div class="severity-label">Low</div>
        </div>
        <div class="severity-stat">
          <div class="severity-number">${totalVulnerabilities}</div>
          <div class="severity-label">Total</div>
        </div>
      </div>
      <p>Scan completed at ${new Date().toLocaleTimeString()}</p>
    `;
    
    // Clear previous vulnerability results
    vulnerabilitiesArea.innerHTML = '';
    
    // Add each vulnerability with enhanced information
    if (totalVulnerabilities > 0) {
      // Sort vulnerabilities by severity: High, Medium, Low
      const sortedVulns = [...data.vulnerabilities].sort((a, b) => {
        const severityRank = { 'high': 3, 'medium': 2, 'low': 1 };
        return severityRank[b.severity.toLowerCase()] - severityRank[a.severity.toLowerCase()];
      });
    
      sortedVulns.forEach(vuln => {
        const vulnElement = document.createElement('div');
        vulnElement.className = 'vulnerability-item ' + vuln.severity.toLowerCase();
        vulnElement.dataset.severity = vuln.severity.toLowerCase();
        
        // Add AI-detected class for styling
        if (vuln.source === 'ai_analysis') {
          vulnElement.classList.add('ai-detected');
        }
        
        // Create badge for vulnerability type
        const typeBadge = getTypeBadge(vuln.type);
        
        vulnElement.innerHTML = `
          <div class="vuln-header">
            <h3>${vuln.type}</h3>
            <div class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</div>
            ${typeBadge}
          </div>
          <p class="description">${vuln.description}</p>
          <div class="location">${formatLocation(vuln.location)}</div>
          <div class="remediation">
            <h4>Recommended Fix:</h4>
            <p>${vuln.remediation}</p>
          </div>
        `;
        vulnerabilitiesArea.appendChild(vulnElement);
      });
    } else {
      vulnerabilitiesArea.innerHTML = `
        <div class="no-vulnerabilities">
          No vulnerabilities detected! 🎉
        </div>
      `;
    }
    
    statusArea.textContent = 'Scan completed';
    
    // Enable the button again
    scanButton.disabled = false;
  }
  
  function getTypeBadge(vulnType) {
    // Generate badge based on vulnerability type
    const type = vulnType.toLowerCase();
    
    if (type.includes('xss')) {
      return '<span class="type-badge xss">XSS</span>';
    } else if (type.includes('csrf')) {
      return '<span class="type-badge csrf">CSRF</span>';
    } else if (type.includes('sql') || type.includes('inject')) {
      return '<span class="type-badge injection">Injection</span>';
    } else if (type.includes('ssl') || type.includes('tls')) {
      return '<span class="type-badge ssl">SSL/TLS</span>';
    } else if (type.includes('file') || type.includes('upload')) {
      return '<span class="type-badge other">File</span>';
    } else if (type.includes('auth')) {
      return '<span class="type-badge other">Auth</span>';
    } else {
      return '<span class="type-badge other">Security</span>';
    }
  }
  
  function formatLocation(location) {
    // Prevent XSS in the location display and add code formatting
    if (!location || typeof location !== 'string') return 'Unknown location';
    
    // Escape HTML
    const escaped = location
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
    
    // Add basic syntax highlighting for HTML/JS
    return escaped
      .replace(/(&lt;[^&]*&gt;)/g, '<span class="html-tag">$1</span>')
      .replace(/(function|var|let|const|return|if|else|for|while)/g, '<span class="js-keyword">$1</span>');
  }
  
  function filterVulnerabilities(filter) {
    const vulnerabilityItems = document.querySelectorAll('.vulnerability-item');
    
    vulnerabilityItems.forEach(item => {
      if (filter === 'all') {
        item.style.display = 'block';
      } else {
        if (item.dataset.severity === filter) {
          item.style.display = 'block';
        } else {
          item.style.display = 'none';
        }
      }
    });
  }
  
  function exportResults() {
    // Generate timestamp for filename
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `webscout-scan-${timestamp}.html`;
    
    // Create export content
    const exportContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>WebScout Security Report</title>
        <style>
          ${getExportStyles()}
        </style>
      </head>
      <body>
        <div class="report-container">
          <div class="report-header">
            <h1>WebScout Security Report</h1>
            <p>Generated on: ${new Date().toLocaleString()}</p>
          </div>
          ${summaryArea.outerHTML}
          <div class="vulnerabilities-container">
            ${vulnerabilitiesArea.outerHTML}
          </div>
        </div>
      </body>
      </html>
    `;
    
    // Create download link
    const blob = new Blob([exportContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    
    // Create temporary link element and trigger download
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    
    // Clean up
    URL.revokeObjectURL(url);
    
    showNotification('Report exported successfully');
  }
  
  function getExportStyles() {
    return `
      body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f8fafc; }
      .report-container { max-width: 800px; margin: 0 auto; padding: 20px; }
      .report-header { margin-bottom: 30px; text-align: center; }
      .vulnerability-item { margin-bottom: 20px; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
      .high { border-left: 5px solid #ef4444; background-color: #fef2f2; }
      .medium { border-left: 5px solid #f97316; background-color: #fff7ed; }
      .low { border-left: 5px solid #eab308; background-color: #fef9c3; }
      .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 20px; font-size: 12px; font-weight: bold; }
      .severity-badge.high { background-color: #fee2e2; color: #b91c1c; }
      .severity-badge.medium { background-color: #ffedd5; color: #c2410c; }
      .severity-badge.low { background-color: #fef9c3; color: #a16207; }
      .type-badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 5px; }
      .type-badge.xss { background-color: #e0f2fe; color: #0369a1; }
      .type-badge.csrf { background-color: #f3e8ff; color: #6b21a8; }
      .type-badge.injection { background-color: #fef3c7; color: #a16207; }
      .type-badge.ssl { background-color: #d1fae5; color: #047857; }
      .type-badge.other { background-color: #f1f5f9; color: #475569; }
      .location { font-family: monospace; background-color: #f8fafc; padding: 10px; border-radius: 5px; overflow-x: auto; }
      .remediation { background-color: #f0fdf4; padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 3px solid #10b981; }
      .vuln-header { position: relative; margin-bottom: 10px; }
      .html-tag { color: #9333ea; }
      .js-keyword { color: #0369a1; font-weight: bold; }
      .severity-breakdown { display: flex; justify-content: space-around; padding: 15px; background-color: #f8fafc; border-radius: 8px; margin: 15px 0; }
      .severity-stat { text-align: center; }
      .severity-number { font-size: 24px; font-weight: bold; }
      .high-count { color: #dc2626; }
      .medium-count { color: #ea580c; }
      .low-count { color: #ca8a04; }
    `;
  }
  
  function showError(message) {
    loadingArea.style.display = 'none';
    statusArea.innerHTML = `<div class="error">${message}</div>`;
    resultsArea.style.display = 'block';
    vulnerabilitiesArea.innerHTML = '';
    scanButton.disabled = false;
  }
  
  function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
      notification.classList.add('show');
    }, 10);
    
    // Remove after 3 seconds
    setTimeout(() => {
      notification.classList.remove('show');
      setTimeout(() => {
        document.body.removeChild(notification);
      }, 300);
    }, 3000);
  }
  
  function truncateUrl(url) {
    const maxLength = 40;
    if (url.length <= maxLength) return url;
    
    // Extract domain
    let domain = url.replace(/^https?:\/\//, '');
    domain = domain.split('/')[0];
    
    if (url.length <= maxLength) return domain;
    return domain.substring(0, maxLength - 3) + '...';
  }
  
  // Initialize
  initEventListeners();
  
  // Auto-scan if enabled (would need to be implemented in background.js for new page loads)
  if (settings.autoScan) {
    startScan();
  }
});