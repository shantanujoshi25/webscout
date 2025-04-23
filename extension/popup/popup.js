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
        settings: settings
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
          <div class="vuln-header" onclick="toggleVulnDetails(this)">
            <h3>${vuln.type}</h3>
            <div class="badge-container">
              <div class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</div>
              ${typeBadge}
              <i class="fas fa-chevron-down chevron"></i>
            </div>
          </div>
          <div class="vuln-body">
            <p class="description">${vuln.description}</p>
            <div class="location">${formatLocation(vuln.location)}</div>
            <div class="remediation">
              <h4>Recommended Fix:</h4>
              <p>${vuln.remediation}</p>
            </div>
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
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `webscout-scan-${timestamp}.html`;
    
    const url = document.querySelector('#summaryArea p strong')?.textContent || 'Unknown URL';
    const timestamp_gen = new Date().toLocaleString();
    const scanTime = document.querySelector('#summaryArea p:last-child')?.textContent.replace('Scan completed at ', '') || '';
    
    const vulnerabilityItems = document.querySelectorAll('.vulnerability-item');
    let vulnerabilitiesHTML = '';
    
    vulnerabilityItems.forEach(item => {
      const type = item.querySelector('h3')?.textContent || 'Unknown';
      const severity = item.dataset.severity || 'medium';
      const description = item.querySelector('.description')?.textContent || '';
      const location = item.querySelector('.location')?.textContent || '';
      const remediation = item.querySelector('.remediation p')?.textContent || '';
      const typeBadge = getTypeBadgeHTML(type);
      
      vulnerabilitiesHTML += `
        <div class="vulnerability-item ${severity}">
          <div class="vuln-header" onclick="toggleVulnDetails(this)">
            <div class="vuln-title">${type}</div>
            <div class="badge-container">
              <div class="severity-badge ${severity}">${severity.charAt(0).toUpperCase() + severity.slice(1)}</div>
              ${typeBadge}
              <i class="fas fa-chevron-down chevron"></i>
            </div>
          </div>
          <div class="vuln-body">
            <p class="vuln-description">${description}</p>
            <div class="location">${location}</div>
            <div class="remediation">
              <h4>Recommended Fix:</h4>
              <p>${remediation}</p>
            </div>
          </div>
        </div>
      `;
    });
    
    const highCount = document.querySelector('.high-count')?.textContent || '0';
    const mediumCount = document.querySelector('.medium-count')?.textContent || '0';
    const lowCount = document.querySelector('.low-count')?.textContent || '0';
    const totalVulns = vulnerabilityItems.length;
    
    const exportContent = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WebScout Security Report</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
          ${getExportStyles()}
        </style>
      </head>
      <body>
        <div class="report-container">
          <header class="report-header">
            <div class="dark-mode-toggle">
              <i class="fas fa-sun"></i>
            </div>
            <div class="logo">
              <div class="logo-icon">
                <i class="fas fa-shield-alt"></i>
              </div>
              <h1>WebScout Security Report</h1>
            </div>
            <p class="timestamp">Generated on: ${timestamp_gen}</p>
            <div class="target-url-container">
              <div class="url-bar"></div>
              <div class="target-url">
                Analysis for: ${url}
              </div>
            </div>
          </header>
          
          <div class="filter-tabs">
            <div class="tab active">All Issues</div>
            <div class="tab">High</div>
            <div class="tab">Medium</div>
            <div class="tab">Low</div>
          </div>
          
          <div class="severity-stats">
            <div class="severity-box high-box">
              <div class="severity-count count-high">${highCount}</div>
              <div class="severity-label">High</div>
            </div>
            <div class="severity-box medium-box">
              <div class="severity-count count-medium">${mediumCount}</div>
              <div class="severity-label">Medium</div>
            </div>
            <div class="severity-box low-box">
              <div class="severity-count count-low">${lowCount}</div>
              <div class="severity-label">Low</div>
            </div>
            <div class="severity-box total-box">
              <div class="severity-count count-total">${totalVulns}</div>
              <div class="severity-label">Total</div>
            </div>
          </div>
          
          <p class="scan-time">Scan completed at ${scanTime}</p>
          
          <h2 class="section-title">Detected Vulnerabilities</h2>
          
          <section class="vulnerabilities-section">
            ${vulnerabilitiesHTML}
          </section>
          
          <footer class="report-footer">
            <p>WebScout v1.0 © 2025 | Scan results are based on automated analysis</p>
          </footer>
        </div>
        
        <script>
  function toggleVulnDetails(element) {
    const vulnBody = element.nextElementSibling;
    const chevron = element.querySelector('.chevron');
    
    if (vulnBody.style.display === 'none' || vulnBody.style.display === '') {
      vulnBody.style.display = 'block';
      chevron.classList.add('expanded');
    } else {
      vulnBody.style.display = 'none';
      chevron.classList.remove('expanded');
    }
  }
  
  // Initialize all vulnerability details to be hidden on page load
  document.addEventListener('DOMContentLoaded', function() {
    const vulnBodies = document.querySelectorAll('.vuln-body');
    vulnBodies.forEach(body => {
      body.style.display = 'none';
    });
    
    // Tab functionality
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', function() {
        tabs.forEach(t => t.classList.remove('active'));
        this.classList.add('active');
      });
    });
  });
</script>
      </body>
      </html>
    `;
    
    const blob = new Blob([exportContent], { type: 'text/html' });
    const url_obj = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url_obj;
    a.download = filename;
    a.click();
    
    URL.revokeObjectURL(url_obj);
    
    showNotification('Report exported successfully');
  }
  
  function getExportStyles() {
    return `
      :root {
        --primary: #3b82f6;
        --primary-dark: #2d3748;
        --background: #1a202c;
        --card-bg: #252d3d;
        --high: #f87171;
        --medium: #f97316;
        --low: #4ade80;
        --total: #3b82f6;
        --text: #ffffff;
        --text-secondary: #a0aec0;
        --header-bg: #2b3a67;
      }
      
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      }
      
      body {
        background-color: var(--background);
        color: var(--text);
        line-height: 1.6;
        padding: 0;
      }
      
      .report-container {
        max-width: 800px;
        margin: 0 auto;
        background-color: var(--background);
        border-radius: 16px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
        overflow: hidden;
      }
      
      .report-header {
        background: var(--header-bg);
        padding: 40px;
        color: white;
        text-align: center;
        position: relative;
      }
      
      .dark-mode-toggle {
        position: absolute;
        top: 20px;
        right: 20px;
        color: white;
        font-size: 20px;
        cursor: pointer;
      }
      
      .logo {
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 15px;
      }
      
      .logo-icon {
        width: 50px;
        height: 50px;
        background-color: white;
        border-radius: 10px;
        margin-right: 15px;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      }
      
      .logo-icon i {
        color: var(--primary);
        font-size: 28px;
      }
      
      h1 {
        font-size: 32px;
        margin-bottom: 10px;
        font-weight: 700;
        color: white;
      }
      
      p {
        margin-bottom: 10px;
      }
      
      .target-url-container {
        margin-top: 30px;
        display: flex;
        align-items: center;
      }
      
      .url-bar {
        width: 4px;
        height: 30px;
        background-color: var(--primary);
        border-radius: 2px;
        margin-right: 10px;
      }
      
      .target-url {
        color: var(--text);
        font-size: 14px;
        font-family: 'Consolas', 'Monaco', monospace;
        text-align: left;
      }
      
      .filter-tabs {
        display: flex;
        justify-content: center;
        padding: 20px;
        gap: 10px;
        background-color: var(--background);
      }
      
      .tab {
        padding: 8px 16px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
        background-color: var(--card-bg);
        color: var(--text-secondary);
      }
      
      .tab.active {
        background-color: var(--primary);
        color: white;
      }
      
      .severity-stats {
        display: flex;
        justify-content: space-between;
        padding: 0 20px;
        margin-bottom: 20px;
      }
      
      .severity-box {
        flex: 1;
        padding: 20px 15px;
        border-radius: 10px;
        margin: 0 8px;
        background-color: var(--card-bg);
        text-align: center;
        position: relative;
      }
      
      .severity-box::after {
        content: "";
        position: absolute;
        bottom: 0;
        left: 0;
        right: 0;
        height: 3px;
        border-radius: 0 0 10px 10px;
      }
      
      .high-box::after {
        background-color: var(--high);
      }
      
      .medium-box::after {
        background-color: var(--medium);
      }
      
      .low-box::after {
        background-color: var(--low);
      }
      
      .total-box::after {
        background-color: var(--total);
      }
      
      .severity-count {
        font-size: 36px;
        font-weight: 700;
        margin-bottom: 5px;
      }
      
      .count-high {
        color: var(--high);
      }
      
      .count-medium {
        color: var(--medium);
      }
      
      .count-low {
        color: var(--low);
      }
      
      .count-total {
        color: var(--total);
      }
      
      .severity-label {
        font-size: 12px;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 1px;
      }
      
      .scan-time {
        text-align: center;
        color: var(--text-secondary);
        font-size: 14px;
        margin: 20px 0;
        font-style: italic;
      }
      
      .section-title {
        font-size: 20px;
        font-weight: 600;
        color: var(--text);
        margin: 30px 20px 20px;
        position: relative;
        padding-left: 15px;
      }
      
      .section-title::before {
        content: "";
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 5px;
        background-color: var(--primary);
        border-radius: 3px;
      }
      
      .vulnerabilities-section {
        padding: 0 20px 30px;
      }
      
      .vulnerability-item {
        background-color: var(--card-bg);
        border-radius: 8px;
        margin-bottom: 15px;
        overflow: hidden;
        border-left: 4px solid transparent;
      }
      
      .vulnerability-item.medium {
        border-left-color: var(--medium);
      }
      
      .vulnerability-item.high {
        border-left-color: var(--high);
      }
      
      .vulnerability-item.low {
        border-left-color: var(--low);
      }
      
      .vuln-header {
        padding: 15px 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        cursor: pointer;
      }
      
      .vuln-title {
        font-size: 16px;
        font-weight: 600;
        color: var(--text);
      }
      
      .badge-container {
        display: flex;
        gap: 10px;
        align-items: center;
      }
      
      .severity-badge {
        padding: 5px 10px;
        border-radius: 5px;
        font-size: 12px;
        font-weight: 500;
        text-transform: uppercase;
      }
      
      .severity-badge.medium {
        background-color: rgba(249, 115, 22, 0.2);
        color: var(--medium);
      }
      
      .severity-badge.high {
        background-color: rgba(248, 113, 113, 0.2);
        color: var(--high);
      }
      
      .severity-badge.low {
        background-color: rgba(74, 222, 128, 0.2);
        color: var(--low);
      }
      
      .type-badge {
        padding: 5px 10px;
        border-radius: 5px;
        font-size: 12px;
        font-weight: 500;
      }
      
      .type-badge.ssl, .type-badge.ssl\\/tls {
        background-color: rgba(5, 150, 105, 0.2);
        color: #10b981;
      }
      
      .type-badge.xss {
        background-color: rgba(37, 99, 235, 0.2);
        color: #60a5fa;
      }
      
      .type-badge.csrf {
        background-color: rgba(124, 58, 237, 0.2);
        color: #a78bfa;
      }
      
      .type-badge.injection {
        background-color: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
      }
      
      .type-badge.other {
        background-color: rgba(107, 114, 128, 0.2);
        color: #d1d5db;
      }
      
      .chevron {
        color: var(--text-secondary);
        font-size: 16px;
        transition: transform 0.3s;
      }
      
      .chevron.expanded {
        transform: rotate(180deg);
      }
      
      .vuln-body {
        padding: 0 20px 15px;
        display: none;
      }
      
      .vuln-body.expanded {
        display: block;
      }
      
      .vuln-description {
        font-size: 14px;
        margin-bottom: 15px;
        color: var(--text);
      }
      
      .location {
        font-family: 'Consolas', 'Monaco', monospace;
        background-color: rgba(0, 0, 0, 0.2);
        padding: 10px 15px;
        border-radius: 8px;
        font-size: 13px;
        color: var(--text-secondary);
        margin-bottom: 15px;
        white-space: pre-wrap;
        word-break: break-all;
      }
      
      .remediation {
        background-color: rgba(74, 222, 128, 0.1);
        border-radius: 8px;
        padding: 15px;
        border-left: 3px solid var(--low);
      }
      
      .remediation h4 {
        font-size: 14px;
        font-weight: 600;
        color: var(--low);
        margin-bottom: 8px;
      }
      
      .remediation p {
        color: var(--text);
        font-size: 14px;
        margin-bottom: 0;
      }
      
      .report-footer {
        padding: 20px;
        text-align: center;
        background-color: var(--primary-dark);
        color: var(--text-secondary);
        font-size: 12px;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
      }
      
      @import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css');
    `;
  }
  
  function getTypeBadgeHTML(vulnType) {
    const type = vulnType.toLowerCase();
    
    if (type.includes('xss')) {
      return '<div class="type-badge xss">XSS</div>';
    } else if (type.includes('csrf')) {
      return '<div class="type-badge csrf">CSRF</div>';
    } else if (type.includes('sql') || type.includes('inject')) {
      return '<div class="type-badge injection">Injection</div>';
    } else if (type.includes('ssl') || type.includes('tls')) {
      return '<div class="type-badge ssl">SSL/TLS</div>';
    } else if (type.includes('file') || type.includes('upload')) {
      return '<div class="type-badge other">File</div>';
    } else if (type.includes('auth')) {
      return '<div class="type-badge other">Auth</div>';
    } else {
      return '<div class="type-badge other">Security</div>';
    }
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
  
  // Function to toggle vulnerability details
  function toggleVulnDetails(element) {
    const vulnBody = element.nextElementSibling;
    const chevron = element.querySelector('.chevron');
    
    if (vulnBody.style.display === 'none' || vulnBody.style.display === '') {
      vulnBody.style.display = 'block';
      chevron.classList.add('expanded');
    } else {
      vulnBody.style.display = 'none';
      chevron.classList.remove('expanded');
    }
  }
  
  // Initialize
  initEventListeners();
  
  // Auto-scan if enabled (would need to be implemented in background.js for new page loads)
  if (settings.autoScan) {
    startScan();
  }
});