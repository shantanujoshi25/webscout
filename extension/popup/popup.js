document.addEventListener('DOMContentLoaded', function() {
    const scanButton = document.getElementById('scanButton');
    const statusArea = document.getElementById('statusArea');
    const resultsArea = document.getElementById('resultsArea');
    const summaryArea = document.getElementById('summaryArea');
    const vulnerabilitiesArea = document.getElementById('vulnerabilitiesArea');
    const loadingArea = document.getElementById('loadingArea');
  
    // Handle scan button click
    scanButton.addEventListener('click', function() {
      // Show loading state
      statusArea.textContent = 'Scanning...';
      loadingArea.style.display = 'block';
      resultsArea.style.display = 'none';
  
      
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const activeTab = tabs[0];
        
        
        chrome.scripting.executeScript({
          target: {tabId: activeTab.id},
          function: capturePageSource
        }, function(results) {
          if (chrome.runtime.lastError) {
            showError('Error accessing page: ' + chrome.runtime.lastError.message);
            return;
          }
  
          const pageSource = results[0].result;
          const pageUrl = activeTab.url;
          
          // Send to backend for analysis
          sendToBackend(pageSource, pageUrl);
        });
      });
    });
  
    
    function capturePageSource() {
      return document.documentElement.outerHTML;
    }
  
    
    function sendToBackend(source, url) {
      fetch('http://127.0.0.1:5000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          source: source,
          url: url
        })
      })
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then(data => {
        displayResults(data);
      })
      .catch(error => {
        showError('Error communicating with analysis server: ' + error.message);
      });
    }
  
   
    function displayResults(data) {
      loadingArea.style.display = 'none';
      resultsArea.style.display = 'block';
      
      
      const totalVulnerabilities = data.vulnerabilities.length;
      summaryArea.innerHTML = `
        <p>Found ${totalVulnerabilities} potential vulnerabilities</p>
        <p>Scan completed at ${new Date().toLocaleTimeString()}</p>
      `;
      
      // Clear previous results
      vulnerabilitiesArea.innerHTML = '';
      
      // Add each vulnerability
      if (totalVulnerabilities > 0) {
        data.vulnerabilities.forEach(vuln => {
          const vulnElement = document.createElement('div');
          vulnElement.className = 'vulnerability-item ' + vuln.severity.toLowerCase();
          console.log(vuln.type,vuln.severity)
          vulnElement.innerHTML = `
            <h4>${vuln.type}: ${vuln.severity}</h4>
            <p>${vuln.description}</p>
            <div class="location">Location: ${vuln.location}</div>
            <div class="remediation">
              <h4>Remediation</h4>
              <p>${vuln.remediation}</p>
            </div>
          `;
          vulnerabilitiesArea.appendChild(vulnElement);
        });
      } else {
        vulnerabilitiesArea.innerHTML = '<p class="no-vulnerabilities">No vulnerabilities detected!</p>';
      }
      
      statusArea.textContent = 'Scan completed';
    }
  
    // Show error message
    function showError(message) {
      loadingArea.style.display = 'none';
      statusArea.textContent = 'Error';
      summaryArea.innerHTML = `<p class="error">${message}</p>`;
      resultsArea.style.display = 'block';
      vulnerabilitiesArea.innerHTML = '';
    }
  });