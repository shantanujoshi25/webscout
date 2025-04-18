// This background script can handle events that need to happen
// even when the popup is closed
chrome.runtime.onInstalled.addListener(() => {
    console.log('Security Scanner Extension installed');
  });
  
  // Optional: Handle messages from content script or popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'scanComplete') {
      // Could implement notifications here
    }
    return true;
  });