const button = document.getElementById('toggle'), status = document.getElementById('status');
let enabled = false;
async function refresh() {
  try {
    enabled = (await chrome.declarativeNetRequest.getEnabledRulesets()).includes('starter');
    status.textContent = enabled ? 'Starter rules enabled in this browser.' : 'Blocking paused in this browser.';
    button.textContent = enabled ? 'Pause blocking' : 'Enable blocking'; button.disabled = false;
  } catch(e) {status.textContent = 'Could not read rule status: ' + e.message;}
}
button.onclick = async () => {button.disabled=true;try {await chrome.declarativeNetRequest.updateEnabledRulesets({enableRulesetIds:enabled?[]:['starter'],disableRulesetIds:enabled?['starter']:[]});await refresh();}catch(e){status.textContent=e.message;button.disabled=false;}};
refresh();
