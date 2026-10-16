chrome.runtime.onInstalled.addListener(() => {
  chrome.declarativeNetRequest.getEnabledRulesets().then(ids => {
    if (!ids.includes('block_video')) {
      chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds: ['block_video']
      });
    }
  });
});
