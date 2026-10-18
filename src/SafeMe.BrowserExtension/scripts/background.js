var DEFAULT_CONFIG = { audioOnly: true, hideThumbnails: true };

function getConfig(cb) {
  try {
    chrome.storage.managed.get(['audioOnly', 'hideThumbnails'], function (items) {
      if (chrome.runtime.lastError || !items || Object.keys(items).length === 0) {
        cb(DEFAULT_CONFIG);
        return;
      }
      cb({
        audioOnly: items.audioOnly !== false,
        hideThumbnails: items.hideThumbnails !== false
      });
    });
  } catch (e) {
    cb(DEFAULT_CONFIG);
  }
}

function applyRuleset(config) {
  chrome.declarativeNetRequest.getEnabledRulesets().then(function (ids) {
    var enabled = ids.includes('block_video');
    if (config.audioOnly && !enabled) {
      chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: ['block_video'] });
    } else if (!config.audioOnly && enabled) {
      chrome.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: ['block_video'] });
    }
  });
}

function broadcast(config) {
  chrome.tabs.query({ url: '*://*.youtube.com/*' }, function (tabs) {
    for (var i = 0; i < tabs.length; i++) {
      chrome.tabs.sendMessage(tabs[i].id, { type: 'safeme-config', config: config }).catch(function () {});
    }
  });
}

function refresh() {
  getConfig(function (config) {
    applyRuleset(config);
    broadcast(config);
  });
}

chrome.runtime.onInstalled.addListener(refresh);
chrome.runtime.onStartup.addListener(refresh);

chrome.storage.onChanged.addListener(function (changes, area) {
  if (area === 'managed') refresh();
});

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (msg.type === 'safeme-get-config') {
    getConfig(function (config) { sendResponse(config); });
    return true;
  }
});
