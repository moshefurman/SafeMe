var DEFAULT_CONFIG = { audioOnly: true, hideThumbnails: true, allowedChannels: [], aiSafeMode: false, aiBlockedKeywords: [] };

/*
 * ערוצים מותרים.
 *
 * בערוץ שההורה אישר הסרטון מוצג במלואו. ההחלטה מתקבלת כאן ולא בדף:
 * הערוץ נקבע לפי כתובת הלשונית ושאילתה ישירה ליוטיוב, כך שדף יוטיוב
 * (או מי שעורך אותו) אינו יכול להכריז על עצמו כמותר.
 *
 * ההיתר הוא כלל allow לשונית אחת בלבד, בעדיפות מעל כלל החסימה. כל
 * מעבר כתובת בלשונית מסיר אותו מיד, ורק אז נבדק הסרטון הבא.
 */

var ALLOW_PRIORITY = 2;
var VIDEO_FILTER = '\\/videoplayback\\?.*mime=video(%2[Ff]|\\/)';

var currentConfig = null;
var allowSets = null;          // { ids: Set, handles: Set, unresolved: bool }
var allowSetsPromise = null;
var verdicts = new Map();      // videoId -> bool
var pending = new Map();       // videoId -> Promise<bool>

function parseChannels(raw) {
  if (Array.isArray(raw)) return raw.filter(function (s) { return typeof s === 'string'; });
  if (typeof raw !== 'string' || raw.trim() === '') return [];
  try {
    var arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter(function (s) { return typeof s === 'string'; }) : [];
  } catch (e) {
    return [];
  }
}

function getConfig(cb) {
  try {
    chrome.storage.managed.get(['audioOnly', 'hideThumbnails', 'allowedChannels', 'aiSafeMode', 'aiBlockedKeywords'], function (items) {
      if (chrome.runtime.lastError || !items || Object.keys(items).length === 0) {
        cb(DEFAULT_CONFIG);
        return;
      }
      cb({
        audioOnly: items.audioOnly !== false,
        hideThumbnails: items.hideThumbnails !== false,
        allowedChannels: parseChannels(items.allowedChannels),
        aiSafeMode: items.aiSafeMode === true,
        aiBlockedKeywords: parseChannels(items.aiBlockedKeywords)
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

var AI_URLS = [
  '*://*.chatgpt.com/*', '*://chat.openai.com/*',
  '*://*.claude.ai/*', '*://*.copilot.microsoft.com/*',
  '*://*.gemini.google.com/*', '*://*.perplexity.ai/*',
  '*://*.deepseek.com/*', '*://*.mistral.ai/*', '*://chat.mistral.ai/*',
  '*://*.poe.com/*', '*://*.you.com/*', '*://*.grok.com/*'
];

function broadcast(config) {
  chrome.tabs.query({ url: '*://*.youtube.com/*' }, function (tabs) {
    for (var i = 0; i < tabs.length; i++) {
      chrome.tabs.sendMessage(tabs[i].id, { type: 'safeme-config', config: config }).catch(function () {});
    }
  });
  for (var j = 0; j < AI_URLS.length; j++) {
    chrome.tabs.query({ url: AI_URLS[j] }, function (tabs) {
      for (var k = 0; k < tabs.length; k++) {
        chrome.tabs.sendMessage(tabs[k].id, { type: 'safeme-config', config: config }).catch(function () {});
      }
    });
  }
}

function clearAllowRules() {
  return chrome.declarativeNetRequest.getSessionRules().then(function (rules) {
    var ids = rules.map(function (r) { return r.id; });
    if (ids.length === 0) return;
    return chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids });
  });
}

function refresh() {
  getConfig(function (config) {
    var changed = JSON.stringify(config.allowedChannels) !==
      JSON.stringify(currentConfig ? currentConfig.allowedChannels : null);
    currentConfig = config;

    if (changed) {
      allowSets = null;
      allowSetsPromise = null;
      verdicts.clear();
    }

    applyRuleset(config);
    clearAllowRules().catch(function () {}).then(function () { broadcast(config); });
  });
}

function configReady() {
  if (currentConfig) return Promise.resolve(currentConfig);
  return new Promise(function (resolve) {
    getConfig(function (config) { currentConfig = config; resolve(config); });
  });
}

/* ───────────────────────────── זיהוי ערוץ */

function fetchText(url) {
  return fetch(url, { credentials: 'omit' }).then(function (r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.text();
  });
}

function normHandle(h) {
  try { h = decodeURIComponent(h); } catch (e) {}
  return '@' + h.replace(/^@/, '').toLowerCase();
}

/** מזהה UC וה-handle של ערוץ, מתוך דף הערוץ. */
function resolveChannel(entry) {
  var key = 'ch:' + entry;
  return chrome.storage.local.get(key).then(function (stored) {
    if (stored[key]) return stored[key];

    var url = entry.charAt(0) === '@'
      ? 'https://www.youtube.com/' + encodeURIComponent(entry).replace('%40', '@')
      : 'https://www.youtube.com/channel/' + entry;

    return fetchText(url).then(function (html) {
      var id = (html.match(/<link rel="canonical" href="https:\/\/www\.youtube\.com\/channel\/(UC[\w-]{22})"/) ||
                html.match(/"externalId":"(UC[\w-]{22})"/) || [])[1] || null;
      var handle = (html.match(/"vanityChannelUrl":"https?:\/\/www\.youtube\.com\/(@[^"\/]+)"/) ||
                    html.match(/"canonicalBaseUrl":"\/(@[^"\/]+)"/) || [])[1] || null;
      var result = { id: id, handle: handle ? normHandle(handle) : null };
      if (id && handle) {
        var obj = {};
        obj[key] = result;
        chrome.storage.local.set(obj);
      }
      return result;
    });
  }).catch(function () { return { id: null, handle: null }; });
}

function getAllowSets(config) {
  if (allowSets) return Promise.resolve(allowSets);
  if (allowSetsPromise) return allowSetsPromise;

  allowSetsPromise = Promise.all(config.allowedChannels.map(function (entry) {
    return resolveChannel(entry).then(function (r) {
      var isId = /^UC[\w-]{22}$/.test(entry);
      return {
        id: isId ? entry : r.id,
        handle: isId ? r.handle : normHandle(entry)
      };
    });
  })).then(function (list) {
    var sets = { ids: new Set(), handles: new Set(), unresolved: false };
    list.forEach(function (c) {
      if (c.id) sets.ids.add(c.id);
      if (c.handle) sets.handles.add(c.handle);
      if (!c.id || !c.handle) sets.unresolved = true;
    });
    allowSets = sets;
    allowSetsPromise = null;
    return sets;
  });

  return allowSetsPromise;
}

/** האם הסרטון שייך לערוץ מותר. כל כשל — לא. */
function checkVideo(videoId, sets) {
  return fetchText('https://www.youtube.com/oembed?format=json&url=' +
      encodeURIComponent('https://www.youtube.com/watch?v=' + videoId))
    .then(function (text) {
      var author = (JSON.parse(text).author_url || '');
      var h = author.match(/youtube\.com\/(@[^\/?#]+)/);
      if (h && sets.handles.has(normHandle(h[1]))) return true;
      var c = author.match(/youtube\.com\/channel\/(UC[\w-]{22})/);
      if (c && sets.ids.has(c[1])) return true;
      if ((h || c) && !sets.unresolved) return false;
      throw new Error('fallback');
    })
    .catch(function () {
      // סרטון שחסום להטמעה, או ערוץ שלא זוהה במלואו: דף הצפייה עצמו.
      return fetchText('https://www.youtube.com/watch?v=' + videoId).then(function (html) {
        var m = html.match(/"channelId":"(UC[\w-]{22})"/);
        return !!(m && sets.ids.has(m[1]));
      });
    })
    .catch(function () { return false; });
}

function verdictFor(videoId, config) {
  if (verdicts.has(videoId)) return Promise.resolve(verdicts.get(videoId));
  if (pending.has(videoId)) return pending.get(videoId);

  var p = getAllowSets(config).then(function (sets) {
    return checkVideo(videoId, sets);
  }).then(function (ok) {
    verdicts.set(videoId, ok);
    pending.delete(videoId);
    return ok;
  });

  pending.set(videoId, p);
  return p;
}

/* ───────────────────────────── כלל ההיתר ללשונית */

function watchVideoId(url) {
  try {
    var u = new URL(url);
    if (!/(^|\.)youtube\.com$/.test(u.hostname) || u.pathname !== '/watch') return null;
    var v = u.searchParams.get('v');
    return v && /^[\w-]{11}$/.test(v) ? v : null;
  } catch (e) {
    return null;
  }
}

function removeAllow(tabId) {
  return chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [tabId] }).catch(function () {});
}

function addAllow(tabId) {
  return chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [tabId],
    addRules: [{
      id: tabId,
      priority: ALLOW_PRIORITY,
      action: { type: 'allow' },
      condition: {
        regexFilter: VIDEO_FILTER,
        requestDomains: ['googlevideo.com'],
        resourceTypes: ['xmlhttprequest', 'media', 'other'],
        tabIds: [tabId]
      }
    }]
  });
}

/**
 * מחליט על הלשונית לפי הכתובת שלה כרגע.
 *
 * כשהתשובה עוד לא ידועה הכלל מוסר קודם, כדי שסרטון לא מוכר לא ירוץ
 * על היתר של הסרטון הקודם. לפני ההוספה נבדק שוב שהלשונית עדיין על
 * אותו סרטון.
 */
function evaluateTab(tabId) {
  return configReady().then(function (config) {
    return chrome.tabs.get(tabId).then(function (tab) {
      var videoId = watchVideoId(tab.url || '');

      if (!config.audioOnly || config.allowedChannels.length === 0 || !videoId) {
        return removeAllow(tabId).then(function () { return { videoId: videoId, allowed: false }; });
      }

      var known = verdicts.has(videoId);
      var first = known ? Promise.resolve() : removeAllow(tabId);

      return first.then(function () { return verdictFor(videoId, config); }).then(function (ok) {
        if (!ok) return removeAllow(tabId).then(function () { return { videoId: videoId, allowed: false }; });

        return chrome.tabs.get(tabId).then(function (now) {
          if (watchVideoId(now.url || '') !== videoId) return { videoId: videoId, allowed: false };
          return addAllow(tabId).then(function () { return { videoId: videoId, allowed: true }; });
        });
      });
    });
  }).catch(function () {
    return removeAllow(tabId).then(function () { return { videoId: null, allowed: false }; });
  });
}

/* ───────────────────────────── אירועים */

chrome.runtime.onInstalled.addListener(function () { clearAllowRules().catch(function () {}); refresh(); });
chrome.runtime.onStartup.addListener(refresh);

chrome.storage.onChanged.addListener(function (changes, area) {
  if (area === 'managed') refresh();
});

chrome.tabs.onUpdated.addListener(function (tabId, changeInfo) {
  if (changeInfo.url) evaluateTab(tabId);
});

chrome.tabs.onRemoved.addListener(function (tabId) {
  removeAllow(tabId);
});

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (msg.type === 'safeme-get-config') {
    getConfig(function (config) { sendResponse(config); });
    return true;
  }

  var tabId = sender.tab && sender.tab.id;
  if (typeof tabId !== 'number') return;

  // יציאה מסרטון: ההיתר יורד מיד. בכיוון הזה אין סיכון, ולכן אין בדיקה.
  if (msg.type === 'safeme-leave') {
    removeAllow(tabId).then(function () { sendResponse({ ok: true }); });
    return true;
  }

  // תוכן ההודעה אינו קובע דבר: ההחלטה לפי כתובת הלשונית בלבד.
  if (msg.type === 'safeme-video-status') {
    evaluateTab(tabId).then(sendResponse);
    return true;
  }
});
