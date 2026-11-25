(function () {
  'use strict';

  /*
   * FilterPlus AI Safe Mode
   *
   * שתי שכבות סינון:
   * 1. תמונות — תמונה שגדולה מ-MIN_SIZE בשני הצירים מוסתרת.
   * 2. טקסט — כשיש רשימת מילים חסומות, כל בלוק תשובה שמכיל
   *    ביטוי מהרשימה מטושטש. ההתאמה אינה תלוית רישיות.
   */

  var MIN_SIZE = 64;
  var PLACEHOLDER_CLASS = 'filterplus-ai-placeholder';
  var BLUR_CLASS = 'filterplus-ai-blurred';
  var BLUR_OVERLAY_CLASS = 'filterplus-ai-blur-overlay';
  var active = false;
  var blockedRe = null;  // RegExp | null

  /* ─── הפעלה / כיבוי ─── */

  function init(keywords) {
    document.documentElement.classList.add('filterplus-ai-safe');
    buildKeywordRegex(keywords);
    if (!active) {
      active = true;
      processAll();
      observe();
    } else {
      rescanText();
    }
  }

  function disable() {
    if (!active) return;
    active = false;
    blockedRe = null;
    document.documentElement.classList.remove('filterplus-ai-safe');
    var hidden = document.querySelectorAll('[data-filterplus-ai-hidden]');
    for (var i = 0; i < hidden.length; i++) {
      hidden[i].style.removeProperty('visibility');
      hidden[i].removeAttribute('data-filterplus-ai-hidden');
    }
    var placeholders = document.querySelectorAll('.' + PLACEHOLDER_CLASS);
    for (var j = 0; j < placeholders.length; j++) placeholders[j].remove();

    var blurred = document.querySelectorAll('.' + BLUR_CLASS);
    for (var k = 0; k < blurred.length; k++) blurred[k].classList.remove(BLUR_CLASS);
    var overlays = document.querySelectorAll('.' + BLUR_OVERLAY_CLASS);
    for (var m = 0; m < overlays.length; m++) overlays[m].remove();
  }

  /* ─── מילים חסומות ─── */

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  var IS_LATIN = /^[a-zA-Z0-9\s]+$/;

  function buildKeywordRegex(keywords) {
    if (!keywords || keywords.length === 0) { blockedRe = null; return; }
    var parts = [];
    for (var i = 0; i < keywords.length; i++) {
      var kw = keywords[i].trim();
      if (!kw) continue;
      var escaped = escapeRegex(kw);
      if (IS_LATIN.test(kw)) escaped = '\\b' + escaped + '\\b';
      parts.push(escaped);
    }
    blockedRe = parts.length > 0 ? new RegExp(parts.join('|'), 'i') : null;
  }

  /* ─── גודל תמונה ─── */

  function isContentSize(el) {
    var w = el.naturalWidth || el.width || 0;
    var h = el.naturalHeight || el.height || 0;
    if (w > MIN_SIZE && h > MIN_SIZE) return true;
    var rect = el.getBoundingClientRect();
    return rect.width > MIN_SIZE && rect.height > MIN_SIZE;
  }

  function isUiImage(img) {
    if (img.closest('nav, header, [role="banner"], [role="navigation"]')) return true;
    if (img.closest('[class*="avatar"], [class*="Avatar"]')) return true;
    var rect = img.getBoundingClientRect();
    if (rect.width <= MIN_SIZE || rect.height <= MIN_SIZE) return true;
    return false;
  }

  /* ─── הסתרת תמונה ─── */

  function hideElement(el) {
    if (el.dataset.filterplusAiHidden) return;
    el.dataset.filterplusAiHidden = '1';
    el.style.visibility = 'hidden';
    if (!el.parentNode) return;
    var existing = el.nextElementSibling;
    if (existing && existing.classList.contains(PLACEHOLDER_CLASS)) return;
    var ph = document.createElement('div');
    ph.className = PLACEHOLDER_CLASS;
    ph.dir = 'rtl';
    ph.textContent = '🛡️ FilterPlus: תמונה הוסתרה';
    el.parentNode.insertBefore(ph, el.nextSibling);
  }

  /* ─── טשטוש בלוק טקסט ─── */

  var MESSAGE_SELECTOR =
    '[data-message-id], [data-message-author-role], ' +
    '.markdown, .prose, .message-content, ' +
    '[class*="message-"], [class*="Message"], ' +
    '[class*="response"], [class*="Response"], ' +
    '[class*="answer"], [class*="turn-"], ' +
    'article, [role="article"], [role="listitem"]';

  function findMessageBlock(el) {
    var node = el;
    while (node && node !== document.body) {
      if (node.matches && node.matches(MESSAGE_SELECTOR)) return node;
      node = node.parentElement;
    }
    return null;
  }

  function blurBlock(block) {
    if (!block || block.classList.contains(BLUR_CLASS)) return;
    block.classList.add(BLUR_CLASS);

    var overlay = document.createElement('div');
    overlay.className = BLUR_OVERLAY_CLASS;
    overlay.dir = 'rtl';
    overlay.textContent = '🛡️ FilterPlus: תוכן הוסתר';
    block.style.position = block.style.position || 'relative';
    block.appendChild(overlay);
  }

  /* ─── סריקת טקסט ─── */

  var scanTimer = null;
  var dirtyNodes = new Set();

  function scheduleScan() {
    if (scanTimer) return;
    scanTimer = setTimeout(function () {
      scanTimer = null;
      flushScan();
    }, 300);
  }

  function flushScan() {
    if (!blockedRe) { dirtyNodes.clear(); return; }

    dirtyNodes.forEach(function (node) {
      if (!document.body.contains(node)) return;
      var el = node.nodeType === 3 ? node.parentElement : node;
      if (!el) return;
      var block = findMessageBlock(el);
      if (!block || block.classList.contains(BLUR_CLASS)) return;
      var text = block.innerText || block.textContent || '';
      if (blockedRe.test(text)) blurBlock(block);
    });
    dirtyNodes.clear();
  }

  function rescanText() {
    if (!blockedRe) return;
    var blocks = document.querySelectorAll(MESSAGE_SELECTOR);
    for (var i = 0; i < blocks.length; i++) {
      var block = blocks[i];
      if (block.classList.contains(BLUR_CLASS)) continue;
      var text = block.innerText || block.textContent || '';
      if (blockedRe.test(text)) blurBlock(block);
    }
  }

  /* ─── עיבוד תמונות ─── */

  function processImg(img) {
    if (!active || img.dataset.filterplusAiHidden) return;
    if (img.complete && img.naturalWidth > 0) {
      if (!isUiImage(img) && isContentSize(img)) hideElement(img);
      return;
    }
    img.addEventListener('load', function handler() {
      img.removeEventListener('load', handler);
      if (!active) return;
      if (!isUiImage(img) && isContentSize(img)) hideElement(img);
    });
  }

  function processCanvas(canvas) {
    if (!active || canvas.dataset.filterplusAiHidden) return;
    if (isContentSize(canvas) && !canvas.closest('nav, header, [role="banner"]')) {
      hideElement(canvas);
    }
  }

  function processVideo(video) {
    if (!active || video.dataset.filterplusAiHidden) return;
    if (isContentSize(video) && !video.closest('nav, header, [role="banner"]')) {
      hideElement(video);
    }
  }

  function processNode(node) {
    if (node.nodeType === 3) {
      if (blockedRe) { dirtyNodes.add(node); scheduleScan(); }
      return;
    }
    if (node.nodeType !== 1) return;

    var tag = node.tagName;
    if (tag === 'IMG') processImg(node);
    else if (tag === 'CANVAS') processCanvas(node);
    else if (tag === 'VIDEO') processVideo(node);

    var imgs = node.querySelectorAll('img');
    for (var i = 0; i < imgs.length; i++) processImg(imgs[i]);
    var canvases = node.querySelectorAll('canvas');
    for (var j = 0; j < canvases.length; j++) processCanvas(canvases[j]);
    var videos = node.querySelectorAll('video');
    for (var k = 0; k < videos.length; k++) processVideo(videos[k]);

    if (blockedRe) { dirtyNodes.add(node); scheduleScan(); }
  }

  function processAll() {
    var imgs = document.querySelectorAll('img');
    for (var i = 0; i < imgs.length; i++) processImg(imgs[i]);
    var canvases = document.querySelectorAll('canvas');
    for (var j = 0; j < canvases.length; j++) processCanvas(canvases[j]);
    var videos = document.querySelectorAll('video');
    for (var k = 0; k < videos.length; k++) processVideo(videos[k]);
    rescanText();
  }

  /* ─── MutationObserver ─── */

  var observer;
  function observe() {
    if (observer) return;
    observer = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var m = mutations[i];
        if (m.type === 'characterData') {
          if (blockedRe && m.target) { dirtyNodes.add(m.target); scheduleScan(); }
          continue;
        }
        var added = m.addedNodes;
        for (var j = 0; j < added.length; j++) processNode(added[j]);
      }
    });
    var target = document.body || document.documentElement;
    observer.observe(target, { childList: true, subtree: true, characterData: true });
  }

  /* ─── תקשורת עם background ─── */

  chrome.runtime.sendMessage({ type: 'filterplus-get-config' }, function (resp) {
    if (chrome.runtime.lastError || !resp) return;
    if (resp.aiSafeMode) init(resp.aiBlockedKeywords);
  });

  chrome.runtime.onMessage.addListener(function (msg) {
    if (msg.type === 'filterplus-config') {
      if (msg.config.aiSafeMode) init(msg.config.aiBlockedKeywords);
      else disable();
    }
  });
})();
