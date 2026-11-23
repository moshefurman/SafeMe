(function () {
  'use strict';

  /*
   * SafeMe AI Safe Mode
   *
   * מסתיר תמונות בתוך תשובות של מנועי AI — תמונות שנוצרו, תמונות
   * מחיפוש, ותמונות שהמשתמש העלה. אלמנטים של ממשק (לוגו, אייקונים,
   * אווטר) נשארים.
   *
   * ההיוריסטיקה: תמונה שגדולה מ-MIN_SIZE בשני הצירים נחשבת לתוכן.
   * אלמנטים קטנים יותר (אייקונים, אווטרים) נשארים.
   */

  var MIN_SIZE = 64;
  var PLACEHOLDER_CLASS = 'safeme-ai-placeholder';
  var active = false;

  function init() {
    if (active) return;
    active = true;
    document.documentElement.classList.add('safeme-ai-safe');
    processAll();
    observe();
  }

  function disable() {
    if (!active) return;
    active = false;
    document.documentElement.classList.remove('safeme-ai-safe');
    var hidden = document.querySelectorAll('[data-safeme-ai-hidden]');
    for (var i = 0; i < hidden.length; i++) {
      hidden[i].style.removeProperty('visibility');
      hidden[i].removeAttribute('data-safeme-ai-hidden');
    }
    var placeholders = document.querySelectorAll('.' + PLACEHOLDER_CLASS);
    for (var j = 0; j < placeholders.length; j++) {
      placeholders[j].remove();
    }
  }

  /* ─── גודל תמונה ─── */

  function isContentSize(el) {
    var w = el.naturalWidth || el.width || 0;
    var h = el.naturalHeight || el.height || 0;
    if (w > MIN_SIZE && h > MIN_SIZE) return true;
    var rect = el.getBoundingClientRect();
    return rect.width > MIN_SIZE && rect.height > MIN_SIZE;
  }

  /* ─── סינון: מה לא להסתיר ─── */

  function isUiImage(img) {
    // SVG favicon / icon
    if (img.closest('nav, header, [role="banner"], [role="navigation"]')) return true;
    // אווטר קטן
    if (img.closest('[class*="avatar"], [class*="Avatar"]')) return true;
    // תמונת פרופיל בגודל קטן
    var rect = img.getBoundingClientRect();
    if (rect.width <= MIN_SIZE || rect.height <= MIN_SIZE) return true;
    return false;
  }

  /* ─── הסתרה ─── */

  function hideElement(el) {
    if (el.dataset.safemeAiHidden) return;
    el.dataset.safemeAiHidden = '1';
    el.style.visibility = 'hidden';

    if (!el.parentNode) return;
    var existing = el.nextElementSibling;
    if (existing && existing.classList.contains(PLACEHOLDER_CLASS)) return;

    var ph = document.createElement('div');
    ph.className = PLACEHOLDER_CLASS;
    ph.dir = 'rtl';
    ph.textContent = '🛡️ SafeMe: תמונה הוסתרה';
    el.parentNode.insertBefore(ph, el.nextSibling);
  }

  /* ─── עיבוד ─── */

  function processImg(img) {
    if (!active) return;
    if (img.dataset.safemeAiHidden) return;

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
    if (!active || canvas.dataset.safemeAiHidden) return;
    if (isContentSize(canvas) && !canvas.closest('nav, header, [role="banner"]')) {
      hideElement(canvas);
    }
  }

  function processVideo(video) {
    if (!active || video.dataset.safemeAiHidden) return;
    if (isContentSize(video) && !video.closest('nav, header, [role="banner"]')) {
      hideElement(video);
    }
  }

  function processNode(node) {
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
  }

  function processAll() {
    var imgs = document.querySelectorAll('img');
    for (var i = 0; i < imgs.length; i++) processImg(imgs[i]);
    var canvases = document.querySelectorAll('canvas');
    for (var j = 0; j < canvases.length; j++) processCanvas(canvases[j]);
    var videos = document.querySelectorAll('video');
    for (var k = 0; k < videos.length; k++) processVideo(videos[k]);
  }

  /* ─── MutationObserver ─── */

  var observer;
  function observe() {
    if (observer) return;
    observer = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var added = mutations[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          processNode(added[j]);
        }
      }
    });
    var target = document.body || document.documentElement;
    observer.observe(target, { childList: true, subtree: true });
  }

  /* ─── תקשורת עם background ─── */

  chrome.runtime.sendMessage({ type: 'safeme-get-config' }, function (resp) {
    if (chrome.runtime.lastError || !resp) return;
    if (resp.aiSafeMode) init();
  });

  chrome.runtime.onMessage.addListener(function (msg) {
    if (msg.type === 'safeme-config') {
      if (msg.config.aiSafeMode) init();
      else disable();
    }
  });
})();
