(function () {
  'use strict';

  var OVERLAY_ID = 'safeme-audio-only';
  var timer;
  var config = { audioOnly: true, hideThumbnails: true, allowedChannels: [] };

  /*
   * הסרטון שהרקע אישר כשייך לערוץ מותר. ההחלטה עצמה ברקע, לפי
   * כתובת הלשונית; כאן רק מורידים את הכיסוי כשהתשובה חיובית.
   */
  var allowedVideo = null;
  var statusSeq = 0;

  function videoId() {
    return new URLSearchParams(location.search).get('v');
  }

  function isWatch() {
    return location.pathname === '/watch' && videoId();
  }

  function currentAllowed() {
    return !!(isWatch() && allowedVideo && allowedVideo === videoId());
  }

  function applyOverlay() {
    if (!config.audioOnly || !isWatch() || currentAllowed()) { removeOverlay(); return; }

    var player = document.querySelector('#movie_player');
    if (!player) return;

    var id = videoId();
    var existing = document.getElementById(OVERLAY_ID);
    if (existing && existing.dataset.v === id) return;

    removeOverlay();

    var overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    overlay.dataset.v = id;

    var logo = document.createElement('div');
    logo.className = 'safeme-logo';

    var shield = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    shield.setAttribute('viewBox', '0 0 24 24');
    shield.setAttribute('width', '64');
    shield.setAttribute('height', '64');
    shield.setAttribute('fill', 'none');
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5zm0 3.88L16.5 9v3.5c0 3.47-2.04 6.7-4.5 7.94-2.46-1.24-4.5-4.47-4.5-7.94V9L12 5.88z');
    path.setAttribute('fill', '#4fc3f7');
    shield.appendChild(path);
    var check = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    check.setAttribute('d', 'M10 14.2l-2.6-2.6L6 13l4 4 8-8-1.4-1.4L10 14.2z');
    check.setAttribute('fill', '#4fc3f7');
    shield.appendChild(check);
    logo.appendChild(shield);

    var title = document.createElement('div');
    title.className = 'safeme-logo-title';
    title.textContent = 'SafeMe';
    logo.appendChild(title);

    overlay.appendChild(logo);

    var label = document.createElement('div');
    label.className = 'safeme-audio-label';
    label.dir = 'rtl';
    label.textContent = '♫  מצב שמע בלבד';
    overlay.appendChild(label);

    player.appendChild(overlay);
  }

  function removeOverlay() {
    var el = document.getElementById(OVERLAY_ID);
    if (el) el.remove();
  }

  function hideThumbnails() {
    if (!config.hideThumbnails) return;
    var sel = 'ytd-thumbnail, ytd-playlist-thumbnail, yt-thumbnail-view-model';
    var thumbs = document.querySelectorAll(sel);
    for (var i = 0; i < thumbs.length; i++) {
      var el = thumbs[i];
      if (el.dataset.safemeHidden) continue;
      el.dataset.safemeHidden = '1';
      el.style.cssText += 'background:#1a2a3a!important;overflow:hidden!important;border-radius:8px!important;position:relative!important;';
      var imgs = el.querySelectorAll('img');
      for (var j = 0; j < imgs.length; j++) {
        imgs[j].style.visibility = 'hidden';
      }
    }
    var loose = document.querySelectorAll('img[src*="ytimg.com/vi/"]');
    for (var k = 0; k < loose.length; k++) {
      var img = loose[k];
      if (img.dataset.safemeHidden) continue;
      var container = img.closest('yt-thumbnail-view-model, ytd-thumbnail, ytd-playlist-thumbnail');
      if (container) continue;
      img.dataset.safemeHidden = '1';
      img.style.visibility = 'hidden';
    }
  }

  var thumbObserver;
  function startThumbObserver() {
    if (thumbObserver || !config.hideThumbnails) return;
    thumbObserver = new MutationObserver(function () { hideThumbnails(); });
    thumbObserver.observe(document.body, { childList: true, subtree: true });
  }

  function applyClasses() {
    document.documentElement.classList.toggle('safeme-audio-only', config.audioOnly && !currentAllowed());
    document.documentElement.classList.toggle('safeme-hide-thumbnails', config.hideThumbnails);
  }

  function applyAll() {
    applyClasses();
    applyOverlay();
    hideThumbnails();
    startThumbObserver();
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(applyAll, 150);
  }

  /*
   * הנגן התחיל לטעון לפני שההיתר הגיע, ובקשות הווידאו נחסמו. אם
   * אחרי ההיתר עדיין אין תמונה, טוענים את הדף מחדש מאותה נקודה —
   * פעם אחת לכל סרטון, כדי שלא תיווצר לולאה.
   */
  function ensurePicture(id) {
    setTimeout(function () {
      if (!currentAllowed() || videoId() !== id) return;
      var video = document.querySelector('#movie_player video');
      if (!video || video.videoWidth > 0) return;

      var flag = 'safeme-reloaded-' + id;
      if (sessionStorage.getItem(flag)) return;
      sessionStorage.setItem(flag, '1');

      var url = new URL(location.href);
      var t = Math.floor(video.currentTime || 0);
      if (t > 0) url.searchParams.set('t', t + 's');
      location.replace(url.toString());
    }, 2500);
  }

  function checkStatus() {
    allowedVideo = null;
    if (!config.audioOnly || !config.allowedChannels || config.allowedChannels.length === 0 || !isWatch()) return;

    var seq = ++statusSeq;
    var id = videoId();
    chrome.runtime.sendMessage({ type: 'safeme-video-status' }, function (resp) {
      if (chrome.runtime.lastError || !resp || seq !== statusSeq) return;
      if (resp.allowed && resp.videoId === id && videoId() === id) {
        allowedVideo = id;
        schedule();
        ensurePicture(id);
      }
    });
  }

  function onNavigateFinish() {
    checkStatus();
    schedule();
  }

  chrome.runtime.sendMessage({ type: 'safeme-get-config' }, function (resp) {
    if (chrome.runtime.lastError || !resp) return;
    config = resp;
    checkStatus();
    schedule();
  });

  chrome.runtime.onMessage.addListener(function (msg) {
    if (msg.type === 'safeme-config') {
      config = msg.config;
      checkStatus();
      schedule();
    }
  });

  // יציאה מסרטון מותר: הכיסוי חוזר מיד וההיתר ברקע יורד.
  document.addEventListener('yt-navigate-start', function () {
    statusSeq++;
    if (allowedVideo) {
      allowedVideo = null;
      applyClasses();
    }
    chrome.runtime.sendMessage({ type: 'safeme-leave' }, function () { void chrome.runtime.lastError; });
  });

  document.addEventListener('yt-navigate-finish', onNavigateFinish);
  document.addEventListener('yt-page-data-updated', schedule);

  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', schedule);
  else
    schedule();
})();
