(function () {
  'use strict';

  var OVERLAY_ID = 'safeme-audio-only';
  var timer;

  function videoId() {
    return new URLSearchParams(location.search).get('v');
  }

  function isWatch() {
    return location.pathname === '/watch' && videoId();
  }

  function apply() {
    if (!isWatch()) { remove(); return; }

    var player = document.querySelector('#movie_player');
    if (!player) return;

    var id = videoId();
    var existing = document.getElementById(OVERLAY_ID);
    if (existing && existing.dataset.v === id) return;

    remove();

    var overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    overlay.dataset.v = id;
    overlay.style.backgroundImage =
      'url(https://i.ytimg.com/vi/' + encodeURIComponent(id) + '/maxresdefault.jpg)';

    var label = document.createElement('div');
    label.className = 'safeme-audio-label';
    label.dir = 'rtl';
    label.textContent = 'מצב שמע בלבד';
    overlay.appendChild(label);

    player.appendChild(overlay);
  }

  function remove() {
    var el = document.getElementById(OVERLAY_ID);
    if (el) el.remove();
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(apply, 150);
  }

  document.addEventListener('yt-navigate-finish', schedule);
  document.addEventListener('yt-page-data-updated', schedule);

  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', schedule);
  else
    schedule();
})();
