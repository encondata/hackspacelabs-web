// Behaviour for demo.html only. Not part of the kit.
(function () {
  'use strict';
  var $ = function (sel) {
    return document.querySelector(sel);
  };
  var result = $('#demo-result');
  $('#demo-version').textContent = 'v' + window.HSLSuite.version;

  // The app switcher's list, as an app would pass it from HSL_SUITE_APPS.
  $('#demo-switcher').setAttribute(
    'apps',
    JSON.stringify([
      { id: 'portal', name: 'HackSpaceLabs', url: 'https://hackspacelabs.com/apps', description: 'Apps and account' },
      { id: 'slipway', name: 'Slipway', url: 'https://slipway.hackspacelabs.com', description: 'Deploys' },
      { id: 'switchyard', name: 'Switchyard', url: 'http://192.168.1.10:8080', description: 'Proxy and certificates' },
      { id: 'harbormaster', name: 'Harbor Master', url: 'https://harbormaster.hackspacelabs.com', description: 'Boards and wiki' },
      { id: 'tideline', name: 'Tideline', url: 'https://tideline.hackspacelabs.com', description: 'Logs' },
    ]),
  );
  $('#demo-user').addEventListener('hsl-signout', function () {
    result.textContent = 'hsl-signout fired: the app would sign out here.';
  });

  // Views
  var buttons = document.querySelectorAll('[data-view]');
  function show(view) {
    document.querySelectorAll('[data-demo]').forEach(function (s) {
      s.hidden = s.getAttribute('data-demo') !== view;
    });
    buttons.forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-view') === view));
    });
    result.textContent = '';
    try {
      history.replaceState(null, '', '#' + view);
    } catch (e) {
      /* ignore */
    }
  }
  buttons.forEach(function (b) {
    b.addEventListener('click', function () {
      show(b.getAttribute('data-view'));
    });
  });
  var start = location.hash.slice(1);
  show(document.querySelector('[data-demo="' + start + '"]') ? start : 'frame');

  // Theme
  var themeButton = $('#demo-theme');
  function syncTheme() {
    themeButton.textContent = 'Dark mode: ' + (window.HSLSuite.theme.get() === 'dark' ? 'on' : 'off');
    drawSwatches();
  }
  themeButton.addEventListener('click', function () {
    window.HSLSuite.theme.toggle();
  });
  document.addEventListener('hsl-themechange', syncTheme);

  // Token swatches (CSSOM writes are allowed under style-src 'self'; markup style attributes are not).
  var TOKENS = ['--bg', '--surface', '--surface-2', '--text', '--muted', '--faint', '--border', '--border-strong',
    '--logo-ink', '--accent', '--accent-hover', '--accent-soft', '--accent-text', '--ok', '--ok-bg', '--bad', '--bad-bg',
    '--bad-border', '--warn', '--warn-bg', '--warn-border', '--notice-bg', '--off', '--off-bg', '--success-bg',
    '--add-bg', '--del-bg', '--code-bg', '--series-1', '--series-2', '--grid', '--c0', '--c2', '--c3', '--c4', '--c5'];
  function drawSwatches() {
    var box = $('#demo-swatches');
    box.textContent = '';
    TOKENS.forEach(function (name) {
      var row = document.createElement('div');
      row.className = 'demo-swatch';
      var chip = document.createElement('span');
      chip.className = 'demo-chip';
      chip.style.background = 'var(' + name + ')';
      var label = document.createElement('code');
      label.textContent = name;
      row.appendChild(chip);
      row.appendChild(label);
      box.appendChild(row);
    });
  }
  syncTheme();

  // ---------------------------------------------------------------- contrast check
  // Every visible text in the current view (menus opened for the check), against the colour actually
  // behind it, by WCAG 2.1: 4.5:1, or 3:1 for large text (24px, or 18.66px bold).
  var canvas = document.createElement('canvas');
  canvas.width = canvas.height = 1;
  var ctx = canvas.getContext('2d', { willReadFrequently: true });
  function rgba(css) {
    ctx.clearRect(0, 0, 1, 1);
    ctx.fillStyle = '#000';
    ctx.fillStyle = css;
    ctx.fillRect(0, 0, 1, 1);
    var d = ctx.getImageData(0, 0, 1, 1).data;
    return [d[0], d[1], d[2], d[3] / 255];
  }
  function over(top, bottom) {
    var a = top[3];
    return [0, 1, 2].map(function (i) {
      return top[i] * a + bottom[i] * (1 - a);
    }).concat(1);
  }
  function background(node) {
    var layers = [];
    for (var n = node; n && n.nodeType === 1; n = n.parentElement) {
      var c = rgba(getComputedStyle(n).backgroundColor);
      if (c[3] > 0) layers.push(c);
      if (c[3] === 1) break;
    }
    var base = rgba(getComputedStyle(document.documentElement).backgroundColor);
    if (base[3] < 1) base = [255, 255, 255, 1];
    return layers.reverse().reduce(function (acc, layer) {
      return over(layer, acc);
    }, base);
  }
  function luminance(c) {
    var v = c.slice(0, 3).map(function (x) {
      x /= 255;
      return x <= 0.04045 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
  }
  function ratio(a, b) {
    var la = luminance(a);
    var lb = luminance(b);
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
  }
  function check() {
    var view = document.querySelector('[data-demo]:not([hidden])');
    var pops = Array.prototype.slice.call(view.querySelectorAll('.hsl-pop'));
    var was = pops.map(function (p) {
      return p.hidden;
    });
    pops.forEach(function (p) {
      p.hidden = false;
    });
    var walker = document.createTreeWalker(view, NodeFilter.SHOW_TEXT);
    var seen = 0;
    var failures = [];
    for (var t = walker.nextNode(); t; t = walker.nextNode()) {
      var elem = t.parentElement;
      if (!t.textContent.trim() || !elem || elem.closest('[aria-hidden="true"]') || elem.closest(':disabled')) continue;
      var box = elem.getBoundingClientRect();
      if (box.width === 0 || box.height === 0) continue;
      var cs = getComputedStyle(elem);
      if (cs.visibility === 'hidden' || cs.opacity === '0') continue;
      var bg = background(elem);
      var fg = over(rgba(cs.color), bg);
      var size = parseFloat(cs.fontSize);
      var large = size >= 24 || (size >= 18.66 && Number(cs.fontWeight) >= 700);
      var need = large ? 3 : 4.5;
      var r = ratio(fg, bg);
      seen += 1;
      if (r < need) failures.push(r.toFixed(2) + ':1 (needs ' + need + ') "' + t.textContent.trim().slice(0, 40) + '"');
    }
    pops.forEach(function (p, i) {
      p.hidden = was[i];
    });
    return { theme: window.HSLSuite.theme.get(), checked: seen, failures: failures };
  }
  $('#demo-contrast').addEventListener('click', function () {
    var r = check();
    result.textContent = r.failures.length
      ? r.failures.length + ' of ' + r.checked + ' texts below WCAG AA (' + r.theme + '):\n' + r.failures.join('\n')
      : 'All ' + r.checked + ' texts pass WCAG AA contrast (' + r.theme + ').';
  });
  window.HSLDemo = { check: check, show: show };
})();
