/* ==========================================================
   Gentleman’s Cut Warszawa: script.js
   Security model: never use innerHTML/eval/document.write.
   All text is written with textContent. All input is
   validated (allow-list), then sanitized before it is sent.
   Client-side checks are UX + defense in depth only: the
   receiving server MUST validate and escape again.
   ========================================================== */
(function () {
  'use strict'; // no silent errors, no accidental globals

  /* ---------- 1. State and DOM references ---------- */
  var lang = 'pl';
  var form = document.getElementById('form');
  var statusEl = document.getElementById('status');
  var sendBtn = document.getElementById('send');
  var langBtn = document.getElementById('lang');
  var errors = {};              // field name -> message key (so messages can be re-rendered on language change)
  var statusKey = '', statusArg = '';
  var loadedAt = Date.now();
  var attempts = [];            // timestamps of recent submissions
  var lastClick = 0, locked = false;
  var MAX_ATTEMPTS = 3, WINDOW = 60000, MIN_FILL_MS = 3000, DEBOUNCE_MS = 800;

  /* ---------- 2. All user-facing form texts, PL + EN ---------- */
  var MSG = {
    pl: {
      req: 'To pole jest wymagane.',
      name: 'Proszę podać imię (2 do 60 liter).',
      phone: 'Proszę podać polski numer, np. +48 600 000 000.',
      service: 'Proszę wybrać usługę.',
      date: 'Proszę podać datę w formacie dd.mm.rrrr (od jutra do 60 dni naprzód).',
      bad: 'Proszę usunąć niedozwolone znaki.'
    },
    en: {
      req: 'This field is required.',
      name: 'Please enter your name (2 to 60 letters).',
      phone: 'Please enter a Polish number, e.g. +48 600 000 000.',
      service: 'Please choose a service.',
      date: 'Enter a date as dd/mm/yyyy (from tomorrow, up to 60 days ahead).',
      bad: 'Please remove disallowed characters.'
    }
  };
  var REASON = {
    pl: { bot: 'podejrzana aktywność', limit: 'zbyt wiele prób' },
    en: { bot: 'suspicious activity', limit: 'too many attempts' }
  };
  var STATUS = {
    pl: {
      wait: 'Wysyłanie…',
      fix: 'Prosimy poprawić zaznaczone pola.',
      ok: function (name) { return 'Dziękujemy, ' + name + '. Termin potwierdzimy wiadomością SMS.'; },
      fail: 'Nie udało się wysłać. Prosimy zadzwonić: +48 22 123 45 67.',
      lock: function (r) { return 'Formularz został zablokowany (' + REASON.pl[r] + '). Zapraszamy do kontaktu telefonicznego: +48 22 123 45 67.'; }
    },
    en: {
      wait: 'Sending…',
      fix: 'Please correct the highlighted fields.',
      ok: function (name) { return 'Thank you, ' + name + '. We will confirm by SMS.'; },
      fail: 'Could not send. Please call: +48 22 123 45 67.',
      lock: function (r) { return 'Form locked (' + REASON.en[r] + '). Please call us: +48 22 123 45 67.'; }
    }
  };
  var ERROR_STATUS = { fix: 1, fail: 1, lock: 1 };

  // Messages are stored as KEYS and rendered from the active language,
  // so switching PL/EN re-translates errors that are already on screen.
  function renderErrors() {
    Object.keys(rules).forEach(function (k) {
      form.querySelector('[data-for="' + k + '"]').textContent = errors[k] ? MSG[lang][errors[k]] : '';
    });
  }
  function say(key, arg) { statusKey = key; statusArg = arg; renderStatus(); }
  function renderStatus() {
    var v = statusKey ? STATUS[lang][statusKey] : '';
    statusEl.textContent = typeof v === 'function' ? v(statusArg) : v;
    statusEl.classList.toggle('is-error', !!ERROR_STATUS[statusKey]);
  }

  /* ---------- 3. Language switch (PL <-> EN), textContent only ---------- */
  langBtn.addEventListener('click', function () {
    lang = lang === 'pl' ? 'en' : 'pl';
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-pl]').forEach(function (el) {
      el.textContent = el.getAttribute('data-' + lang); // safe sink
    });
    onLang();        // date field + calendar
    renderErrors();  // field errors already on screen
    renderStatus();  // form status line
  });

  /* ---------- 4. Sanitization ---------- */
  // Normalize, strip control/zero-width chars and tag-like strings, collapse whitespace, cap length.
  function clean(s, max) {
    return String(s)
      .normalize('NFKC')                                   // defeats unicode lookalike tricks
      .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028\u2029\uFEFF]/g, '')
      .replace(/<[^>]*>?/g, '')                            // drop anything tag-like
      .replace(/\s+/g, ' ').trim().slice(0, max);
  }
  // Patterns typical of XSS / SQL / template / path injection. Matching input is rejected, not "fixed".
  var ATTACK = /(javascript:|data:text|vbscript:|on\w+\s*=|<\s*script|\bunion\b[\s\S]*\bselect\b|\bdrop\s+table\b|--|;\s*(select|insert|update|delete)\b|\/\*|\*\/|\$\{|\{\{|\.\.\/|\bexec\b|\beval\s*\()/i;

  /* ---------- 5. Field rules (allow-list validation) ---------- */
  var SERVICES = ['classic', 'beard', 'shave', 'package'];
  var rules = {
    name: function (v) { return /^[\p{L}][\p{L} '’\-]{1,59}$/u.test(v) ? '' : 'name'; },
    phone: function (v) { return /^(\+48)?[ -]?\d{3}[ -]?\d{3}[ -]?\d{3}$/.test(v) ? '' : 'phone'; },
    service: function (v) { return SERVICES.indexOf(v) > -1 ? '' : 'service'; },
    date: function (v) { // dd.mm.yyyy or dd/mm/yyyy, a real calendar date, tomorrow .. +60 days
      var d = parseDate(v);
      return d && d >= minDate() && d <= maxDate() ? '' : 'date';
    },
    note: function () { return ''; } // optional, only sanitized
  };
  var limits = { name: 60, phone: 16, service: 12, date: 10, note: 300 };

  /* ---------- 6. Anti-bot: honeypot, time trap, debounce, rate limit ---------- */
  // Permanent lockdown for this page view: disable every control.
  function lockDown(reason) {
    locked = true;
    Array.prototype.forEach.call(form.elements, function (el) { el.disabled = true; });
    say('lock', reason);
  }
  // Debounce: ignore clicks that arrive faster than a human could repeat them.
  sendBtn.addEventListener('click', function (e) {
    var now = Date.now();
    if (now - lastClick < DEBOUNCE_MS) { e.preventDefault(); e.stopImmediatePropagation(); return; }
    lastClick = now;
  }, true);

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var fd = new FormData(form);

    if (fd.get('website')) { lockDown('bot'); return; }                 // honeypot: humans never see this field
    if (Date.now() - loadedAt < MIN_FILL_MS) { lockDown('bot'); return; } // time trap: under 3 s is a script

    var now = Date.now();                                               // rate limit: 3 submissions per minute
    attempts = attempts.filter(function (t) { return now - t < WINDOW; });
    if (attempts.length >= MAX_ATTEMPTS) { lockDown('limit'); return; }
    attempts.push(now);

    var data = {}, ok = true;
    Object.keys(rules).forEach(function (k) {
      var raw = clean(fd.get(k) || '', limits[k]);
      var errKey = '';
      if (!raw && k !== 'note') errKey = 'req';
      else if (raw && ATTACK.test(String(fd.get(k)))) errKey = 'bad'; // test the ORIGINAL input
      else if (raw) errKey = rules[k](raw);
      errors[k] = errKey;
      form.elements[k].setAttribute('aria-invalid', errKey ? 'true' : 'false');
      if (errKey) ok = false;
      // Dates are normalized to dd.mm.yyyy for the owner's e-mail. Always render values with textContent, never innerHTML.
      data[k] = (k === 'date' && !errKey) ? fmt(parseDate(raw), '.') : raw;
    });
    renderErrors();
    if (!ok) { say('fix'); return; }
    send(data);
  });

  /* ---------- 7. Real delivery via Web3Forms (free; the key is public by design) ---------- */
  var ENDPOINT = 'https://api.web3forms.com/submit';   // whitelisted in the CSP connect-src
  var ACCESS_KEY = 'WSTAW_TUTAJ_KLUCZ_WEB3FORMS';      // from web3forms.com (sent to your inbox)
  var LABELS = { classic: 'Strzyżenie klasyczne', beard: 'Pielęgnacja brody', shave: 'Golenie brzytwą', package: 'Pakiet Gentleman' };

  function send(d) {
    sendBtn.disabled = true;
    say('wait');
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, 10000); // 10 s network timeout
    fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'omit',                                        // never send cookies
      signal: ctrl.signal,
      body: JSON.stringify({
        access_key: ACCESS_KEY,
        subject: 'Nowa rezerwacja: ' + LABELS[d.service] + ', ' + d.date,
        from_name: 'Gentleman’s Cut: formularz',
        name: d.name, phone: d.phone, service: LABELS[d.service], date: d.date,
        message: d.note || '-',
        botcheck: ''                                              // Web3Forms' own honeypot
      })
    })
    .then(function (r) { return r.json(); })
    .then(function (res) {
      if (!res.success) throw new Error('rejected');
      form.reset();
      loadedAt = Date.now();
      say('ok', d.name);
    })
    .catch(function () { say('fail'); })                          // network error, timeout or rejection
    .finally(function () { clearTimeout(timer); if (!locked) sendBtn.disabled = false; });
  }

  /* ---------- 8. Date field: text mask + localized calendar (no <input type="date">) ---------- */
  var MONTHS = {
    pl: ['Styczeń', 'Luty', 'Marzec', 'Kwiecień', 'Maj', 'Czerwiec', 'Lipiec', 'Sierpień', 'Wrzesień', 'Październik', 'Listopad', 'Grudzień'],
    en: ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
  };
  var WEEKDAYS = { pl: ['Pn', 'Wt', 'Śr', 'Cz', 'Pt', 'So', 'Nd'], en: ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su'] }; // weeks start on Monday
  var dateInput = document.getElementById('date');
  var calBtn = document.getElementById('cal-btn');
  var cal = document.getElementById('cal');
  var dwrap = dateInput.parentNode;
  var viewY = 0, viewM = 0, isOpen = false;

  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function sep() { return lang === 'pl' ? '.' : '/'; }
  function fmt(d, s) { return pad(d.getDate()) + s + pad(d.getMonth() + 1) + s + d.getFullYear(); }
  function today0() { var n = new Date(); n.setHours(0, 0, 0, 0); return n; }
  function minDate() { var d = today0(); d.setDate(d.getDate() + 1); return d; }
  function maxDate() { var d = today0(); d.setDate(d.getDate() + 60); return d; }
  function monthIndex(d) { return d.getFullYear() * 12 + d.getMonth(); }
  // Strict parser: rejects 31.02.2026 and anything that is not dd.mm.yyyy / dd/mm/yyyy.
  function parseDate(s) {
    var m = /^(\d{2})[.\/](\d{2})[.\/](\d{4})$/.exec(s);
    if (!m) return null;
    var d = new Date(+m[3], +m[2] - 1, +m[1]);
    return d.getFullYear() === +m[3] && d.getMonth() === +m[2] - 1 && d.getDate() === +m[1] ? d : null;
  }
  function node(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text; // textContent only
    return e;
  }

  // Mask: keep digits only and insert the separator of the active language.
  dateInput.addEventListener('input', function () {
    var dg = dateInput.value.replace(/\D/g, '').slice(0, 8), out = dg.slice(0, 2);
    if (dg.length > 2) out += sep() + dg.slice(2, 4);
    if (dg.length > 4) out += sep() + dg.slice(4);
    dateInput.value = out;
    var d = parseDate(out);
    if (d) { viewY = d.getFullYear(); viewM = d.getMonth(); }
    if (isOpen) renderCal();
  });

  function pick(d) {
    dateInput.value = fmt(d, sep());
    dateInput.setAttribute('aria-invalid', 'false');
    errors.date = '';
    renderErrors();
    closeCal();
    dateInput.focus();
  }

  function renderCal() {
    var min = minDate(), max = maxDate(), sel = parseDate(dateInput.value), td = today0();
    cal.textContent = '';
    var head = node('div', 'cal-head');
    var prev = node('button', 'cal-nav', '\u2039'), next = node('button', 'cal-nav', '\u203A');
    prev.type = next.type = 'button';
    prev.setAttribute('aria-label', lang === 'pl' ? 'Poprzedni miesiąc' : 'Previous month');
    next.setAttribute('aria-label', lang === 'pl' ? 'Następny miesiąc' : 'Next month');
    prev.disabled = viewY * 12 + viewM <= monthIndex(min);
    next.disabled = viewY * 12 + viewM >= monthIndex(max);
    prev.addEventListener('click', function () { viewM--; if (viewM < 0) { viewM = 11; viewY--; } renderCal(); });
    next.addEventListener('click', function () { viewM++; if (viewM > 11) { viewM = 0; viewY++; } renderCal(); });
    head.appendChild(prev); head.appendChild(node('div', 'cal-title', MONTHS[lang][viewM] + ' ' + viewY)); head.appendChild(next);

    var grid = node('div', 'cal-grid');
    WEEKDAYS[lang].forEach(function (w) { grid.appendChild(node('span', 'cal-wd', w)); });
    for (var b = (new Date(viewY, viewM, 1).getDay() + 6) % 7; b > 0; b--) grid.appendChild(node('span'));
    for (var i = 1, n = new Date(viewY, viewM + 1, 0).getDate(); i <= n; i++) {
      (function (d) {
        var btn = node('button', 'cal-day', String(d.getDate()));
        btn.type = 'button';
        btn.disabled = d < min || d > max;
        if (+d === +td) btn.classList.add('today');
        if (sel && +d === +sel) btn.classList.add('sel');
        btn.addEventListener('click', function () { pick(d); });
        grid.appendChild(btn);
      })(new Date(viewY, viewM, i));
    }
    cal.appendChild(head); cal.appendChild(grid);
  }
  function openCal() {
    var d = parseDate(dateInput.value) || minDate();
    viewY = d.getFullYear(); viewM = d.getMonth();
    isOpen = true; renderCal();
    cal.classList.add('open'); calBtn.setAttribute('aria-expanded', 'true');
  }
  function closeCal() { isOpen = false; cal.classList.remove('open'); calBtn.setAttribute('aria-expanded', 'false'); }

  calBtn.addEventListener('click', function () { if (isOpen) closeCal(); else openCal(); });
  cal.addEventListener('click', function (e) { e.preventDefault(); }); // clicks inside the popup must not activate the parent <label>
  dwrap.addEventListener('keydown', function (e) { if (e.key === 'Escape' && isOpen) { closeCal(); calBtn.focus(); } });
  // composedPath is captured at dispatch time, so it still works after the calendar re-renders its own nodes.
  document.addEventListener('click', function (e) { if (isOpen && e.composedPath().indexOf(dwrap) === -1) closeCal(); });
  form.addEventListener('reset', closeCal);

  // Called by the PL/EN switch: placeholder, separator of the typed date, aria labels, calendar texts.
  function onLang() {
    dateInput.placeholder = lang === 'pl' ? 'dd.mm.rrrr' : 'dd/mm/yyyy';
    var d = parseDate(dateInput.value);
    dateInput.value = d ? fmt(d, sep()) : dateInput.value.replace(/[.\/]/g, sep());
    calBtn.setAttribute('aria-label', lang === 'pl' ? 'Otwórz kalendarz' : 'Open calendar');
    cal.setAttribute('aria-label', lang === 'pl' ? 'Kalendarz' : 'Calendar');
    if (isOpen) renderCal();
  }
})();
