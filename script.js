/* ==========================================================
   Gentleman's Cut Warszawa: script.js
   Security model: never use innerHTML/eval/document.write.
   All text is written with textContent. All input is
   validated (allow-list), sanitized, then escaped.
   IMPORTANT: client-side checks are UX + defense in depth.
   The server MUST re-validate and escape everything again.
   ========================================================== */
(function () {
  'use strict'; // strict mode: no silent errors, no accidental globals

  /* ---------- 1. Language switch (PL <-> EN), textContent only ---------- */
  var langBtn = document.getElementById('lang');
  var lang = 'pl';
  langBtn.addEventListener('click', function () {
    lang = lang === 'pl' ? 'en' : 'pl';
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-pl]').forEach(function (el) {
      el.textContent = el.getAttribute('data-' + lang); // safe sink
    });
  });

  /* ---------- 2. Sanitization helpers ---------- */
  // Normalize, strip control/zero-width chars and tags, collapse whitespace.
  function clean(s, max) {
    return String(s)
      .normalize('NFKC')                                   // defeats unicode lookalike tricks
      .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028\u2029\uFEFF]/g, '')
      .replace(/<[^>]*>?/g, '')                            // drop anything tag-like
      .replace(/\s+/g, ' ').trim().slice(0, max);
  }

  // Patterns typical of XSS / SQL / template / path injection. Matching input is rejected, not "fixed".
  var ATTACK = /(javascript:|data:text|vbscript:|on\w+\s*=|<\s*script|\bunion\b[\s\S]*\bselect\b|\bdrop\s+table\b|--|;\s*(select|insert|update|delete)\b|\/\*|\*\/|\$\{|\{\{|\.\.\/|\bexec\b|\beval\s*\()/i;

  /* ---------- 3. Field rules (allow-list validation) ---------- */
  var SERVICES = ['classic', 'beard', 'shave', 'package'];
  var MSG = {
    pl: { req: 'To pole jest wymagane.', name: 'Proszę podać imię (2 do 60 liter).', phone: 'Proszę podać polski numer, np. +48 600 000 000.', service: 'Proszę wybrać usługę.', date: 'Proszę wybrać dzień od jutra do 60 dni naprzód.', bad: 'Proszę usunąć niedozwolone znaki.' },
    en: { req: 'This field is required.', name: 'Use letters only (2 to 60 characters).', phone: 'Enter a Polish number, e.g. +48 600 000 000.', service: 'Choose a service.', date: 'Pick a day from tomorrow to 60 days out.', bad: 'Remove disallowed characters.' }
  };
  var rules = {
    name: function (v) { return /^[\p{L}][\p{L} '\-]{1,59}$/u.test(v) ? '' : 'name'; },
    phone: function (v) { return /^(\+48)?[ -]?\d{3}[ -]?\d{3}[ -]?\d{3}$/.test(v) ? '' : 'phone'; },
    service: function (v) { return SERVICES.indexOf(v) > -1 ? '' : 'service'; },
    date: function (v) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return 'date';
      var d = new Date(v + 'T00:00:00'), now = new Date(); now.setHours(0, 0, 0, 0);
      var days = (d - now) / 864e5;
      return days >= 1 && days <= 60 ? '' : 'date';
    },
    note: function () { return ''; } // optional, only sanitized
  };
  var limits = { name: 60, phone: 16, service: 12, date: 10, note: 300 };

  /* ---------- 4. Anti-bot: honeypot, time trap, debounce, rate limit ---------- */
  var form = document.getElementById('form');
  var status = document.getElementById('status');
  var sendBtn = document.getElementById('send');
  var loadedAt = Date.now();
  var attempts = [];            // timestamps of recent submissions
  var lastClick = 0, locked = false;
  var MAX_ATTEMPTS = 3, WINDOW = 60000, MIN_FILL_MS = 3000, DEBOUNCE_MS = 800;

  function say(key, text) { status.textContent = text; status.dataset.key = key; }

  // Permanent lockdown for this page view: disable every control.
  function lockDown(reason) {
    locked = true;
    Array.prototype.forEach.call(form.elements, function (el) { el.disabled = true; });
    say('lock', lang === 'pl' ? 'Formularz został zablokowany (' + reason + '). Zapraszamy do kontaktu telefonicznego: +48 22 123 45 67.' : 'Form locked (' + reason + '). Please call: +48 22 123 45 67.');
  }

  // Debounce: ignore clicks that arrive faster than a human could repeat them.
  sendBtn.addEventListener('click', function (e) {
    var now = Date.now();
    if (now - lastClick < DEBOUNCE_MS) { e.preventDefault(); e.stopImmediatePropagation(); return; }
    lastClick = now;
  }, true);

  /* ---------- 5. Submit handler ---------- */
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var fd = new FormData(form);

    // Honeypot: real users never see this field.
    if (fd.get('website')) { lockDown('bot'); return; }

    // Time trap: a form filled in under 3 seconds is a script.
    if (Date.now() - loadedAt < MIN_FILL_MS) { lockDown('bot'); return; }

    // Rate limit: max 3 submissions per minute.
    var now = Date.now();
    attempts = attempts.filter(function (t) { return now - t < WINDOW; });
    if (attempts.length >= MAX_ATTEMPTS) { lockDown('limit'); return; }
    attempts.push(now);

    // Validate + sanitize every field.
    var data = {}, ok = true, m = MSG[lang];
    Object.keys(rules).forEach(function (k) {
      var raw = clean(fd.get(k) || '', limits[k]);
      var errKey = '';
      if (!raw && k !== 'note') errKey = 'req';
      else if (raw && ATTACK.test(String(fd.get(k)))) errKey = 'bad'; // test the ORIGINAL input
      else if (raw) errKey = rules[k](raw);
      var field = form.elements[k], out = form.querySelector('[data-for="' + k + '"]');
      out.textContent = errKey ? m[errKey] : '';
      field.setAttribute('aria-invalid', errKey ? 'true' : 'false');
      if (errKey) ok = false;
      data[k] = raw; // sanitized + validated value; always render it with textContent, never innerHTML
    });
    if (!ok) { say('err', lang === 'pl' ? 'Prosimy poprawić zaznaczone pola.' : 'Please fix the highlighted fields.'); return; }

    send(data);
  });

  /* ---------- 6. Real delivery via Web3Forms (free; key is public by design) ---------- */
  var ENDPOINT = 'https://api.web3forms.com/submit';   // whitelisted in CSP connect-src
  var ACCESS_KEY = 'WSTAW_TUTAJ_KLUCZ_WEB3FORMS';      // from web3forms.com (sent to your inbox)
  var LABELS = { classic: 'Strzyżenie klasyczne', beard: 'Pielęgnacja brody', shave: 'Golenie brzytwą', package: 'Pakiet Gentleman' };

  function send(d) {
    sendBtn.disabled = true;
    say('wait', lang === 'pl' ? 'Wysyłanie…' : 'Sending…');
    status.classList.remove('is-error');
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
        from_name: "Gentleman's Cut: formularz",
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
      say('ok', lang === 'pl' ? 'Dziękujemy, ' + d.name + '. Termin potwierdzimy wiadomością SMS.' : 'Thank you, ' + d.name + '. We will confirm by SMS.');
    })
    .catch(function () {                                          // network error, timeout or rejection
      status.classList.add('is-error');
      say('err', lang === 'pl' ? 'Nie udało się wysłać. Prosimy zadzwonić: +48 22 123 45 67.' : 'Could not send. Please call: +48 22 123 45 67.');
    })
    .finally(function () { clearTimeout(timer); if (!locked) sendBtn.disabled = false; });
  }

  // Date input: only allow tomorrow onward in the picker UI.
  var t = new Date(); t.setDate(t.getDate() + 1);
  form.elements.date.min = t.toISOString().slice(0, 10);
})();
