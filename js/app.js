'use strict';

(function () {
  const grid = document.getElementById('grid');
  const empty = document.getElementById('empty');
  const searchInput = document.getElementById('search');
  const resultCount = document.getElementById('resultCount');
  const langChips = document.getElementById('langChips');
  const purposeChips = document.getElementById('purposeChips');
  const resetBtn = document.getElementById('resetFilters');
  const emptyReset = document.getElementById('emptyReset');
  const overlay = document.getElementById('overlay');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');
  const modalClose = document.getElementById('modalClose');

  const filter = { q: '', langs: new Set(), purposes: new Set() };
  let lastFocus = null;

  /* ---------- helpers ---------- */

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function defaultStateFor(script) {
    const sel = {};
    (script.options || []).forEach(g => {
      if (g.type === 'multi') sel[g.id] = new Set(g.items.filter(i => i.default).map(i => i.id));
      else if (g.type === 'single') sel[g.id] = (g.items.find(i => i.default) || g.items[0]).id;
      else sel[g.id] = g.value || '';
    });
    return sel;
  }

  function codeFor(script, sel) {
    return script.build ? script.build(sel || defaultStateFor(script)) : script.code;
  }

  async function copyText(text, btn) {
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (err) {
      // Fallback for contexts without the async clipboard API.
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (err2) { /* ignore */ }
      ta.remove();
    }
    if (btn) {
      if (!btn.dataset.label) btn.dataset.label = btn.textContent;
      btn.textContent = ok ? 'Copied!' : 'Copy failed';
      btn.classList.add('flash');
      clearTimeout(btn._flashTimer);
      btn._flashTimer = setTimeout(() => {
        btn.textContent = btn.dataset.label;
        btn.classList.remove('flash');
      }, 1400);
    }
  }

  /* ---------- searchable text, computed once ---------- */

  SCRIPTS.forEach(s => {
    s._defaultCode = codeFor(s);
    s._search = [s.title, s.description, s.language, s.purposes.join(' '), s.keywords || '', s._defaultCode]
      .join(' ').toLowerCase();
  });

  /* ---------- filter chips ---------- */

  function tally(getter) {
    const map = new Map();
    SCRIPTS.forEach(s => getter(s).forEach(v => map.set(v, (map.get(v) || 0) + 1)));
    return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }

  function renderChips(container, entries, active) {
    container.textContent = '';
    const all = el('button', 'chip' + (active.size ? '' : ' active'), 'All');
    all.type = 'button';
    all.addEventListener('click', () => { active.clear(); refresh(); });
    container.appendChild(all);
    entries.forEach(([value, count]) => {
      const chip = el('button', 'chip' + (active.has(value) ? ' active' : ''));
      chip.type = 'button';
      chip.appendChild(el('span', '', value));
      chip.appendChild(el('span', 'chip-count', String(count)));
      chip.addEventListener('click', () => {
        if (active.has(value)) active.delete(value); else active.add(value);
        refresh();
      });
      container.appendChild(chip);
    });
  }

  function matches(s) {
    if (filter.langs.size && !filter.langs.has(s.language)) return false;
    if (filter.purposes.size && !s.purposes.some(p => filter.purposes.has(p))) return false;
    if (filter.q) {
      const tokens = filter.q.split(/\s+/).filter(Boolean);
      if (!tokens.every(t => s._search.includes(t))) return false;
    }
    return true;
  }

  /* ---------- cards ---------- */

  function makeCard(s) {
    const card = el('article', 'card');
    card.tabIndex = 0;
    card.setAttribute('role', 'button');
    card.setAttribute('aria-label', 'Open options for ' + s.title);

    const head = el('div', 'card-head');
    head.appendChild(el('h3', '', s.title));
    const badge = el('span', 'badge', s.language);
    badge.dataset.lang = s.language.toLowerCase();
    head.appendChild(badge);
    card.appendChild(head);

    const tags = el('div', 'tags');
    s.purposes.forEach(p => tags.appendChild(el('span', 'tag', p)));
    card.appendChild(tags);

    card.appendChild(el('p', 'desc', s.description));
    card.appendChild(el('pre', 'code-preview', s._defaultCode));

    const foot = el('div', 'card-foot');
    const copyBtn = el('button', 'btn', 'Copy');
    copyBtn.type = 'button';
    copyBtn.addEventListener('click', e => { e.stopPropagation(); copyText(s._defaultCode, copyBtn); });
    const detailBtn = el('button', 'btn btn-primary', s.options ? 'Options' : 'View');
    detailBtn.type = 'button';
    detailBtn.addEventListener('click', e => { e.stopPropagation(); openModal(s); });
    foot.append(copyBtn, detailBtn);
    card.appendChild(foot);

    card.addEventListener('click', () => openModal(s));
    card.addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target === card) {
        e.preventDefault();
        openModal(s);
      }
    });
    return card;
  }

  function refresh() {
    renderChips(langChips, tally(s => [s.language]), filter.langs);
    renderChips(purposeChips, tally(s => s.purposes), filter.purposes);

    const list = SCRIPTS.filter(matches);
    grid.textContent = '';
    const frag = document.createDocumentFragment();
    list.forEach(s => frag.appendChild(makeCard(s)));
    grid.appendChild(frag);

    // Fade out card previews only when the code is actually clipped.
    grid.querySelectorAll('.code-preview').forEach(pre => {
      if (pre.scrollHeight > pre.clientHeight + 4) pre.classList.add('clipped');
    });

    resultCount.textContent = list.length + ' of ' + SCRIPTS.length + ' scripts';
    empty.hidden = list.length > 0;
    grid.hidden = list.length === 0;
  }

  function clearFilters() {
    filter.q = '';
    filter.langs.clear();
    filter.purposes.clear();
    searchInput.value = '';
    refresh();
  }

  /* ---------- detail modal ---------- */

  function renderOptionGroups(script, sel, host, updatePreview) {
    host.textContent = '';
    (script.options || []).forEach(g => {
      const block = el('section', 'opt-group' + (g.wide ? ' wide' : ''));
      block.appendChild(el('div', 'opt-title', g.label));
      if (g.hint) block.appendChild(el('p', 'opt-hint', g.hint));

      if (g.type === 'multi') {
        const wrap = el('div', 'opt-grid');
        g.items.forEach(item => {
          const label = el('label', 'check');
          if (item.hint) label.title = item.hint;
          const box = document.createElement('input');
          box.type = 'checkbox';
          box.checked = sel[g.id].has(item.id);
          box.addEventListener('change', () => {
            if (box.checked) sel[g.id].add(item.id); else sel[g.id].delete(item.id);
            updatePreview();
          });
          label.append(box, el('span', '', item.label));
          wrap.appendChild(label);
        });
        block.appendChild(wrap);
      } else if (g.type === 'single') {
        const wrap = el('div', 'opt-row');
        g.items.forEach(item => {
          const label = el('label', 'radio');
          const radio = document.createElement('input');
          radio.type = 'radio';
          radio.name = script.id + '-' + g.id;
          radio.checked = sel[g.id] === item.id;
          radio.addEventListener('change', () => {
            if (radio.checked) { sel[g.id] = item.id; updatePreview(); }
          });
          label.append(radio, el('span', '', item.label));
          wrap.appendChild(label);
        });
        block.appendChild(wrap);
      } else {
        const input = document.createElement('input');
        input.className = 'opt-input';
        input.type = g.type === 'number' ? 'number' : 'text';
        if (g.type === 'number') input.min = '1';
        input.placeholder = g.placeholder || '';
        input.value = sel[g.id];
        input.addEventListener('input', () => { sel[g.id] = input.value; updatePreview(); });
        block.appendChild(input);
      }
      host.appendChild(block);
    });
  }

  function openModal(script) {
    lastFocus = document.activeElement;
    let sel = defaultStateFor(script);

    modalTitle.textContent = script.title;
    modalBody.textContent = '';

    const badges = el('div', 'tags');
    const badge = el('span', 'badge', script.language);
    badge.dataset.lang = script.language.toLowerCase();
    badges.appendChild(badge);
    script.purposes.forEach(p => badges.appendChild(el('span', 'tag', p)));
    modalBody.appendChild(badges);

    modalBody.appendChild(el('p', 'desc', script.description));
    if (script.requires) modalBody.appendChild(el('p', 'note', 'Requires: ' + script.requires));

    let optionHost = null;
    if (script.options) {
      optionHost = el('div', 'opt-groups');
      modalBody.appendChild(optionHost);
    }

    const previewWrap = el('div', 'preview-wrap');
    const previewHead = el('div', 'preview-head');
    previewHead.appendChild(el('span', 'preview-label', 'Command'));
    const copyBtn = el('button', 'btn btn-primary', 'Copy command');
    copyBtn.type = 'button';
    let resetOpts = null;
    if (script.options) {
      resetOpts = el('button', 'btn btn-ghost', 'Reset options');
      resetOpts.type = 'button';
      previewHead.appendChild(resetOpts);
    }
    previewHead.appendChild(copyBtn);
    const pre = el('pre', 'preview');
    const codeEl = el('code');
    pre.appendChild(codeEl);
    previewWrap.append(previewHead, pre);
    modalBody.appendChild(previewWrap);

    const updatePreview = () => {
      const code = codeFor(script, sel);
      codeEl.textContent = code && code.trim() ? code : '# Nothing selected. Pick at least one option above.';
    };
    copyBtn.addEventListener('click', () => copyText(codeEl.textContent, copyBtn));
    if (resetOpts) {
      resetOpts.addEventListener('click', () => {
        sel = defaultStateFor(script);
        renderOptionGroups(script, sel, optionHost, updatePreview);
        updatePreview();
      });
    }
    if (optionHost) renderOptionGroups(script, sel, optionHost, updatePreview);
    updatePreview();

    overlay.hidden = false;
    document.body.classList.add('no-scroll');
    modalClose.focus();
  }

  function closeModal() {
    overlay.hidden = true;
    document.body.classList.remove('no-scroll');
    if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
  }

  /* ---------- events ---------- */

  searchInput.addEventListener('input', () => {
    filter.q = searchInput.value.trim().toLowerCase();
    refresh();
  });
  resetBtn.addEventListener('click', clearFilters);
  emptyReset.addEventListener('click', clearFilters);
  modalClose.addEventListener('click', closeModal);
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !overlay.hidden) closeModal();
    const tag = (document.activeElement && document.activeElement.tagName) || '';
    if (e.key === '/' && overlay.hidden && !/^(INPUT|TEXTAREA|SELECT)$/.test(tag)) {
      e.preventDefault();
      searchInput.focus();
    }
  });

  refresh();
})();
