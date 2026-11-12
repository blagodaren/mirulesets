// MIRulesets administrative client. No dependencies, telemetry or remote assets.
// Visual tokens and component rules: UI_KIT.md.
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const number = value => new Intl.NumberFormat('ru-RU').format(Number(value) || 0);
const lines = value => String(value || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
const sizes = ['Б', 'КБ', 'МБ', 'ГБ'];
function bytes(value) { const n = Number(value) || 0; const i = n ? Math.min(Math.floor(Math.log(n) / Math.log(1024)), 3) : 0; return `${new Intl.NumberFormat('ru-RU', {maximumFractionDigits:i ? 1 : 0}).format(n / 1024 ** i)} ${sizes[i]}`; }
function date(value, short = false) { if (!value) return 'Ещё не собран'; const d = new Date(value); return Number.isNaN(d.valueOf()) ? '—' : new Intl.DateTimeFormat('ru-RU', short ? {hour:'2-digit', minute:'2-digit'} : {day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit'}).format(d); }
function safeURL(value) { try { const url = new URL(value, location.origin); return ['http:', 'https:'].includes(url.protocol) ? url.href : '#'; } catch { return '#'; } }
const paths = {
  layers:'<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/>',
  server:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="m16 16 4 4"/>',
  refresh:'<path d="M20 11a8 8 0 0 0-14-5L3 9m0-5v5h5M4 13a8 8 0 0 0 14 5l3-3m0 5v-5h-5"/>',
  chevron:'<path d="m9 5 7 7-7 7"/>',
  arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',
  edit:'<path d="m16 3 5 5M4 20l5-1L21 7a2 2 0 0 0-4-4L5 15l-1 5Z"/>',
  close:'<path d="m6 6 12 12M6 18 18 6"/>',
  trash:'<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/>',
  download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
  copy:'<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a17 17 0 0 1 0 18 17 17 0 0 1 0-18Z"/>',
  file:'<path d="M14 2H5v20h14V7l-5-5Zm0 0v5h5M8 12h8M8 16h6"/>',
  folder:'<path d="M3 5h6l2 3h10v12H3V5Z"/>',
  link:'<path d="m10 14 4-4m-6 6-2 2a3 3 0 0 1-4-4l5-5a3 3 0 0 1 4 0m2 6a3 3 0 0 0 4 0l5-5a3 3 0 0 0-4-4l-2 2"/>',
  cloud:'<path d="M6 18a5 5 0 0 1-1-10 7 7 0 0 1 13-1 5.5 5.5 0 0 1 0 11H6Z"/>',
  logout:'<path d="M9 21H3V3h6M9 12h12m-5-5 5 5-5 5"/>',
  lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V6a4 4 0 0 1 8 0v4M12 14v3"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  monitor:'<rect x="3" y="3" width="18" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
  moon:'<path d="M20.9 13A9 9 0 0 1 11 3.1 9 9 0 1 0 20.9 13Z"/>',
};
const icon = (name, extra = '') => `<svg class="icon ${extra}" viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.file}</svg>`;
function themeSwitcher() {
  const current = window.MIRulesetsTheme?.get() || 'system';
  const modes = [['system','Системная','monitor'],['light','Светлая','sun'],['dark','Тёмная','moon']];
  return `<fieldset class="theme-switcher"><legend class="sr-only">Тема оформления</legend><div class="theme-options">${modes.map(([value,label,symbol]) => `<label class="theme-option" title="${label}"><input class="sr-only" type="radio" name="theme-mode" data-theme-mode value="${value}" aria-label="${label}" ${current === value ? 'checked' : ''}>${icon(symbol)}<span class="theme-option-text">${label}</span></label>`).join('')}</div></fieldset>`;
}
function syncThemeControls() {
  const current = window.MIRulesetsTheme?.get() || 'system';
  $$('[data-theme-mode]').forEach(input => { input.checked = input.value === current; });
}
window.addEventListener('mirulesets:themechange',syncThemeControls);
const brand = () => `<span class="wordmark-row"><img src="/favicon.svg" alt="" width="24" height="24" class="brand-icon"><span class="wordmark">MIRulesets<span class="brand-tick">/</span></span></span>`;
const pipeline = () => `<div class="pipeline" aria-label="Источники, свои правила, готовые файлы"><div class="pipeline-node"><span class="pipeline-symbol">${icon('globe')}</span><span>Источники</span></div><span class="pipeline-arrow"></span><div class="pipeline-node"><span class="pipeline-symbol">${icon('layers')}</span><span>Свои правила</span></div><span class="pipeline-arrow"></span><div class="pipeline-node"><span class="pipeline-symbol">${icon('file')}</span><span>YAML · TXT · MRS</span></div></div>`;
const pageNames = {rulesets:'Наборы правил', tools:'Инструменты'};
const initialView = location.hash.slice(1);
if (location.hash && !Object.hasOwn(pageNames, initialView)) history.replaceState(null, '', `${location.pathname}${location.search}#rulesets`);
const state = {authenticated:false, view:Object.hasOwn(pageNames, initialView) ? initialView : 'rulesets', overview:null, search:'', tag:'', pageError:'', building:new Set(), draft:null, editingId:null};
let toastTimer;
function toast(message, error = false) {
  clearTimeout(toastTimer);
  $$('.dialog-toast').forEach(item => item.remove());
  const dialog = $('dialog[open]');
  const node = dialog ? document.createElement('div') : $('#toast');
  if (dialog) { node.className = 'dialog-toast'; node.setAttribute('role','status'); dialog.append(node); }
  node.textContent = message; node.classList.toggle('error', error); node.hidden = false;
  toastTimer = setTimeout(() => { if (dialog) node.remove(); else node.hidden = true; }, error ? 8000 : 4000);
}
async function request(url, options = {}) {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (options.method && options.method !== 'GET') headers.set('X-Requested-With', 'MIRulesets');
  let response;
  try { response = await fetch(url, {...options, headers, credentials:'same-origin'}); }
  catch { throw new Error('Сервер недоступен. Проверьте подключение и повторите запрос'); }
  let data = null;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && !url.includes('/login')) { state.authenticated = false; $('#editor').close(); $('#detail').close(); renderLogin('Сессия завершена. Введите пароль ещё раз'); }
    throw new Error(data?.error || `Сервер вернул ошибку ${response.status}`);
  }
  return data;
}
async function refresh({silent = false} = {}) {
  try {
    state.overview = await request('/api/overview');
    state.pageError = '';
    if (!silent || (!$('#editor').open && !$('#detail').open && state.view === 'rulesets' && document.activeElement?.id !== 'search')) renderShell();
  } catch (error) {
    if (!state.authenticated) return;
    state.pageError = error.message;
    if (!silent) renderShell();
  }
}
async function load() {
  await refresh();
}
function renderLogin(error = '') {
  $('#app').innerHTML = `<main id="main" class="login-page"><section class="login-intro">${brand()}<div class="login-message"><h1>Наборы правил<br>для Mihomo</h1><p>Объединяйте источники по URL со своими доменами и IP. Публикуйте файлы для Mihomo на сервере или в S3.</p>${pipeline()}</div><span class="login-caption">YAML, text и MRS · На вашей инфраструктуре</span></section><section class="login-area"><div class="login-card"><div class="login-theme">${themeSwitcher()}</div><h2>Вход в панель</h2><p>Пароль администратора этого сервера</p><form id="login-form"><div class="field"><label for="password">Пароль</label><input type="password" id="password" name="password" autocomplete="current-password" required autofocus placeholder="Введите пароль"></div><div id="login-error" class="notice error" role="alert" ${error ? '' : 'hidden'}>${esc(error)}</div><button class="button primary" type="submit">Открыть панель ${icon('arrow')}</button><p class="help">Пароль задаётся в <code>MI_ADMIN_PASSWORD</code> или хранится в файле <code>admin-password</code> каталога данных</p></form></div></section></main>`;
  requestAnimationFrame(() => $('#password')?.focus());
}
function renderShell() {
  if (!state.authenticated) return;
  const system = state.overview?.system || {};
  const total = state.overview?.rulesets?.length || 0;
  $('#app').innerHTML = `<div class="shell"><aside class="sidebar">${brand()}<div class="workspace-label">${icon('server')} Свой сервер · Mihomo</div><div class="nav-label">Управление</div><nav class="nav" aria-label="Основная навигация">${Object.entries(pageNames).filter(([key]) => key === 'rulesets').map(([key, name]) => `<button class="nav-item ${state.view === key ? 'active' : ''}" data-action="navigate" data-view="${key}" ${state.view === key ? 'aria-current="page"' : ''}>${icon({rulesets:'layers'}[key])}<span>${name}</span>${key === 'rulesets' ? `<span class="nav-count mono">${number(total)}</span>` : ''}</button>`).join('')}</nav><div class="sidebar-bottom"><div class="server-note"><span class="status ${state.pageError ? 'error' : 'ok'}">${state.pageError ? 'Нет связи с сервером' : 'Сервер подключён'}</span><p>${system.s3Enabled ? 'Публикация: сервер + S3' : 'Публикация: локальные файлы'}</p></div><button class="logout" data-action="logout" aria-label="Выйти из панели">${icon('logout')} Выйти из панели</button></div></aside><div class="main-wrap"><header class="topbar"><div class="breadcrumb"><span>Панель</span><span>/</span><span class="current">${pageNames[state.view]}</span></div><div class="top-meta"><span class="version mono">${esc(system.version || 'MIRulesets')}</span><span class="connection-mode">${system.tlsMode === 'auto' ? 'Автоматический TLS' : system.tlsMode === 'manual' ? 'Свой сертификат' : 'HTTP / reverse proxy'}</span>${themeSwitcher()}</div></header><main id="main" class="main">${state.pageError ? `<div class="notice error page-error" role="alert"><span>${esc(state.pageError)}</span><button class="button small quiet" data-action="refresh">Повторить</button></div>` : ''}${state.view === 'tools' ? toolsView() : rulesetsView()}<footer class="footer"><span>MIRulesets <span class="muted">/</span> Источники → правила → файлы</span><span>Формат <span class="mono">mrs</span>: domain и ipcidr</span></footer></main></div></div>`;
}
function rulesetsView() {
  const stats = state.overview?.stats || {};
  const sets = state.overview?.rulesets || [];
  const filtered = sets.filter(set => `${set.name} ${set.id} ${set.behavior} ${(set.tags || []).join(' ')}`.toLowerCase().includes(state.search.toLowerCase()) && (!state.tag || (set.tags || []).includes(state.tag)));
  return `<div class="page-heading"><div><h1>Наборы правил</h1><p>Источники по URL и свои правила для Mihomo</p></div><div class="button-row"><button class="button small quiet" data-action="navigate" data-view="tools" aria-label="Инструменты">${icon('server')} Инструменты</button><button class="button primary" data-action="create" aria-label="Создать набор правил">${icon('plus')} Создать набор</button></div></div><section class="stats" aria-label="Статистика"><div class="stat"><div class="stat-label">Наборы</div><div class="stat-value">${number(stats.rulesets ?? sets.length)}</div><div class="stat-note">В вашем пространстве</div></div><div class="stat"><div class="stat-label">Источники</div><div class="stat-value">${number(stats.sources)}</div><div class="stat-note">Подключённые списки</div></div><div class="stat"><div class="stat-label">Правила</div><div class="stat-value ${stats.rules ? 'accent' : ''}">${number(stats.rules)}</div><div class="stat-note">В последних сборках</div></div><div class="stat"><div class="stat-label">Размер файлов</div><div class="stat-value">${bytes(stats.storageBytes)}</div><div class="stat-note">Опубликовано на сервере</div></div></section><div class="toolbar"><label class="search">${icon('search')}<input id="search" type="search" placeholder="Название, ID или тег" aria-label="Поиск наборов" value="${esc(state.search)}"></label><div class="toolbar-right"><select id="tag-filter" aria-label="Фильтр по тегу"><option value="">Все теги</option>${options([...new Set(sets.flatMap(set => set.tags || []))].sort(),state.tag)}</select><span class="filter-note">${number(filtered.length)} из ${number(sets.length)}</span><button class="icon-button" data-action="refresh" title="Обновить данные" aria-label="Обновить данные">${icon('refresh')}</button></div></div><section class="panel" aria-label="Список наборов">${sets.length ? `<div class="table-wrap"><table class="rules-table"><thead><tr><th scope="col">Название / формат</th><th scope="col">Тип правил</th><th scope="col" class="numeric hide-medium">Источники</th><th scope="col" class="numeric">Правила</th><th scope="col">Последняя сборка</th><th scope="col"><span class="muted">Действия</span></th></tr></thead><tbody>${filtered.map(rulesetRow).join('')}</tbody></table>${!filtered.length ? '<div class="empty-search">Наборы не найдены. Измените поисковый запрос</div>' : ''}</div>` : `<div class="empty-state"><div><h2>Первый набор начинается с одного источника</h2><p>Добавьте ссылку на готовый ruleset или впишите свои домены и IP. После сборки получите постоянные ссылки для Mihomo.</p><button class="button accent" data-action="create">${icon('plus')} Создать первый набор</button></div>${pipeline()}</div>`}</section><div class="lower-grid"><section><div class="section-heading"><h2>Последние события</h2><span class="meta">На этом сервере</span></div><div class="panel">${activityView()}</div></section><section><div class="section-heading"><h2>Публикация</h2><span class="meta">Место хранения</span></div><div class="panel storage-panel"><div class="storage-top">${icon('server')}<strong>Ваш сервер${state.overview?.system?.s3Enabled ? ' + S3' : ''}</strong></div><div class="storage-line"><span>Форматы</span><span class="mono">yaml / text / mrs / singbox / srs</span></div><div class="storage-line"><span>Хранилище S3</span><span>${state.overview?.system?.s3Enabled ? esc(state.overview.system.s3Bucket) : 'Не подключено'}</span></div><p>Ссылки на файлы остаются прежними после обновления правил</p></div></section></div>`;
}
function rulesetRow(set) {
  const build = set.lastBuild;
  const busy = state.building.has(set.id);
  const pending = build && build.revision !== set.revision;
  const status = busy ? ['warning','Собирается…'] : set.rollbackHold ? ['warning','Откат удерживается'] : set.lastError ? ['error','Ошибка сборки'] : pending ? ['warning','Есть изменения'] : build ? ['ok','Собран'] : ['','Не собран'];
  return `<tr><td><button class="rule-title" data-action="details" data-id="${esc(set.id)}"><span class="rule-icon">${icon(set.behavior === 'domain' ? 'globe' : set.behavior === 'ipcidr' ? 'server' : 'layers')}</span><span><span class="rule-name">${esc(set.name)}</span><span class="rule-id mono">${esc(set.id)}</span></span></button><div class="format-tags">${(set.formats || []).map(format => `<span class="format-tag ${format === 'mrs' ? 'mrs' : ''}">${esc(format)}</span>`).join('')}${(set.tags || []).map(tag => `<span class="format-tag tag">${esc(tag)}</span>`).join('')}${!set.enabled ? '<span class="format-tag">По запросу</span>' : ''}</div></td><td class="mono">${esc(set.behavior)}</td><td class="numeric hide-medium mono">${number((set.sources || []).filter(source => source.enabled).length)}</td><td class="numeric mono">${build ? `${number(build.ruleCount)}<div class="row-diff">К прошлой: +${number(build.added)} / −${number(build.removed)}</div>` : '—'}</td><td><span class="status ${status[0]}" title="${esc(set.lastError || '')}">${status[1]}</span><div class="row-status-time">${build ? date(build.builtAt) : 'Запустите сборку'}</div>${set.rollbackHold ? `<div class="mt-12"><button class="button small quiet" data-action="resume" data-id="${esc(set.id)}" ${busy ? 'disabled' : ''}>Возобновить обновления</button></div>` : ''}</td><td><div class="rule-actions"><button class="icon-button" data-action="clone" data-id="${esc(set.id)}" title="Клонировать" aria-label="Клонировать ${esc(set.name)}">${icon('copy')}</button><button class="icon-button" data-action="build" data-id="${esc(set.id)}" title="Собрать набор" aria-label="Собрать ${esc(set.name)}" ${busy ? 'disabled' : ''}>${icon('refresh')}</button><button class="icon-button" data-action="edit" data-id="${esc(set.id)}" title="Редактировать" aria-label="Редактировать ${esc(set.name)}">${icon('edit')}</button><button class="icon-button" data-action="details" data-id="${esc(set.id)}" title="Ссылки и конфигурация" aria-label="Ссылки и конфигурация ${esc(set.name)}">${icon('chevron')}</button></div></td></tr>`;
}
function activityView() { const entries = (state.overview?.activity || []).slice(0,5); return entries.length ? `<ul class="activity">${entries.map(item => `<li><time class="mono" datetime="${esc(item.time)}" title="${date(item.time)}">${date(item.time,true)}</time><span class="activity-message ${item.level === 'error' ? 'danger-text' : ''}">${esc(item.message)}</span></li>`).join('')}</ul>` : '<p class="activity-empty">Здесь появятся результаты сборок и обновления источников</p>'; }
function newRuleset() { return {id:'',name:'',behavior:'domain',policy:'PROXY',sources:[],customRules:[],excludeRules:[],intervalSeconds:3600,formats:['yaml','text','mrs'],enabled:true,tags:[],maxDropPercent:50}; }
function openEditor(id = null) {
  state.editingId = id;
  const original = id ? state.overview?.rulesets?.find(set => set.id === id) : null;
  if (id && !original) { toast('Набор не найден. Обновите страницу',true); return; }
  state.draft = original ? structuredClone(original) : newRuleset();
  state.draft.sources ||= [];
  state.slugManual = Boolean(id);
  $('#detail').close();
  renderEditor();
  if (!$('#editor').open) $('#editor').showModal();
  $('#set-name')?.focus();
}
function options(values, selected) { return values.map(value => `<option value="${esc(value)}" ${value === selected ? 'selected' : ''}>${esc(value)}</option>`).join(''); }
function renderEditor() {
  cancelSourcePreviews();
  const draft = state.draft;
  const editing = Boolean(state.editingId);
  $('#editor').innerHTML = `<form id="editor-form" class="dialog-layout"><header class="dialog-header"><div><h2 id="editor-title">${editing ? 'Настройки набора' : 'Новый набор правил'}</h2><p>${editing ? esc(draft.id) : 'Источники → свои правила → готовые файлы'}</p></div><button type="button" class="icon-button" data-action="close-editor" aria-label="Закрыть редактор">${icon('close')}</button></header><div class="dialog-body"><div id="editor-error" class="notice error" role="alert" hidden></div><section class="form-section"><h3>Набор</h3><p class="section-description">Один набор объединяет несколько источников с выбранным типом правил</p><div class="field-row"><div class="field"><label class="required" for="set-name">Название</label><input id="set-name" name="name" value="${esc(draft.name)}" placeholder="Например, рабочие сервисы" maxlength="120" required></div><div class="field"><label class="required" for="set-id">Имя в ссылке</label><input id="set-id" class="mono" name="id" value="${esc(draft.id)}" placeholder="work-services" pattern="[a-z0-9][a-z0-9_-]{0,63}" maxlength="64" ${editing ? 'readonly' : ''} required><p class="help">Латиница, цифры, дефис и подчёркивание</p></div></div><div class="field-row"><div class="field"><label for="set-behavior">Тип правил</label><select id="set-behavior" name="behavior">${options(['domain','ipcidr','classical'],draft.behavior)}</select><p class="help" id="behavior-help">${behaviorHelp(draft.behavior)}</p></div><div class="field"><span>Выходные форматы</span><div class="check-row">${['yaml','text','mrs','singbox','srs'].map(format => `<label class="check-label"><input type="checkbox" name="formats" value="${format}" ${(draft.formats || []).includes(format) ? 'checked' : ''} ${draft.behavior === 'classical' && format === 'mrs' ? 'disabled' : ''}><span class="mono">${format}</span></label>`).join('')}</div><p class="help">MRS доступен для domain и ipcidr</p></div></div><div class="field mt-20"><label for="set-policy">Группа Mihomo</label><input id="set-policy" name="policy" value="${esc(draft.policy || 'PROXY')}" maxlength="160" spellcheck="false" aria-describedby="policy-help policy-error"><p class="help" id="policy-help">Точное имя группы из конфигурации Mihomo, например PROXY или DIRECT. Пустое поле — PROXY</p><p id="policy-error" class="help" role="alert" hidden></p></div></section><section class="form-section"><div class="form-heading"><h3>Источники <span class="muted mono">${draft.sources.length}</span></h3><button type="button" class="button small quiet" data-action="add-source">${icon('plus')} По ссылке</button></div><p class="section-description">HTTP(S), s3://, ruleset:// или ASN. При сборке правила из всех включённых источников объединяются</p><div class="source-list">${draft.sources.length ? draft.sources.map(sourceCard).join('') : '<div class="source-empty">Источников пока нет. Можно добавить ссылку или собрать набор только из своих правил ниже</div>'}</div></section><section class="form-section"><h3>Свои правила</h3><p class="section-description">Добавляются при каждой сборке. Повторяющиеся строки удаляются автоматически</p><div class="field"><label for="custom-rules">По одному правилу на строку</label><textarea id="custom-rules" name="customRules" class="code-editor" spellcheck="false" placeholder="${esc(rulePlaceholder(draft.behavior))}">${esc((draft.customRules || []).join('\n'))}</textarea></div><div class="field mt-20"><label for="exclude-rules">Исключить точные правила</label><textarea id="exclude-rules" name="excludeRules" class="code-editor" rows="3" spellcheck="false" placeholder="Правила, которые нужно удалить из результата">${esc((draft.excludeRules || []).join('\n'))}</textarea><p class="help">Исключение сравнивает нормализованные строки, а не доменные маски</p></div></section><section class="form-section"><h3>Защита и организация</h3><div class="field-row"><div class="field"><label for="set-drop">Допустимое падение числа правил, %</label><input id="set-drop" name="maxDropPercent" type="number" min="0" max="100" step="0.1" required value="${draft.maxDropPercent ?? 50}"><p class="help">Если правил станет меньше сверх порога, предыдущая сборка продолжит работать. 100 — отключить защиту</p></div><div class="field"><label for="set-tags">Теги через запятую</label><input id="set-tags" name="tags" value="${esc((draft.tags || []).join(', '))}" placeholder="работа, реклама"><p class="help">Используйте теги для поиска и фильтрации наборов</p></div></div></section><section class="form-section"><h3>Обновление</h3><p class="section-description">Источники обновляются по расписанию, свои правила сохраняются</p><div class="field-row"><div class="field"><label for="set-interval">Интервал, в секундах</label><input id="set-interval" type="number" name="intervalSeconds" value="${draft.intervalSeconds || 3600}" min="60" max="2592000" step="1" required><p class="help">3600 = 1 час · 43200 = 12 часов</p></div><div class="field"><span>Режим обновления</span><label class="check-label check-row"><input type="checkbox" name="enabled" ${draft.enabled ? 'checked' : ''}> Обновлять автоматически</label></div></div></section>${editing ? '<div class="danger-zone"><p>Удаление отключит локальные ссылки и удалит локальные файлы. Опубликованные объекты S3 также будут удалены.</p><button class="button small danger" type="button" data-action="delete">Удалить набор</button></div>' : ''}</div><footer class="dialog-footer"><span class="save-note">Файлы обновляются при сборке</span><button type="button" class="button quiet" data-action="close-editor">Отмена</button><button type="submit" class="button primary">${icon('check')} Сохранить набор</button></footer></form>`;
}
function behaviorHelp(behavior) { return {domain:'Домены и маски: example.com, +.example.com',ipcidr:'Сети IPv4 и IPv6 в формате CIDR',classical:'Правила Mihomo: DOMAIN-SUFFIX, IP-CIDR, AND и другие'}[behavior] || ''; }
function rulePlaceholder(behavior) { return {domain:'+.example.com\napi.example.org',ipcidr:'192.0.2.0/24\n2001:db8::/32',classical:'DOMAIN-SUFFIX,example.com\nIP-CIDR,192.0.2.0/24,no-resolve'}[behavior]; }
function sourceCard(source,index) {
  const advanced = source.includeRegex || source.excludeRegex || source.selector || source.headerNames?.length || source.headersDraft || source.clearHeaders;
  return `<article class="source-card" data-source="${index}"><div class="source-top"><span class="source-number mono">${String(index+1).padStart(2,'0')}</span><div class="field"><label class="sr-only" for="source-name-${index}">Название источника ${index+1}</label><input id="source-name-${index}" data-field="name" placeholder="Название источника" value="${esc(source.name)}" maxlength="120"></div><button type="button" class="icon-button" data-action="remove-source" data-index="${index}" aria-label="Удалить источник ${index+1}">${icon('close')}</button></div><div class="field"><label for="source-url-${index}">Адрес источника</label><input id="source-url-${index}" data-field="url" class="source-url" placeholder="https://… · ruleset://id · AS13335" value="${esc(source.url)}" required><p class="help">Набор: ruleset://id. ASN: AS13335 с форматом asn и типом ipcidr</p></div><div class="source-bottom"><div class="field"><label for="source-format-${index}">Формат</label><select id="source-format-${index}" data-field="format">${options(['auto','yaml','text','mrs','geosite','geoip','hosts','adblock','singbox','asn'],source.format || 'auto')}</select></div><div class="field"><label for="source-behavior-${index}">Тип правил источника</label><select id="source-behavior-${index}" data-field="behavior">${options(['domain','ipcidr','classical'],source.behavior || state.draft.behavior)}</select></div><label class="check-label"><input type="checkbox" data-field="enabled" ${source.enabled !== false ? 'checked' : ''}> Включён</label></div><details class="source-advanced" ${advanced ? 'open' : ''}><summary>Фильтры и доступ к источнику</summary><div class="field"><label for="source-selector-${index}">Категории geosite / geoip</label><input id="source-selector-${index}" data-field="selector" value="${esc(source.selector)}" placeholder="telegram,google или *"><p class="help">Для DAT укажите коды через запятую. * выбирает все категории</p></div><div class="field-row"><div class="field"><label for="source-include-${index}">Включить по регулярному выражению</label><input id="source-include-${index}" data-field="includeRegex" value="${esc(source.includeRegex)}" spellcheck="false"></div><div class="field"><label for="source-exclude-${index}">Исключить по регулярному выражению</label><input id="source-exclude-${index}" data-field="excludeRegex" value="${esc(source.excludeRegex)}" spellcheck="false"></div></div><div class="field"><label for="source-headers-${index}">HTTP-заголовки, по одному на строку</label><textarea id="source-headers-${index}" data-field="headersDraft" rows="3" autocomplete="off" spellcheck="false" placeholder="Authorization: Bearer …">${esc(source.headersDraft || '')}</textarea><p class="help">${source.headerNames?.length ? `Сохранены: ${esc(source.headerNames.join(', '))}. ` : ''}Значения не возвращаются браузеру. Пустое поле сохраняет прежние заголовки; новые строки заменяют весь список</p><label class="check-label"><input type="checkbox" data-field="clearHeaders" ${source.clearHeaders ? 'checked' : ''}> Удалить сохранённые заголовки</label></div></details><div class="source-preview-actions"><button type="button" class="button small quiet" data-action="preview-source" aria-controls="source-preview-${index}" aria-describedby="source-preview-help-${index}" ${String(source.url || '').trim() ? '' : 'disabled'}>Предпросмотр</button></div><p class="help" id="source-preview-help-${index}">HTTP(S) и S3 · auto, yaml, text, mrs · без фильтров и HTTP-заголовков</p><div id="source-preview-${index}" class="source-preview" aria-live="polite" hidden></div></article>`;
}
const sourcePreviews = new Map();
const rulePlural = new Intl.PluralRules('ru-RU');
function ruleCountLabel(count) {
  const noun = {one:'правило',few:'правила',many:'правил',other:'правила'}[rulePlural.select(count)];
  return `${number(count)} ${noun}`;
}
function previewInput(card) {
  return Object.fromEntries(['url','format','behavior'].map(field => [field,$(`[data-field="${field}"]`,card).value.trim()]));
}
function syncSourcePreviewButton(card) {
  if (!card?.isConnected) return;
  const button = $('[data-action="preview-source"]',card);
  const pending = sourcePreviews.has(card);
  button.disabled = pending || !previewInput(card).url;
  button.textContent = pending ? 'Загрузка…' : 'Предпросмотр';
  button.setAttribute('aria-busy',String(pending));
}
function cancelSourcePreviews() {
  for (const [card,preview] of sourcePreviews) {
    preview.controller.abort();
    sourcePreviews.delete(card);
    syncSourcePreviewButton(card);
  }
}
function updateSourcePreview(field) {
  if (!['url','format','behavior'].includes(field.dataset?.field)) return;
  const card = field.closest('.source-card');
  if (!card) return;
  sourcePreviews.get(card)?.controller.abort();
  sourcePreviews.delete(card);
  const result = $('.source-preview',card);
  result.replaceChildren();
  result.hidden = true;
  syncSourcePreviewButton(card);
}
async function previewSource(card) {
  const input = previewInput(card);
  if (!input.url || sourcePreviews.has(card)) return;
  const preview = {controller:new AbortController(),signature:JSON.stringify(input)};
  const result = $('.source-preview',card);
  sourcePreviews.set(card,preview);
  syncSourcePreviewButton(card);
  result.replaceChildren();
  result.hidden = true;
  const current = () => card.isConnected && $('#editor').open && sourcePreviews.get(card) === preview && JSON.stringify(previewInput(card)) === preview.signature;
  try {
    const data = await request('/api/preview',{method:'POST',body:JSON.stringify(input),signal:preview.controller.signal});
    if (!current()) return;
    result.innerHTML = `<p class="source-preview-meta mono">${ruleCountLabel(data.ruleCount)} · ${bytes(data.sizeBytes)} · ${esc(data.format)}</p><pre class="code-block source-preview-code" tabindex="0" aria-label="Первые правила источника">${esc(data.lines.join('\n'))}</pre>${data.truncated ? '<p class="source-preview-note">Показаны первые 200 правил</p>' : ''}`;
    result.hidden = false;
  } catch(error) {
    if (!current()) return;
    result.innerHTML = `<div class="notice error" role="alert">${esc(error.message)}</div>`;
    result.hidden = false;
  } finally {
    if (sourcePreviews.get(card) === preview) sourcePreviews.delete(card);
    syncSourcePreviewButton(card);
  }
}
function captureEditor() {
  const form = $('#editor-form');
  if (!form) return state.draft;
  const data = new FormData(form);
  state.draft = {...state.draft, id:String(data.get('id') || '').trim(), name:String(data.get('name') || '').trim(), behavior:data.get('behavior'), policy:String(data.get('policy') || '').trim() || 'PROXY', formats:data.getAll('formats'), customRules:lines(data.get('customRules')), excludeRules:lines(data.get('excludeRules')), intervalSeconds:Number(data.get('intervalSeconds')), maxDropPercent:Number(data.get('maxDropPercent')), tags:String(data.get('tags') || '').split(',').map(tag => tag.trim()).filter(Boolean), enabled:data.has('enabled'), sources:$$('.source-card',form).map((card,index) => {
    const source = {...state.draft.sources[index]};
    $$('[data-field]',card).forEach(field => { source[field.dataset.field] = field.type === 'checkbox' ? field.checked : field.value.trim(); });
    return source;
  })};
  return state.draft;
}
function payloadDraft(draft) {
  return {...draft,sources:draft.sources.map(source => {
    const result = {...source};
    delete result.headersDraft;
    if (source.headersDraft) {
      result.headers = {};
      for (const line of lines(source.headersDraft)) {
        const colon = line.indexOf(':');
        if (colon < 1) throw new Error('Заголовок источника: используйте строку «Имя: значение»');
        result.headers[line.slice(0,colon).trim()] = line.slice(colon+1).trim();
      }
      if (result.clearHeaders) throw new Error('Выберите одно действие: задать заголовки или удалить их');
    }
    return result;
  })};
}
function editorError(message) { const node = $('#editor-error'); if (!node) return; node.textContent = message; node.hidden = false; node.scrollIntoView({block:'nearest'}); }
function validatePolicyField() {
  const field = $('#set-policy');
  const error = $('#policy-error');
  if (!field || !error) return '';
  const invalid = /[,\p{Cc}]/u.test(field.value);
  const message = invalid ? 'Название группы не должно содержать запятые или управляющие символы' : '';
  field.setAttribute('aria-invalid', String(invalid));
  error.textContent = message;
  error.hidden = !message;
  return message;
}
async function saveEditor(form) {
  const draft = captureEditor();
  const policyError = validatePolicyField();
  if (policyError) { $('#set-policy').focus(); return; }
  if (!draft.formats.length) { editorError('Выберите хотя бы один выходной формат'); return; }
  const button = $('button[type="submit"]',form); button.disabled = true;
  try {
    await request(state.editingId ? `/api/rulesets/${encodeURIComponent(state.editingId)}` : '/api/rulesets', {method:state.editingId ? 'PUT' : 'POST',body:JSON.stringify(payloadDraft(draft))});
    $('#editor').close(); state.draft = null;
    toast(draft.enabled ? 'Набор сохранён. Автообновление включено' : 'Набор сохранён. Нажмите «Собрать», чтобы опубликовать файлы');
    await refresh();
  } catch(error) { editorError(error.message); }
  finally { button.disabled = false; }
}
async function buildRuleset(id) {
  if (state.building.has(id)) return;
  state.building.add(id);
  if ($('#detail').open) $('#detail').close();
  renderShell(); toast('Сборка запущена: загрузка источников и подготовка файлов');
  try {
    const data = await request(`/api/rulesets/${encodeURIComponent(id)}/build`,{method:'POST'});
    const publicationError = data.ruleset?.lastError;
    toast(publicationError ? `Локальные файлы готовы. ${publicationError}` : 'Набор собран. Ссылки на файлы готовы', Boolean(publicationError));
  }
  catch(error) { toast(error.message,true); }
  finally { state.building.delete(id); if (state.authenticated) await refresh(); }
}
async function openDetails(id) {
  const set = state.overview?.rulesets?.find(item => item.id === id);
  if (!set) return;
  state.detailId = id;
  const build = set.lastBuild;
  const mihomoFiles = (build?.files || []).filter(file => ['mrs','yaml','text'].includes(file.format));
  const sourceStatus = source => source.status ? `<div class="source-status ${source.status.error ? 'danger-text' : ''}">Проверка: ${date(source.status.checkedAt)}${source.status.fetchedAt && !source.status.fetchedAt.startsWith('0001-') ? ` · Загружен: ${date(source.status.fetchedAt)}` : ''} · ${source.status.httpStatus ? `HTTP ${number(source.status.httpStatus)} · ` : ''}${ruleCountLabel(source.status.ruleCount)}${source.status.error ? `<br>${esc(source.status.error)}` : ''}</div>` : '<div class="source-status">Ещё не загружен</div>';
  $('#detail').innerHTML = `<div class="dialog-layout"><header class="dialog-header"><div><h2 id="detail-title">${esc(set.name)}</h2><p class="mono">${esc(set.id)} / ${esc(set.behavior)}</p></div><button class="icon-button" data-action="close-detail" aria-label="Закрыть информацию о наборе">${icon('close')}</button></header><div class="dialog-body">
  ${set.rollbackHold ? '<div class="status warning mb-24">Откат удерживается</div>' : ''}${set.lastError ? `<div class="notice error" role="alert">${esc(set.lastError)}</div>` : ''}${build && build.revision !== set.revision ? '<div class="notice">Настройки изменены после последней сборки. Пересоберите набор, чтобы обновить файлы</div>' : ''}
  ${build ? `<dl class="build-summary"><div><dt>Правила</dt><dd>${number(build.ruleCount)}</dd></div><div><dt>К предыдущей сборке</dt><dd class="build-diff">+${number(build.added)} / −${number(build.removed)}</dd></div><div><dt>Скачивания</dt><dd>${number(state.overview?.downloads?.[id])}</dd></div></dl><p class="help mb-24">Скачивания с запуска сервера: GET 200/206, без HEAD и HTTP 304</p><section class="detail-block"><div class="section-heading"><h3>Опубликованные файлы</h3><span class="meta">${date(build.builtAt)}</span></div>${(build.files || []).map(file => `<div class="artifact"><span class="format-tag ${file.format === 'mrs' ? 'mrs' : ''}">${esc(file.format)}</span><div class="artifact-info"><a href="${esc(safeURL(file.url))}" target="_blank" rel="noopener">${esc(set.id)}.${file.format === 'text' ? 'txt' : file.format === 'singbox' ? 'json' : esc(file.format)}</a><div class="artifact-meta">${bytes(file.size)}${file.s3Url ? ` · <a href="${esc(safeURL(file.s3Url))}" target="_blank" rel="noopener">Копия в S3</a>` : ''}${file.s3Error ? `<span class="danger-text"> · ${esc(file.s3Error)}</span>` : ''}</div></div><button class="button small quiet" data-action="copy-url" data-url="${esc(safeURL(file.url))}" aria-label="Скопировать ссылку на ${esc(file.format)}">${icon('copy')}<span class="button-label">Ссылка</span></button></div>`).join('')}
  <div class="publication-actions">${build.previousGeneration ? `<button class="button quiet" data-action="rollback" data-id="${esc(id)}">${icon('refresh')} Откатить на предыдущую</button>` : ''}${set.rollbackHold ? `<button class="button small quiet" data-action="resume" data-id="${esc(id)}">Возобновить обновления</button>` : ''}${state.overview?.system?.s3Enabled && !build.s3Published ? `<button class="button quiet" data-action="retry-s3" data-id="${esc(id)}">${icon('cloud')} Повторить отправку S3</button>` : ''}</div></section>
  ${mihomoFiles.length ? `<section class="detail-block"><div class="snippet-bar"><h3>Конфигурация Mihomo</h3><div class="button-row"><select id="snippet-format" aria-label="Формат в конфигурации">${options(mihomoFiles.map(file => file.format),mihomoFiles.some(file => file.format === 'mrs') ? 'mrs' : mihomoFiles[0].format)}</select><button class="icon-button" data-action="copy-snippet" title="Скопировать конфигурацию" aria-label="Скопировать конфигурацию">${icon('copy')}</button></div></div><pre class="code-block" id="snippet">Загрузка конфигурации…</pre><p class="help mt-12">Группа: <span class="mono">${esc(set.policy || 'PROXY')}</span> · общая конфигурация доступна в разделе «Инструменты»</p></section>` : '<p class="help mb-24">Файлы sing-box подключаются как rule_set в конфигурации sing-box</p>'}` : '<div class="notice mb-24">Набор сохранён. Запустите первую сборку, чтобы получить файлы</div>'}
  <section class="detail-block"><h3>Подключённые источники</h3>${set.sources?.length ? `<ul class="detail-sources">${set.sources.map(source => `<li><span class="status ${source.enabled ? source.status?.error ? 'error' : source.status ? 'ok' : '' : ''}">${esc(source.name || source.url)}</span><span class="muted mono"> · ${esc(source.behavior)} / ${esc(source.format)}${source.enabled ? '' : ' · выключен'}</span><a href="${esc(safeURL(source.url))}" target="_blank" rel="noopener">${esc(source.url)}</a>${sourceStatus(source)}</li>`).join('')}</ul>` : '<p class="help">Набор состоит только из своих правил</p>'}</section>
  ${set.rollbackUntil && new Date(set.rollbackUntil) > new Date() ? `<div class="notice mb-24">После отката автообновление отложено до ${date(set.rollbackUntil)}. Ручная сборка доступна</div>` : ''}<div class="storage-line"><span>Порог падения</span><span>${number(set.maxDropPercent ?? 50)}%</span></div><div class="storage-line"><span>Своих правил / исключений</span><span>${number(set.customRules?.length)} / ${number(set.excludeRules?.length)}</span></div><div class="storage-line"><span>Обновление</span><span>${set.enabled ? `Каждые ${number(set.intervalSeconds)} с` : 'Вручную'}</span></div></div><footer class="dialog-footer"><button class="button quiet" data-action="clone" data-id="${esc(id)}">${icon('copy')} Копия</button><button class="button quiet" data-action="edit" data-id="${esc(id)}">${icon('edit')} Изменить</button><button class="button primary" data-action="build" data-id="${esc(id)}" ${state.building.has(id) ? 'disabled' : ''}>${icon('refresh')} Собрать</button></footer></div>`;
  if (!$('#detail').open) $('#detail').showModal();
  if (mihomoFiles.length) await loadSnippet();
}
async function loadSnippet() { const node = $('#snippet'); if (!node) return; const id = state.detailId; const format = $('#snippet-format')?.value || 'yaml'; try { const data = await request(`/api/rulesets/${encodeURIComponent(id)}/snippet?format=${encodeURIComponent(format)}`); if (state.detailId === id && $('#snippet-format')?.value === format) node.textContent = data.yaml; } catch(error) { node.textContent = error.message; } }
function toolsView() {
  return `<div class="page-heading"><div><h1>Инструменты</h1><p>Проверка адресов, конфигурация клиентов и перенос настроек</p></div><button class="button small quiet" data-action="navigate" data-view="rulesets" aria-label="К наборам">${icon('layers')} К наборам</button></div>
  <section class="panel tool-panel"><h2>Проверить адрес</h2><p class="help">Поиск домена или IP в опубликованных наборах. Правила, которым нужен контекст соединения, отмечаются отдельно</p><form id="lookup-form" class="tool-form"><div class="field"><label for="lookup-query">Домен или IP</label><input id="lookup-query" name="query" required maxlength="253" placeholder="example.com или 1.2.3.4"></div><button class="button primary" type="submit">${icon('search')} Проверить</button></form><div id="lookup-result" aria-live="polite"></div></section>
  <section class="panel tool-panel"><h2>Все наборы для Mihomo</h2><p class="help">Один YAML с rule-providers. Включаются актуальные опубликованные наборы с форматом MRS, YAML или text</p><form id="snippet-form" class="tool-form"><div class="field"><label for="all-policy">Группа Mihomo</label><input id="all-policy" name="policy" maxlength="160" placeholder="Пусто — политика каждого набора"></div><button class="button quiet" type="submit">Сформировать YAML</button></form><div id="all-snippet-note" aria-live="polite"></div><div id="all-snippet-output" hidden><div class="snippet-bar"><span class="help">Готовая конфигурация</span><button class="button quiet small" data-action="copy-all-snippet">${icon('copy')} Копировать</button></div><pre class="code-block" id="all-snippet"></pre></div></section>
  <section class="panel tool-panel"><h2>Перенести конфигурацию</h2><p class="help">Экспорт state.json содержит настройки без секретных заголовков и файлов сборок. Импорт добавляет наборы и обновляет совпадающие ID; остальные наборы сохраняются</p><button class="button quiet mt-16" data-action="export-config">${icon('download')} Скачать state.json</button><form id="import-form" class="tool-form"><div class="field"><label for="config-file">Импорт state.json</label><input id="config-file" name="file" type="file" accept=".json,application/json" required></div><button class="button quiet" type="submit">Импортировать</button></form><div id="import-result" aria-live="polite"></div></section>`;
}
async function publicationAction(id,action,button) {
  if (action === 'rollback' && !window.confirm('Переключить публикацию на предыдущую сборку? Текущая сохранится для обратного переключения.')) return;
  const showDetails = $('#detail').open && state.detailId === id;
  button.disabled = true;
  button.setAttribute('aria-busy','true');
  try {
    const data = await request(`/api/rulesets/${encodeURIComponent(id)}/${action}`,{method:'POST'});
    await refresh();
    if (showDetails) await openDetails(id);
    if (action === 'resume') {
      const focusTarget = showDetails ? $('#detail [data-action="rollback"]') || $('#detail [data-action="build"]') : $(`.rule-title[data-id="${CSS.escape(id)}"]`);
      focusTarget?.focus();
      toast('Удержание отката снято');
    }
    else toast(data.ruleset?.lastError || (action === 'rollback' ? 'Предыдущая сборка опубликована' : 'Файлы отправлены в S3'),Boolean(data.ruleset?.lastError));
  } catch(error) { toast(error.message,true); }
  finally { button.removeAttribute('aria-busy'); }
}
function openClone(id) {
  const source = state.overview?.rulesets?.find(set => set.id === id);
  if (!source) return;
  state.cloneId = id; $('#detail').close();
  $('#editor').innerHTML = `<form id="clone-form" class="dialog-layout"><header class="dialog-header"><div><h2 id="editor-title">Копия набора</h2><p>${esc(source.name)}</p></div><button type="button" class="icon-button" data-action="close-editor" aria-label="Закрыть">${icon('close')}</button></header><div class="dialog-body"><div id="editor-error" class="notice error" role="alert" hidden></div><div class="field"><label for="clone-name">Название копии</label><input id="clone-name" name="name" value="${esc(source.name + ' — копия')}" maxlength="160" required></div><div class="field mt-16"><label for="clone-id">Новый ID</label><input id="clone-id" name="id" value="${esc(source.id.slice(0,59) + '-copy')}" pattern="[a-z0-9][a-z0-9_-]{0,63}" maxlength="64" required><p class="help">Источники и их серверные заголовки копируются. Первую сборку нужно запустить отдельно</p></div></div><footer class="dialog-footer"><button type="submit" class="button primary">Создать копию</button></footer></form>`;
  if (!$('#editor').open) $('#editor').showModal(); $('#clone-id').focus(); $('#clone-id').select();
}
async function cloneRuleset(form) {
  const button = $('button[type="submit"]',form); button.disabled = true;
  try {
    const data = new FormData(form);
    await request(`/api/rulesets/${encodeURIComponent(state.cloneId)}/clone`,{method:'POST',body:JSON.stringify({id:data.get('id').trim(),name:data.get('name').trim()})});
    $('#editor').close(); await refresh(); toast('Копия создана. Запустите первую сборку');
  } catch(error) { editorError(error.message); }
  finally { button.disabled = false; }
}
async function lookupAddress(form) {
  const button = $('button[type="submit"]',form), result = $('#lookup-result'); button.disabled = true; result.textContent = 'Проверка…';
  try {
    const data = await request(`/api/lookup?query=${encodeURIComponent(new FormData(form).get('query').trim())}`);
    result.innerHTML = data.matches?.length ? `<ul class="lookup-matches">${data.matches.map(match => `<li><button class="rule-title" data-action="details" data-id="${esc(match.rulesetId)}">${esc(match.name)}</button><p class="help mono">${esc(match.behavior)} · ${match.matchCount ? `Совпадений: ${number(match.matchCount)}` : 'Подтверждённых совпадений нет'}${match.rules?.length ? ` · ${esc(match.rules.join(', '))}` : ''}</p>${match.incomplete || match.unsupportedRules ? '<p class="help">Часть правил требует контекста соединения; проверка неполная</p>' : ''}</li>`).join('')}</ul>` : '<div class="notice mt-16">Совпадений в опубликованных правилах нет</div>';
  } catch(error) { result.innerHTML = `<div class="notice error mt-16">${esc(error.message)}</div>`; }
  finally { button.disabled = false; }
}
async function loadAllSnippet(form) {
  const button = $('button[type="submit"]',form), note = $('#all-snippet-note'); button.disabled = true; $('#all-snippet-output').hidden = true;
  try {
    const data = await request(`/api/snippet?policy=${encodeURIComponent(new FormData(form).get('policy').trim())}`);
    $('#all-snippet').textContent = data.yaml; $('#all-snippet-output').hidden = false;
    note.innerHTML = `<p class="help mt-16">Включено наборов: ${number(data.included)}${data.skipped?.length ? ` · Пропущены (нужна актуальная сборка Mihomo): ${data.skipped.map(esc).join(', ')}` : ''}</p>`;
  } catch(error) { note.innerHTML = `<div class="notice error mt-16">${esc(error.message)}</div>`; }
  finally { button.disabled = false; }
}
async function exportConfig() {
  const data = await request('/api/config');
  const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
  const link = document.createElement('a'); link.href=url; link.download='state.json'; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url),1000);
  toast('Конфигурация скачана без секретных заголовков');
}
async function importConfig(form) {
  const button = $('button[type="submit"]',form), result = $('#import-result');
  try {
    const file = $('#config-file').files[0];
    if (!file) throw new Error('Выберите state.json');
    if (file.size > 4*1024*1024) throw new Error('Конфигурация превышает 4 MiB');
    const data = JSON.parse(await file.text());
    if (!Array.isArray(data.rulesets)) throw new Error('В файле отсутствует список rulesets');
    if (!window.confirm(`Импортировать ${data.rulesets.length} наборов? Настройки совпадающих ID будут обновлены.`)) return;
    button.disabled = true; result.textContent = 'Импорт…';
    const response = await request('/api/config',{method:'POST',body:JSON.stringify(data)});
    state.overview = await request('/api/overview'); result.innerHTML = `<div class="notice success mt-16">Импортировано: ${number(response.imported)}. Новые настройки вступят в силу после сборки наборов</div>`;
  } catch(error) { result.innerHTML = `<div class="notice error mt-16">${esc(error.message)}</div>`; }
  finally { button.disabled = false; }
}

async function copyText(text) {
  if (!text || text === '#') throw new Error('Нет данных для копирования');
  if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); }
  else {
    const field = document.createElement('textarea'); field.value = text; field.className = 'clipboard-helper'; const parent = $('dialog[open]') || document.body; parent.append(field); field.select(); const ok = document.execCommand('copy'); field.remove(); if (!ok) throw new Error('Браузер запретил копирование. Выделите текст вручную');
  }
  toast('Скопировано');
}
function navigate(view) { if (!Object.hasOwn(pageNames, view)) return; state.view = view; location.hash = view; renderShell(); window.scrollTo(0,0); }
document.addEventListener('click', async event => {
  const button = event.target.closest('[data-action]');
  if (!button || button.disabled) return;
  const action = button.dataset.action;
  try {
    if (action === 'clone') openClone(button.dataset.id);
    else if (action === 'rollback' || action === 'retry-s3' || action === 'resume') await publicationAction(button.dataset.id,action,button);
    else if (action === 'export-config') await exportConfig();
    else if (action === 'copy-all-snippet') await copyText($('#all-snippet')?.textContent);
    else if (action === 'navigate') navigate(button.dataset.view);
    else if (action === 'refresh') { button.disabled = true; await refresh(); }
    else if (action === 'create') openEditor();
    else if (action === 'edit') openEditor(button.dataset.id);
    else if (action === 'close-editor') { $('#editor').close(); state.draft = null; }
    else if (action === 'close-detail') $('#detail').close();
    else if (action === 'preview-source') await previewSource(button.closest('.source-card'));
    else if (action === 'add-source') { captureEditor(); state.draft.sources.push({name:'',url:'',format:'auto',behavior:state.draft.behavior,enabled:true}); renderEditor(); $$('.source-url').at(-1)?.focus(); }
    else if (action === 'remove-source') { captureEditor(); state.draft.sources.splice(Number(button.dataset.index),1); renderEditor(); }
    else if (action === 'build') await buildRuleset(button.dataset.id);
    else if (action === 'details') await openDetails(button.dataset.id);
    else if (action === 'delete') {
      const id = state.editingId;
      if (!id || !window.confirm(`Удалить набор «${state.draft.name}» и отключить локальные ссылки? Локальные файлы будут удалены. Опубликованные объекты S3 также будут удалены. Запись набора восстановить нельзя.`)) return;
      button.disabled = true;
      await request(`/api/rulesets/${encodeURIComponent(id)}`,{method:'DELETE'}); $('#editor').close(); toast('Набор удалён'); await refresh();
    }
    else if (action === 'logout') { await request('/api/logout',{method:'POST'}); state.authenticated = false; state.overview = null; renderLogin(); }
    else if (action === 'copy-url') await copyText(button.dataset.url);
    else if (action === 'copy-snippet') await copyText($('#snippet')?.textContent);
  } catch(error) { if ($('#editor').open) editorError(error.message); else toast(error.message,true); }
  finally { if (button.isConnected) { if (action === 'preview-source') syncSourcePreviewButton(button.closest('.source-card')); else button.disabled = false; } }
});
document.addEventListener('submit', async event => {
  const form = event.target;
  // A control named "id" shadows HTMLFormElement.id through named properties.
  const formId = form.getAttribute('id');
  if (!['login-form','editor-form','clone-form','lookup-form','snippet-form','import-form'].includes(formId)) return;
  event.preventDefault();
  if (formId === 'clone-form') await cloneRuleset(form);
  else if (formId === 'lookup-form') await lookupAddress(form);
  else if (formId === 'snippet-form') await loadAllSnippet(form);
  else if (formId === 'import-form') await importConfig(form);
  else if (formId === 'editor-form') await saveEditor(form);
  else {
    const button = $('button[type="submit"]',form); button.disabled = true;
    const errorNode = $('#login-error'); errorNode.hidden = true;
    try { await request('/api/login',{method:'POST',body:JSON.stringify({password:$('#password').value})}); state.authenticated = true; await load(); }
    catch(error) { errorNode.textContent = error.message; errorNode.hidden = false; $('#password')?.focus(); }
    finally { button.disabled = false; }
  }
});
document.addEventListener('input', event => {
  updateSourcePreview(event.target);
  if (event.target.id === 'search') {
    const position = event.target.selectionStart;
    state.search = event.target.value; renderShell(); const search = $('#search'); search.focus(); if (position !== null) { try { search.setSelectionRange(position,position); } catch {} }
  }
  if (event.target.id === 'set-name' && !state.slugManual) $('#set-id').value = event.target.value.toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,64);
  if (event.target.id === 'set-id') state.slugManual = true;
  if (event.target.id === 'set-policy') validatePolicyField();
});
document.addEventListener('change', event => {
  if (event.target.matches('[data-theme-mode]')) {
    window.MIRulesetsTheme?.set(event.target.value);
    return;
  }
  updateSourcePreview(event.target);
  if (event.target.id === 'tag-filter') { state.tag = event.target.value; renderShell(); }
  if (event.target.id === 'set-behavior') {
    const behavior = event.target.value; const mrs = $('input[name="formats"][value="mrs"]');
    mrs.disabled = behavior === 'classical'; if (mrs.disabled) mrs.checked = false;
    $('#behavior-help').textContent = behaviorHelp(behavior); $('#custom-rules').placeholder = rulePlaceholder(behavior);
  }
  if (event.target.id === 'snippet-format') loadSnippet();
});
document.addEventListener('keydown', event => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's' && $('#editor').open && $('#editor-form')) { event.preventDefault(); $('#editor-form').requestSubmit(); }
});
window.addEventListener('hashchange', () => {
  const hash = location.hash.slice(1);
  const view = Object.hasOwn(pageNames, hash) ? hash : 'rulesets';
  if (hash !== view) history.replaceState(null, '', `${location.pathname}${location.search}#${view}`);
  if (view !== state.view) navigate(view);
});
$('#editor').addEventListener('close', cancelSourcePreviews);
async function boot() {
  try { const data = await request('/api/session'); state.authenticated = Boolean(data.authenticated); if (state.authenticated) await load(); else renderLogin(); }
  catch(error) { renderLogin(error.message); }
}
await boot();
setInterval(() => { if (state.authenticated && !document.hidden && !state.building.size && !$('#editor').open && !$('#detail').open) refresh({silent:true}); },30000);
