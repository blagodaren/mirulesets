const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {join} = require('node:path');
const {test} = require('node:test');
const {runInNewContext} = require('node:vm');

const source = readFileSync(join(__dirname, 'theme.js'), 'utf8');
const storageKey = 'mirulesets.theme';

function boot({saved = null, denyStorage = false, denyRead = false, denyWrite = false} = {}) {
  const attributes = new Map();
  const writes = [];
  const events = [];
  const listeners = new Map();
  const storage = {
    getItem(key) {
      assert.equal(key, storageKey);
      if (denyRead) throw new Error('Storage read unavailable');
      return saved;
    },
    setItem(key, value) {
      if (denyWrite) throw new Error('Storage write unavailable');
      writes.push([key, value]);
      saved = value;
    },
  };
  const window = {
    get localStorage() {
      if (denyStorage) throw new Error('Storage unavailable');
      return storage;
    },
    addEventListener(type, listener) {
      listeners.set(type, listener);
    },
    dispatchEvent(event) {
      events.push(event);
      return true;
    },
  };
  const document = {documentElement: {
    setAttribute: (key, value) => attributes.set(key, value),
    removeAttribute: key => attributes.delete(key),
  }};
  runInNewContext(source, {
    window,
    document,
    CustomEvent: class {
      constructor(type, {detail}) { this.type = type; this.detail = detail; }
    },
  }, {filename: 'theme.js'});
  return {
    api: window.MIRulesetsTheme,
    attributes,
    writes,
    events,
    storage,
    receive: event => listeners.get('storage')({storageArea: storage, key: storageKey, ...event}),
  };
}

test('saved theme is applied before any application markup is needed', () => {
  for (const theme of ['light', 'dark']) {
    const page = boot({saved: theme});
    assert.equal(page.api.get(), theme);
    assert.equal(page.attributes.get('data-theme'), theme);
    assert.equal(page.writes.length, 0);
    assert.equal(page.events.length, 0);
    assert.ok(Object.isFrozen(page.api));
  }
});

test('missing, system and invalid stored choices follow the system', () => {
  for (const saved of [null, 'system', '', 'sepia', 'DARK']) {
    const page = boot({saved});
    assert.equal(page.api.get(), 'system');
    assert.equal(page.attributes.has('data-theme'), false);
    assert.equal(page.writes.length, 0);
  }
});

test('choices update the root, storage and notification without reloading', () => {
  const page = boot();
  for (const theme of ['dark', 'light', 'system']) {
    assert.equal(page.api.set(theme), theme);
    assert.equal(page.api.get(), theme);
    assert.equal(page.attributes.get('data-theme'), theme === 'system' ? undefined : theme);
    assert.deepEqual(page.writes.at(-1), [storageKey, theme]);
    assert.equal(page.events.at(-1).type, 'mirulesets:themechange');
    assert.equal(page.events.at(-1).detail.theme, theme);
  }
  assert.equal(page.api.set('invalid'), 'system');
  assert.equal(page.attributes.has('data-theme'), false);
  assert.equal(page.events.length, 4);
});

test('denied storage access or writes leave the current choice usable', () => {
  for (const options of [{denyStorage: true}, {denyRead: true}, {denyWrite: true}]) {
    const page = boot(options);
    assert.equal(page.api.get(), 'system');
    page.api.set('dark');
    assert.equal(page.api.get(), 'dark');
    assert.equal(page.attributes.get('data-theme'), 'dark');
    assert.equal(page.events.at(-1).detail.theme, 'dark');
    page.api.set('system');
    assert.equal(page.attributes.has('data-theme'), false);
  }
});

test('cross-tab changes, removal and clear update the choice without write feedback', () => {
  const page = boot({saved: 'dark'});
  page.receive({newValue: 'light'});
  assert.equal(page.api.get(), 'light');
  assert.equal(page.attributes.get('data-theme'), 'light');
  for (const event of [{newValue: null}, {newValue: 'invalid'}, {key: null, newValue: null}]) {
    page.receive({newValue: 'dark'});
    page.receive(event);
    assert.equal(page.api.get(), 'system');
    assert.equal(page.attributes.has('data-theme'), false);
    assert.equal(page.events.at(-1).detail.theme, 'system');
  }
  assert.equal(page.writes.length, 0);
  assert.equal(page.events.length, 7);
});

test('session storage and unrelated keys cannot replace the theme', () => {
  const page = boot({saved: 'dark'});
  page.receive({storageArea: {}, newValue: 'light'});
  page.receive({storageArea: null, newValue: 'light'});
  page.receive({key: 'another.key', newValue: 'light'});
  assert.equal(page.api.get(), 'dark');
  assert.equal(page.attributes.get('data-theme'), 'dark');
  assert.equal(page.events.length, 0);
  assert.equal(page.writes.length, 0);
});

test('theme bootstrap blocks parsing before styles and has no inline code', () => {
  const html = readFileSync(join(__dirname, 'index.html'), 'utf8');
  const bootstrap = html.match(/<script\s+src="\/theme\.js"\s*><\/script>/);
  assert.ok(bootstrap);
  assert.ok(bootstrap.index < html.indexOf('<link rel="stylesheet"'));
  assert.ok(bootstrap.index < html.indexOf('<script src="/app.js"'));
  assert.match(html, /<meta name="color-scheme" content="light dark">/);
});
