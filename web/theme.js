(() => {
  'use strict';

  const key = 'mirulesets.theme';
  const normalize = value => value === 'light' || value === 'dark' ? value : 'system';
  let storage;
  let theme = 'system';

  try {
    storage = window.localStorage;
    theme = normalize(storage.getItem(key));
  } catch {
    // Выбор остаётся доступен в текущей вкладке без хранилища браузера.
  }

  function apply() {
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
  }

  function notify() {
    window.dispatchEvent(new CustomEvent('mirulesets:themechange', {detail: {theme}}));
  }

  apply();
  window.MIRulesetsTheme = Object.freeze({
    get: () => theme,
    set(value) {
      theme = normalize(value);
      apply();
      try {
        storage?.setItem(key, theme);
      } catch {
        // Ошибка сохранения не отменяет выбранную тему в текущей вкладке.
      }
      notify();
      return theme;
    },
  });

  window.addEventListener('storage', event => {
    if (!storage || event.storageArea !== storage || (event.key !== key && event.key !== null)) return;
    theme = normalize(event.newValue);
    apply();
    notify();
  });
})();
