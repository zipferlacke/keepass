import { readFileSync, writeFileSync } from 'node:fs';

/**
 * Bündelt die ES-Module zu einer einzelnen HTML-Datei für die Vorschau
 * ohne Rust. Die Module werden zu IIFEs, ihre Importe über die
 * `__mod_*`-Namensräume ersetzt.
 *
 * Die Reihenfolge in MODULES ist bedeutsam: Ein Modul, dessen Rumpf beim
 * Anlegen aus einem anderen destrukturiert, muss danach stehen.
 */

const DEPS = {
  demo: `const { passwordStrength } = __mod_security;
const { generateTotp, secondsRemaining } = __mod_totp;`,
  settings: `const { invoke } = __mod_platform;`,
  vault: `const { invoke } = __mod_platform;`,
  qr: `const { isTauri, invoke } = __mod_platform;
const { renderQrCode } = __mod_ui;`
};

const MODULES = [
  'dragmove', 'multiselect', 'security', 'totp', 'ui', 'demo', 'platform',
  'settings', 'vault', 'theme', 'icons', 'qr', 'preview'
];

function wrap(name) {
  let src = readFileSync(`./js/${name}.js`, 'utf8');

  // Import-Zeilen entfernen (werden über den Namensraum bereitgestellt)
  src = src.replace(/^import[\s\S]*?from\s+['"][^'"]+['"];?\s*$/gm, '');
  src = src.replace(/^import\s+['"][^'"]+['"];?\s*$/gm, '');

  const names = new Set();
  for (const m of src.matchAll(/export\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)/g)) names.add(m[1]);
  for (const m of src.matchAll(/export\s+(?:const|let|var)\s+([A-Za-z0-9_$]+)/g)) names.add(m[1]);

  src = src.replace(/^export\s+/gm, '');

  const deps = DEPS[name] ? DEPS[name] + '\n' : '';
  return `const __mod_${name.replace(/-/g, '_')} = (() => {\n${deps}${src}\nreturn { ${[...names].join(', ')} };\n})();\n`;
}

let bundle = MODULES.map(wrap).join('\n');

bundle += `const settings = __mod_settings;\nconst vault = __mod_vault;\nconst qr = __mod_qr;\n`;
bundle += `const { dialog, banner, closeHostDialog, tableview } = __mod_ui;\n`;
bundle += `const { parseOtpauth, buildOtpauth } = __mod_totp;\n`;
bundle += `const { checkPwnedByHash, checkEmailBreached, passwordStrength: localStrength } = __mod_security;\n`;
bundle += `const { applyAppearance, applyTheme, applyPrimary, resolvedColor } = __mod_theme;\n`;
bundle += `const { avatarMarkup, refreshEpoch, hostFromUrl } = __mod_icons;\n`;
bundle += `const { enableDragMove } = __mod_dragmove;
const pick = __mod_multiselect;\nconst preview = __mod_preview;\n`;
bundle += `const { isTauri, invoke, unlockMethods, pickDatabaseFile, pickSavePath, listen } = __mod_platform;\n`;

let app = readFileSync('./js/app.js', 'utf8');
app = app.replace(/^import[\s\S]*?from\s+['"][^'"]+['"];?\s*$/gm, '');
bundle += '\n' + app;

/* Im Bündel gibt es keine Modulpfade mehr — platform.js holt demo.js direkt. */
bundle = bundle.replace(
  "demoModule ??= await import('./demo.js');",
  'demoModule ??= __mod_demo;'
);

/* Beide JSON-Dateien einbetten, damit kein fetch nötig ist. */
bundle = bundle
  .replace(
    "const DEFAULTS_URL = './config/settings.default.json';",
    `const __EMBEDDED_SETTINGS = ${readFileSync('./config/settings.default.json', 'utf8')};`)
  .replace(
    /const res = await fetch\(DEFAULTS_URL[\s\S]*?defaults = await res\.json\(\);/,
    'defaults = structuredClone(__EMBEDDED_SETTINGS);')
  .replace(
    "const DEMO_URL = './config/demo.json';",
    `const __EMBEDDED_DEMO = ${readFileSync('./config/demo.json', 'utf8')};`)
  .replace(
    /const res = await fetch\(DEMO_URL[\s\S]*?data = await res\.json\(\);/,
    'data = structuredClone(__EMBEDDED_DEMO);');

const css = readFileSync('./css/app.css', 'utf8');
let html = readFileSync('./index.html', 'utf8');

html = html
  .replace('<link rel="stylesheet" href="./css/app.css">', () => `<style>\n${css}\n</style>`)
  .replace('<script type="module" src="./js/app.js"></script>', () => `<script type="module">\n${bundle}\n</script>`);

writeFileSync('../wkeepass-single.html', html);
console.log('ok', html.length, 'bytes');
