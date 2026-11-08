/**
 * theme.js — Farbschema und Akzentfarbe.
 *
 * Die Akzentfarbe ersetzt nur die Primärfarbe; Warn-, Gefahr- und
 * Erfolgsfarben bleiben unverändert.
 */

const THEMES = { system: 'light dark', light: 'light', dark: 'dark' };

export function applyTheme(theme = 'system') {
  document.documentElement.style.colorScheme = THEMES[theme] ?? THEMES.system;
  document.documentElement.dataset.theme = theme;
}

export function applyPrimary(color) {
  if (color) document.documentElement.style.setProperty('--clr-primary', color);
}

export function applyAppearance(appearance = {}) {
  applyTheme(appearance.theme);
  applyPrimary(appearance.primary);
}

/** Löst einen CSS-Farbwert auf — für QR-Codes und Canvas. */
export function resolvedColor(role, shade = null) {
  const name = shade ? `--clr-${role}-${shade}` : `--clr-${role}`;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  if (!value) return '#000000';
  const probe = document.createElement('span');
  probe.style.cssText = `color:${value};position:absolute;visibility:hidden`;
  document.body.append(probe);
  const rgb = getComputedStyle(probe).color;
  probe.remove();
  return rgb || value;
}
