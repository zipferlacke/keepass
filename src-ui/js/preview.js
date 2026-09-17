/**
 * preview.js — Anhänge anzeigen.
 *
 * Unterstützt Bilder, reinen Text, Markdown und PDF. Alles wird lokal aus
 * dem gespeicherten Data-URL erzeugt; es geht nichts ins Netz.
 */

const TEXT_EXTENSIONS = /\.(txt|md|markdown|json|xml|csv|log|ini|conf|yml|yaml|js|css|html|sh|py|rs|php|sql)$/i;
const MD_EXTENSIONS = /\.(md|markdown)$/i;

export function kindOf(att) {
  const { type = '', name = '' } = att;
  if (type.startsWith('image/')) return 'image';
  if (type === 'application/pdf' || /\.pdf$/i.test(name)) return 'pdf';
  if (MD_EXTENSIONS.test(name) || type === 'text/markdown') return 'markdown';
  if (type.startsWith('text/') || TEXT_EXTENSIONS.test(name) || type === 'application/json') return 'text';
  if (type.startsWith('video/')) return 'video';
  if (type.startsWith('audio/')) return 'audio';
  return 'binary';
}

export function iconFor(att) {
  return {
    image: 'image', pdf: 'picture_as_pdf', markdown: 'article',
    text: 'description', video: 'movie', audio: 'audio_file', binary: 'draft'
  }[kindOf(att)];
}

/* =========================================================
   Data-URL-Hilfen
   ========================================================= */

export async function asText(att) {
  const res = await fetch(att.data);
  return res.text();
}

export async function asBlobUrl(att) {
  const res = await fetch(att.data);
  const blob = await res.blob();
  // Der MIME-Typ muss stimmen, sonst zeigt der Viewer das PDF nicht an
  const typed = blob.type ? blob : new Blob([blob], { type: att.type || 'application/octet-stream' });
  return URL.createObjectURL(typed);
}

/* =========================================================
   Markdown → HTML (bewusst klein gehalten)
   ========================================================= */

const escapeHtml = s => String(s).replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function renderMarkdown(src) {
  const codeBlocks = [];

  // 1. Code-Blöcke herausnehmen, damit die Inline-Regeln sie nicht anfassen
  let text = String(src).replace(/```([\w-]*)\n([\s\S]*?)```/g, (_, lang, code) => {
    codeBlocks.push(`<pre class="md-code"><code data-lang="${escapeHtml(lang)}">${escapeHtml(code.replace(/\n$/, ''))}</code></pre>`);
    return `\u0000CODE${codeBlocks.length - 1}\u0000`;
  });

  text = escapeHtml(text);

  const inline = s => s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, '<img src="$2" alt="$1" class="md-img">')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer noopener">$1</a>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
    .replace(/~~([^~]+)~~/g, '<del>$1</del>');

  const out = [];
  let listType = null;
  let inQuote = false;

  const closeList = () => { if (listType) { out.push(`</${listType}>`); listType = null; } };
  const closeQuote = () => { if (inQuote) { out.push('</blockquote>'); inQuote = false; } };

  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\s+$/, '');

    if (/^\u0000CODE\d+\u0000$/.test(line.trim())) {
      closeList(); closeQuote();
      out.push(line.trim());
      continue;
    }

    if (!line.trim()) { closeList(); closeQuote(); continue; }

    // Tabellen-Trennzeile überspringen
    if (/^\|?[\s:-]+\|[\s|:-]*$/.test(line) && line.includes('|')) continue;

    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      closeList(); closeQuote();
      const level = heading[1].length;
      out.push(`<h${level} class="md-h">${inline(heading[2])}</h${level}>`);
      continue;
    }

    if (/^(---+|\*\*\*+|___+)$/.test(line.trim())) {
      closeList(); closeQuote();
      out.push('<hr>');
      continue;
    }

    const quote = line.match(/^&gt;\s?(.*)$/);
    if (quote) {
      closeList();
      if (!inQuote) { out.push('<blockquote>'); inQuote = true; }
      out.push(`<p>${inline(quote[1])}</p>`);
      continue;
    }
    closeQuote();

    const task = line.match(/^\s*[-*+]\s+\[( |x|X)\]\s+(.*)$/);
    if (task) {
      if (listType !== 'ul') { closeList(); out.push('<ul class="md-list">'); listType = 'ul'; }
      out.push(`<li class="md-task"><input type="checkbox" disabled ${task[1].toLowerCase() === 'x' ? 'checked' : ''}> ${inline(task[2])}</li>`);
      continue;
    }

    const bullet = line.match(/^\s*[-*+]\s+(.*)$/);
    if (bullet) {
      if (listType !== 'ul') { closeList(); out.push('<ul class="md-list">'); listType = 'ul'; }
      out.push(`<li>${inline(bullet[1])}</li>`);
      continue;
    }

    const numbered = line.match(/^\s*\d+\.\s+(.*)$/);
    if (numbered) {
      if (listType !== 'ol') { closeList(); out.push('<ol class="md-list">'); listType = 'ol'; }
      out.push(`<li>${inline(numbered[1])}</li>`);
      continue;
    }

    closeList();
    out.push(`<p>${inline(line)}</p>`);
  }

  closeList();
  closeQuote();

  return out.join('\n').replace(/\u0000CODE(\d+)\u0000/g, (_, i) => codeBlocks[Number(i)]);
}

/* =========================================================
   Vorschau-Inhalt aufbauen
   ========================================================= */

/**
 * Baut die Vorschau in ein Zielelement. Gibt eine Aufräumfunktion zurück,
 * die erzeugte Blob-URLs wieder freigibt.
 */
export async function renderPreview(container, att) {
  const kind = kindOf(att);
  const cleanups = [];

  try {
    switch (kind) {
      case 'image': {
        container.innerHTML = `<img class="preview-image" src="${att.data}" alt="${escapeHtml(att.name)}">`;
        break;
      }

      case 'pdf': {
        const url = await asBlobUrl(att);
        cleanups.push(() => URL.revokeObjectURL(url));
        container.innerHTML = `
          <iframe class="preview-pdf" src="${url}#view=FitH" title="${escapeHtml(att.name)}"></iframe>
          <p class="preview-hint">Zeigt der eingebettete Betrachter nichts an, lade die Datei über den Knopf oben rechts herunter.</p>`;
        break;
      }

      case 'markdown': {
        const text = await asText(att);
        container.innerHTML = `<div class="preview-markdown">${renderMarkdown(text)}</div>`;
        break;
      }

      case 'text': {
        const text = await asText(att);
        container.innerHTML = `<pre class="preview-text">${escapeHtml(text)}</pre>`;
        break;
      }

      case 'video': {
        container.innerHTML = `<video class="preview-media" src="${att.data}" controls></video>`;
        break;
      }

      case 'audio': {
        container.innerHTML = `<audio class="preview-media" src="${att.data}" controls></audio>`;
        break;
      }

      default:
        container.innerHTML = `<p class="empty-state"><span class="msr preview-type-icon">draft</span><br>
          Für diesen Dateityp gibt es keine Vorschau.<br>Zum Öffnen oben rechts herunterladen.</p>`;
    }
  } catch (err) {
    container.innerHTML = `<p class="empty-state">Vorschau nicht möglich: ${escapeHtml(err.message)}</p>`;
  }

  return () => cleanups.forEach(fn => fn());
}

/** Kurzer Textausschnitt für die Kachel in der Anhang-Liste. */
export async function textSnippet(att, maxChars = 160) {
  try {
    const text = await asText(att);
    return text.replace(/\s+/g, ' ').trim().slice(0, maxChars);
  } catch { return ''; }
}

