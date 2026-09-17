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

/** Der MIME-Typ zur Endung — dieselbe Zuordnung wie im Kern (secrets.rs). */
const TYPES = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
  svg: 'image/svg+xml', pdf: 'application/pdf', json: 'application/json',
  md: 'text/markdown', markdown: 'text/markdown', html: 'text/html', htm: 'text/html',
  css: 'text/css', csv: 'text/csv', xml: 'application/xml'
};

export function typeFromName(name) {
  const ext = String(name).split('.').pop().toLowerCase();
  if (TYPES[ext]) return TYPES[ext];
  return TEXT_EXTENSIONS.test(name) || /\.(ya?ml|toml|log)$/i.test(name) ? 'text/plain' : 'application/octet-stream';
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

const slugify = text => String(text)
  .toLowerCase()
  // 1. Deutsche Umlaute gezielt übersetzen, da "ae" im Deutschen besser ist als nur "a"
  .replace(/ä/g, 'ae')
  .replace(/ö/g, 'oe')
  .replace(/ü/g, 'ue')
  .replace(/ß/g, 'ss')
  // 2. Unicode-Normalisierung (trennt z.B. é in e und ´)
  .normalize('NFD')
  // 3. Entfernt alle isolierten Akzente/Diakritika
  .replace(/[\u0300-\u036f]/g, '')
  // 4. Behält nur noch Standard-Buchstaben, Zahlen, Leerzeichen und Bindestriche
  .replace(/[^\w\s-]/g, '')
  // 5. Trimmen und Leerzeichen zu Bindestrichen machen
  .trim()
  .replace(/\s+/g, '-');


export function renderMarkdown(src) {
  const codeBlocks = [];
  const detailsBlocks = [];
  const tableBlocks = [];

  let text = String(src);

  // 1. Code-Blöcke herausnehmen
  text = text.replace(/```([\w-]*)\n([\s\S]*?)```/g, (_, lang, code) => {
    codeBlocks.push(`<pre class="md-code"><code data-lang="${escapeHtml(lang)}">${escapeHtml(code)}</code></pre>`);
    return `\u0000CODE${codeBlocks.length - 1}\u0000`;
  });

  // 1.5 Bequeme Markdown-Details-Syntax umwandeln (::: details Titel ... :::)
  text = text.replace(/^:::\s*details\s*(.*?)\n([\s\S]*?)^:::/gim, (_, summary, content) => {
    const sumText = summary.trim() ? summary.trim() : 'Details';
    return `<details>\n<summary>${sumText}</summary>\n${content}\n</details>`;
  });

  // 2. <details> und <summary> Blöcke herausnehmen und sichern
  text = text.replace(/<details([^>]*)>([\s\S]*?)<\/details>/gi, (_, attrs, content) => {
    let summaryHtml = '';
    let innerContent = content;
    
    const summaryMatch = innerContent.match(/<summary>([\s\S]*?)<\/summary>/i);
    if (summaryMatch) {
      // NEU: Den Summary-Text rekursiv als Markdown rendern!
      let parsedSummary = renderMarkdown(summaryMatch[1].trim());
      
      // Wenn das Ergebnis ein einzelnes <p>-Tag ist (z.B. bei normalem Text),
      // entfernen wir es, da <p> in <summary> den nativen Aufklapp-Pfeil verschiebt.
      if (parsedSummary.startsWith('<p>') && parsedSummary.endsWith('</p>') && parsedSummary.indexOf('<p>', 3) === -1) {
        parsedSummary = parsedSummary.substring(3, parsedSummary.length - 4);
      }
      
      parsedSummary = parsedSummary.replace(/<h([1-6])([^>]*)>/gi, '<h$1$2 style="display: inline; margin: 0;">');
      
      summaryHtml = `<summary>${parsedSummary}</summary>`;
      innerContent = innerContent.replace(/<summary>([\s\S]*?)<\/summary>/i, '');
    }

    // Rekursives Rendern des Inhalts
    const renderedInner = renderMarkdown(innerContent);
    
    detailsBlocks.push(`<details${attrs}>\n${summaryHtml}\n${renderedInner}\n</details>`);
    return `\u0000DETAILS${detailsBlocks.length - 1}\u0000`;
  });

  // 3. Jetzt erst den restlichen Text maskieren
  text = escapeHtml(text);

  const inline = s => s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, '<img src="$2" alt="$1" class="md-img">')
    .replace(/\[([^\]]+)\]\((#[^)\s]+)\)/g, '<a href="$2">$1</a>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer noopener">$1</a>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
    .replace(/~~([^~]+)~~/g, '<del>$1</del>');

  // 4. Tabellen herausnehmen
  text = text.replace(/^([^\n]*\|[^\n]*)\n(^[\s|:-]+\|[\s|:-]*$)\n?((?:^[^\n]*\Vert{}[^\n]*(?:\n\vert{}$))*)/gm, (match, headerLine, sepLine, bodyLines) => {
    const parseRow = (row, isHeader) => '<tr>' + row.split('|')
      .map(c => c.trim())
      .filter((c, i, arr) => !(c === '' && (i === 0 || i === arr.length - 1))) 
      .map(c => `<${isHeader ? 'th' : 'td'}>${inline(c)}</${isHeader ? 'th' : 'td'}>`)
      .join('') + '</tr>';
    
    const headHtml = parseRow(headerLine, true);
    const bodyHtml = bodyLines ? bodyLines.trim().split('\n').filter(Boolean).map(l => parseRow(l, false)).join('\n') : '';
    
    tableBlocks.push(`<table class="md-table">\n<thead>\n${headHtml}\n</thead>\n<tbody>\n${bodyHtml}\n</tbody>\n</table>`);
    return `\n\u0000TABLE${tableBlocks.length - 1}\u0000\n`;
  });

  const out = [];
  let listType = null;
  let inQuote = false;

  const closeList = () => { if (listType) { out.push(`</${listType}>`); listType = null; } };
  const closeQuote = () => { if (inQuote) { out.push('</blockquote>'); inQuote = false; } };
  const closeAll = () => { closeList(); closeQuote(); };

  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\s+$/, '');

    if (/^\u0000(?:CODE|DETAILS|TABLE)\d+\u0000$/.test(line.trim())) {
      closeAll();
      out.push(line.trim());
      continue;
    }

    if (!line.trim()) { closeAll(); continue; }

    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      closeAll();
      const level = heading[1].length;
      const titleText = heading[2];
      const id = slugify(titleText);
      out.push(`<h${level} id="${id}" class="md-h">${inline(titleText)}</h${level}>`);
      continue;
    }

    if (/^(---+|\*\*\*+|___+)$/.test(line.trim())) {
      closeAll();
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

    const task = line.match(/^\s*[-*+]\s+\[([ xX])\]\s+(.*)$/);
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

  closeAll();

  // 5. Blöcke wieder einfügen
  return out.join('\n')
    .replace(/\u0000CODE(\d+)\u0000/g, (_, i) => codeBlocks[Number(i)])
    .replace(/\u0000DETAILS(\d+)\u0000/g, (_, i) => detailsBlocks[Number(i)])
    .replace(/\u0000TABLE(\d+)\u0000/g, (_, i) => tableBlocks[Number(i)]);
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

