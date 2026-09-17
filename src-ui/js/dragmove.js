/**
 * dragmove.js — Elemente per langem Drücken verschieben und umsortieren.
 *
 * Warum eigenes Modul: `gestures.js` aus wuefl-libs kann nur Wischgesten
 * und kennt weder langes Drücken noch Ziehen. Dieses Modul ist bewusst
 * allgemein gehalten, damit es sich dort einfügen ließe.
 *
 * Umgesetzt mit Pointer Events, also Maus, Finger und Stift zugleich —
 * die HTML5-Drag-and-Drop-API arbeitet auf Mobilgeräten nicht zuverlässig.
 *
 * Zwei Arten, etwas abzulegen:
 *
 *   hineinlegen  Zeiger in der Mitte eines Ziels  → onDrop(gezogen, ziel)
 *   einsortieren Zeiger am oberen/unteren Rand    → onReorder(gezogen, bezug, 'before'|'after')
 *
 * Dadurch lässt sich dasselbe Modul für Ordnerstrukturen und für eine
 * rein manuelle Reihenfolge verwenden.
 *
 *   const dnd = enableDragMove(container, {
 *     itemSelector:   '[data-drag-id]',
 *     targetSelector: '[data-drop-path]',
 *     onDrop:    (dragged, target) => {},
 *     onReorder: (dragged, reference, position) => {}
 *   });
 *   dnd.destroy();   // hängt alle Zuhörer wieder ab
 */

const DEFAULTS = {
  itemSelector: '[data-drag-id]',
  targetSelector: null,       // null = nur umsortieren, kein Hineinlegen
  longPressMs: 450,
  moveTolerance: 8,           // so viel darf der Finger wackeln, ohne abzubrechen
  edgeRatio: 0.3,             // oberer/unterer Anteil eines Elements = einsortieren
  reorder: true,
  label: null,
  onDrop: () => {},
  onReorder: () => {},
  onStart: () => {},
  onEnd: () => {}
};

export function enableDragMove(container, options = {}) {
  const cfg = { ...DEFAULTS, ...options };
  const abort = new AbortController();
  const { signal } = abort;

  let pressTimer = null;
  let dragging = false;
  let source = null;
  let ghost = null;
  let marker = null;
  let hoverTarget = null;
  let dropPlan = null;        // { mode: 'into'|'reorder', node, position }
  let startX = 0;
  let startY = 0;
  let pointerId = null;

  function clearHighlight() {
    hoverTarget?.classList.remove('drop-target');
    hoverTarget = null;
    marker?.remove();
    marker = null;
  }

  function cleanup() {
    clearTimeout(pressTimer);
    pressTimer = null;

    ghost?.remove();
    ghost = null;

    clearHighlight();

    source?.classList.remove('dragging');
    document.body.classList.remove('is-dragging');

    if (dragging) cfg.onEnd(source);

    dragging = false;
    source = null;
    dropPlan = null;
    pointerId = null;
  }

  function beginDrag(ev) {
    dragging = true;
    source.classList.add('dragging');
    document.body.classList.add('is-dragging');

    ghost = document.createElement('div');
    ghost.className = 'drag-ghost';
    ghost.textContent = cfg.label
      ? cfg.label(source)
      : (source.dataset.dragLabel || source.textContent.trim().slice(0, 40));
    document.body.append(ghost);
    moveGhost(ev.clientX, ev.clientY);

    navigator.vibrate?.(15);
    cfg.onStart(source);
  }

  function moveGhost(x, y) {
    if (ghost) ghost.style.transform = `translate(${x + 12}px, ${y + 12}px)`;
  }

  function elementUnder(x, y) {
    if (ghost) ghost.style.visibility = 'hidden';
    const el = document.elementFromPoint(x, y);
    if (ghost) ghost.style.visibility = '';
    return el;
  }

  /** Entscheidet, was an dieser Stelle passieren würde. */
  function planFor(x, y) {
    const el = elementUnder(x, y);
    if (!el) return null;

    const item = cfg.reorder ? el.closest(cfg.itemSelector) : null;
    const target = cfg.targetSelector ? el.closest(cfg.targetSelector) : null;

    const usable = node => node && node !== source && !source.contains(node);

    // Ist das Element zugleich Ziel und Element, entscheidet die Höhe:
    // Mitte heißt hineinlegen, Rand heißt daneben einsortieren.
    if (usable(item)) {
      const rect = item.getBoundingClientRect();
      const edge = rect.height * cfg.edgeRatio;
      const atTop = y < rect.top + edge;
      const atBottom = y > rect.bottom - edge;

      if (atTop || atBottom) {
        return { mode: 'reorder', node: item, position: atTop ? 'before' : 'after' };
      }
      if (!usable(target)) {
        return { mode: 'reorder', node: item, position: y < rect.top + rect.height / 2 ? 'before' : 'after' };
      }
    }

    if (usable(target)) return { mode: 'into', node: target };
    return null;
  }

  function showPlan(plan) {
    const same = dropPlan && plan &&
      dropPlan.mode === plan.mode &&
      dropPlan.node === plan.node &&
      dropPlan.position === plan.position;
    if (same) return;

    clearHighlight();
    dropPlan = plan;
    if (!plan) return;

    if (plan.mode === 'into') {
      plan.node.classList.add('drop-target');
      hoverTarget = plan.node;
      return;
    }

    marker = document.createElement('div');
    marker.className = 'drop-marker';
    const rect = plan.node.getBoundingClientRect();
    marker.style.top = `${plan.position === 'before' ? rect.top : rect.bottom}px`;
    marker.style.left = `${rect.left}px`;
    marker.style.width = `${rect.width}px`;
    document.body.append(marker);
  }

  container.addEventListener('pointerdown', ev => {
    if (ev.pointerType === 'mouse' && ev.button !== 0) return;
    if (ev.target.closest('button, input, select, textarea, a')) return;

    const item = ev.target.closest(cfg.itemSelector);
    if (!item || !container.contains(item)) return;

    source = item;
    startX = ev.clientX;
    startY = ev.clientY;
    pointerId = ev.pointerId;

    pressTimer = setTimeout(() => beginDrag(ev), cfg.longPressMs);
  }, { signal });

  container.addEventListener('pointermove', ev => {
    if (ev.pointerId !== pointerId) return;

    if (!dragging) {
      // Vor dem Start heißt Bewegung: scrollen, nicht ziehen
      if (Math.hypot(ev.clientX - startX, ev.clientY - startY) > cfg.moveTolerance) {
        clearTimeout(pressTimer);
        pressTimer = null;
        source = null;
        pointerId = null;
      }
      return;
    }

    ev.preventDefault();
    moveGhost(ev.clientX, ev.clientY);
    showPlan(planFor(ev.clientX, ev.clientY));
  }, { signal });

  const finish = ev => {
    if (ev.pointerId !== pointerId) return;

    if (!dragging) { cleanup(); return; }

    const plan = planFor(ev.clientX, ev.clientY);
    const dragged = source;
    cleanup();

    if (!plan) return;
    if (plan.mode === 'into') cfg.onDrop(dragged, plan.node);
    else cfg.onReorder(dragged, plan.node, plan.position);
  };

  container.addEventListener('pointerup', finish, { signal });
  container.addEventListener('pointercancel', finish, { signal });

  document.addEventListener('keydown', ev => {
    if (ev.key === 'Escape' && dragging) cleanup();
  }, { signal });

  window.addEventListener('scroll', () => { if (dragging) clearHighlight(); }, { signal, capture: true });

  return {
    destroy() {
      cleanup();
      abort.abort();
    }
  };
}
