// The trace is an illustration. It never submits metadata or calls a scanner.
export function setupInspectionMotion(engine) {
  if (!engine) return;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const replay = engine.querySelector('[data-replay]');
  const pause = engine.querySelector('[data-pause]');
  let observer;

  function finish() {
    engine.classList.remove('is-running', 'is-paused');
    pause.hidden = true;
  }
  function play() {
    finish();
    if (reduced.matches) return;
    pause.textContent = 'Pause animation';
    pause.hidden = false;
    // Two frames reset the finite CSS sequence without hiding its content.
    requestAnimationFrame(() => requestAnimationFrame(() => {
      if (!reduced.matches) engine.classList.add('is-running');
    }));
  }
  function applyPreference() {
    replay.hidden = reduced.matches;
    if (reduced.matches) { finish(); observer?.disconnect(); }
  }
  pause.addEventListener('click', () => {
    const paused = engine.classList.toggle('is-paused');
    pause.textContent = paused ? 'Resume animation' : 'Pause animation';
  });
  replay.addEventListener('click', play);
  engine.addEventListener('animationend', event => {
    if (event.animationName === 'inspection-sweep') finish();
  });
  reduced.addEventListener('change', applyPreference);
  applyPreference();
  if (!reduced.matches) {
    if ('IntersectionObserver' in window) {
      observer = new IntersectionObserver(entries => {
        if (entries.some(entry => entry.isIntersecting)) { play(); observer.disconnect(); }
      }, { threshold: 0.25 });
      observer.observe(engine);
    } else play();
  }
}
