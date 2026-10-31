const label = document.getElementById("status");
const approvals = document.getElementById("approvals");
// Touchscreens keep :hover after a tap, which would pause the page for good.
const hovering = matchMedia("(hover: hover)").matches ? ", #approvals :is(button, summary):hover" : "";
const busy = `details[open], #approvals :focus-visible, #approvals :active${hovering}`;
let latest = 0;

function show(state) {
  label.textContent = state;
  label.dataset.state = state.toLowerCase();
}

async function refresh() {
  if (document.hidden) return;
  if (document.querySelector(busy)) return show("Paused");
  const ticket = ++latest;
  try {
    const response = await fetch(location.href, {
      cache: "no-store",
      signal: AbortSignal.timeout(4000),
    });
    const html = await response.text();
    if (ticket !== latest) return;
    const next = new DOMParser().parseFromString(html, "text/html").getElementById("approvals");
    if (!response.ok || !next) return show("Offline");
    if (document.querySelector(busy)) return show("Paused");
    if (next.innerHTML !== approvals.innerHTML) approvals.replaceChildren(...next.childNodes);
    show("Live");
  } catch {
    if (ticket === latest) show("Offline");
  }
}

document.addEventListener("toggle", refresh, true);
document.addEventListener("visibilitychange", refresh);
setInterval(refresh, 5000);
