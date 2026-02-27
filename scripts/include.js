async function loadPartial(id, url) {
  const el = document.getElementById(id);
  if (!el) return;
  try {
    const r = await fetch(url);
    el.innerHTML = await r.text();
  } catch (e) {
    el.innerHTML = "<!-- erreur chargement -->";
    console.error("Include error:", url, e);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  loadPartial("header", "partials/header.html");
  loadPartial("footer", "partials/footer.html");
});
