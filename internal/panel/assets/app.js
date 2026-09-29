document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const source = document.querySelector(button.dataset.copy);
  if (!source) return;
  await navigator.clipboard.writeText(source.value || source.textContent);
  const original = button.textContent;
  button.textContent = "Скопировано";
  setTimeout(() => { button.textContent = original; }, 1400);
});
