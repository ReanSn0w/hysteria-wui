import { load } from "./vendor/js-yaml.mjs";

const textarea = document.querySelector("#config-editor");
const form = document.querySelector("#config-form");
const status = document.querySelector("#yaml-status");
const save = document.querySelector("#config-save");

if (textarea && window.CodeMirror) {
  const editor = window.CodeMirror.fromTextArea(textarea, {
    mode: "yaml",
    lineNumbers: true,
    lineWrapping: true,
    indentUnit: 2,
    tabSize: 2,
  });
  const validate = () => {
    try {
      load(editor.getValue());
      status.textContent = "YAML синтаксически корректен. Инварианты проверит сервер.";
      status.className = "form-text mt-2 text-success";
      save.disabled = false;
      return true;
    } catch (error) {
      const mark = error.mark ? `Строка ${error.mark.line + 1}, колонка ${error.mark.column + 1}: ` : "";
      status.textContent = mark + (error.reason || error.message);
      status.className = "form-text mt-2 text-danger";
      save.disabled = true;
      return false;
    }
  };
  editor.on("change", validate);
  validate();
  form.addEventListener("submit", (event) => {
    editor.save();
    if (!validate() || !window.confirm("Сохранить YAML и кратковременно перезапустить Hysteria?")) event.preventDefault();
  });
}

document.querySelectorAll("form[data-confirm]").forEach((candidate) => {
  candidate.addEventListener("submit", (event) => {
    if (!window.confirm(candidate.dataset.confirm)) event.preventDefault();
  });
});

const ruleList = document.querySelector("#access-rule-list");
const orderForm = document.querySelector("#access-order-form");
const orderFields = document.querySelector("#access-order-fields");
const orderSave = document.querySelector("#access-order-save");

if (ruleList && orderForm && orderFields && orderSave) {
  const markChanged = () => {
    orderSave.disabled = false;
  };
  const move = (button, direction) => {
    const item = button.closest(".access-rule");
    const sibling = direction < 0 ? item.previousElementSibling : item.nextElementSibling;
    if (!sibling?.classList.contains("access-rule")) return;
    if (direction < 0) ruleList.insertBefore(item, sibling);
    else ruleList.insertBefore(sibling, item);
    markChanged();
    button.focus();
  };
  ruleList.querySelectorAll(".access-up").forEach((button) => button.addEventListener("click", () => move(button, -1)));
  ruleList.querySelectorAll(".access-down").forEach((button) => button.addEventListener("click", () => move(button, 1)));

  let dragged = null;
  let dragHandle = null;
  ruleList.querySelectorAll(".access-drag-handle").forEach((handle) => {
    handle.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      dragged = handle.closest(".access-rule");
      dragHandle = handle;
      handle.setPointerCapture(event.pointerId);
      dragged.classList.add("is-dragging");
    });
    handle.addEventListener("pointermove", (event) => {
      if (!dragged) return;
      const target = document.elementFromPoint(event.clientX, event.clientY)?.closest(".access-rule");
      if (!target || target === dragged || target.parentElement !== ruleList) return;
      const before = event.clientY < target.getBoundingClientRect().top + target.getBoundingClientRect().height / 2;
      ruleList.insertBefore(dragged, before ? target : target.nextElementSibling);
      markChanged();
    });
    const finish = (event) => {
      if (!dragged) return;
      dragged.classList.remove("is-dragging");
      if (dragHandle?.hasPointerCapture(event.pointerId)) dragHandle.releasePointerCapture(event.pointerId);
      dragged = null;
      dragHandle = null;
    };
    handle.addEventListener("pointerup", finish);
    handle.addEventListener("pointercancel", finish);
  });

  orderForm.addEventListener("submit", () => {
    orderFields.replaceChildren();
    ruleList.querySelectorAll(".access-rule").forEach((item) => {
      for (const [name, value] of [["rule_action", item.dataset.action], ["rule_domain", item.dataset.domain]]) {
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        orderFields.append(input);
      }
    });
  });
}
