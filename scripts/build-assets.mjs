import { copyFile, mkdir } from "node:fs/promises";

const target = "internal/panel/assets/vendor";
await mkdir(target, { recursive: true });

const files = [
  ["node_modules/bootstrap/dist/css/bootstrap.min.css", `${target}/bootstrap.min.css`],
  ["node_modules/bootstrap/dist/js/bootstrap.bundle.min.js", `${target}/bootstrap.bundle.min.js`],
  ["node_modules/htmx.org/dist/htmx.min.js", `${target}/htmx.min.js`],
  ["node_modules/codemirror/lib/codemirror.css", `${target}/codemirror.css`],
  ["node_modules/codemirror/lib/codemirror.js", `${target}/codemirror.js`],
  ["node_modules/codemirror/mode/yaml/yaml.js", `${target}/yaml.js`],
  ["node_modules/js-yaml/dist/js-yaml.mjs", `${target}/js-yaml.mjs`]
];

for (const [source, destination] of files) {
  await copyFile(source, destination);
}
