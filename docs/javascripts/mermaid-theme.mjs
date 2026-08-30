// Renders ```mermaid fences with a theme derived from this site's own
// palette (primary teal #009485, accent cyan #00bad6) instead of mermaid's
// generic defaults, and keeps diagrams in sync with the light/dark toggle.
//
// pymdownx.superfences emits the raw diagram source as
// `<pre class="mermaid-source"><code>...</code></pre>` (see mkdocs.yml —
// the fence is still named `mermaid` so every ```mermaid block in docs/
// works unchanged; only the output class was renamed so Material's own
// built-in mermaid auto-render, which floats an unpinned mermaid version
// and renders into a closed shadow root we cannot restyle, never claims
// these elements). This module owns rendering end to end instead.

import mermaid from "https://unpkg.com/mermaid@11.17.2/dist/mermaid.esm.min.mjs";

const FONT_FAMILY = "Inter, var(--md-text-font-family), sans-serif";

const LIGHT_VARIABLES = {
  background: "#ffffff",
  primaryColor: "#e6f5f3",
  primaryTextColor: "#1d2b30",
  primaryBorderColor: "#007a6c",
  secondaryColor: "#eef7f6",
  secondaryTextColor: "#1d2b30",
  secondaryBorderColor: "#26a699",
  tertiaryColor: "#f5fbfa",
  tertiaryTextColor: "#1d2b30",
  tertiaryBorderColor: "#26a699",
  lineColor: "#007a6c",
  textColor: "#1d2b30",
  mainBkg: "#e6f5f3",
  nodeTextColor: "#1d2b30",
  clusterBkg: "#f5fbfa",
  clusterBorder: "#26a699",
  defaultLinkColor: "#007a6c",
  titleColor: "#1d2b30",
  edgeLabelBackground: "#ffffff",
  actorBkg: "#e6f5f3",
  actorBorder: "#007a6c",
  actorTextColor: "#1d2b30",
  actorLineColor: "#007a6c",
  signalColor: "#1d2b30",
  signalTextColor: "#1d2b30",
  labelBoxBkgColor: "#e6f5f3",
  labelBoxBorderColor: "#007a6c",
  labelTextColor: "#1d2b30",
  loopTextColor: "#1d2b30",
  noteBkgColor: "#dcf0ec",
  noteTextColor: "#1d2b30",
  noteBorderColor: "#007a6c",
  activationBkgColor: "#d3ece8",
  activationBorderColor: "#007a6c",
  sequenceNumberColor: "#ffffff",
};

const DARK_VARIABLES = {
  background: "#1c2127",
  primaryColor: "#123b37",
  primaryTextColor: "#e3f2f1",
  primaryBorderColor: "#22d3ee",
  secondaryColor: "#17302d",
  secondaryTextColor: "#d7e6e4",
  secondaryBorderColor: "#22d3ee",
  tertiaryColor: "#142623",
  tertiaryTextColor: "#d7e6e4",
  tertiaryBorderColor: "#22d3ee",
  lineColor: "#22d3ee",
  textColor: "#d7e6e4",
  mainBkg: "#123b37",
  nodeTextColor: "#e3f2f1",
  clusterBkg: "#142623",
  clusterBorder: "#22d3ee",
  defaultLinkColor: "#22d3ee",
  titleColor: "#e3f2f1",
  edgeLabelBackground: "#1c2127",
  actorBkg: "#123b37",
  actorBorder: "#22d3ee",
  actorTextColor: "#e3f2f1",
  actorLineColor: "#22d3ee",
  signalColor: "#d7e6e4",
  signalTextColor: "#d7e6e4",
  labelBoxBkgColor: "#123b37",
  labelBoxBorderColor: "#22d3ee",
  labelTextColor: "#e3f2f1",
  loopTextColor: "#d7e6e4",
  noteBkgColor: "#0e3a42",
  noteTextColor: "#dff5f3",
  noteBorderColor: "#22d3ee",
  activationBkgColor: "#164943",
  activationBorderColor: "#22d3ee",
  sequenceNumberColor: "#0e1013",
};

let renderToken = 0;

function currentScheme() {
  return document.body.getAttribute("data-md-color-scheme") === "slate" ? "dark" : "light";
}

function themeVariablesFor(scheme) {
  return scheme === "dark" ? DARK_VARIABLES : LIGHT_VARIABLES;
}

async function renderAll() {
  const sources = document.querySelectorAll("pre.mermaid-source");
  if (!sources.length) return;

  const scheme = currentScheme();
  mermaid.initialize({
    startOnLoad: false,
    theme: "base",
    themeVariables: themeVariablesFor(scheme),
    fontFamily: FONT_FAMILY,
    sequence: { actorFontSize: 15, messageFontSize: 15, noteFontSize: 14 },
    flowchart: { htmlLabels: true, curve: "basis" },
  });

  const token = ++renderToken;

  for (const pre of sources) {
    if (!pre.dataset.mermaidSource) {
      pre.dataset.mermaidSource = pre.textContent;
    }
    const source = pre.dataset.mermaidSource;

    let target = pre.nextElementSibling;
    if (!target || !target.classList.contains("mermaid-diagram")) {
      target = document.createElement("div");
      target.className = "mermaid-diagram";
      pre.insertAdjacentElement("afterend", target);
    }

    const id = `mermaid-${Math.random().toString(36).slice(2, 10)}`;
    try {
      const { svg, bindFunctions } = await mermaid.render(id, source);
      if (token !== renderToken) return; // a newer render pass superseded this one
      target.innerHTML = svg;
      bindFunctions?.(target);
    } catch (error) {
      target.textContent = "Diagram failed to render.";
      console.error("mermaid render failed", error);
    }
  }
}

function watchPaletteToggle() {
  document.addEventListener("change", (event) => {
    if (event.target instanceof HTMLInputElement && event.target.name === "__palette") {
      renderAll();
    }
  });
}

if (typeof document$ !== "undefined") {
  document$.subscribe(() => renderAll());
} else {
  document.addEventListener("DOMContentLoaded", () => renderAll());
}
watchPaletteToggle();
