document$.subscribe(function () {
  mermaid.initialize({
    startOnLoad: false,
    securityLevel: "loose",
    theme: "neutral",
  });

  document.querySelectorAll("pre code.language-mermaid").forEach(function (element) {
    const text = element.textContent;
    const id = "mermaid-" + Math.random().toString(36).slice(2, 10);
    const container = document.createElement("div");
    container.className = "mermaid";

    element.parentElement.replaceWith(container);

    mermaid.render(id, text).then(function (result) {
      container.innerHTML = result.svg;
    });
  });
});