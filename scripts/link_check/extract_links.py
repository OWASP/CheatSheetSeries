"""Render Markdown like the published site and report its links and HTML IDs.

Reads {"documents": [{"key": str, "text": str}]} as JSON on stdin and writes
{"renderer": {...}, "documents": [{"key", "links", "ids"}]} as JSON on stdout.
Links are collected from the rendered HTML, so reference definitions, code
spans, code fences, and entities follow Python-Markdown semantics, and heading
IDs follow the toc extension used by mkdocs.yml (including "_1" suffixes for
duplicate headings).
"""

import json
import sys
from html.parser import HTMLParser

try:
    import markdown
    import pymdownx
    import pymdownx.emoji
except ImportError as error:  # pragma: no cover - exercised by the Node adapter
    sys.stderr.write(
        f"Markdown renderer dependency is missing ({error}). Install it with: "
        "python3 -m pip install -r scripts/link_check/requirements.txt\n"
    )
    sys.exit(3)

# MkDocs always enables toc, tables, and fenced_code before the extensions in
# mkdocs.yml. Keep this list in step with the markdown_extensions in mkdocs.yml.
EXTENSIONS = [
    "toc",
    "tables",
    "fenced_code",
    "pymdownx.highlight",
    "pymdownx.superfences",
    "pymdownx.inlinehilite",
    "pymdownx.tasklist",
    "pymdownx.emoji",
    "sane_lists",
]
EXTENSION_CONFIGS = {
    "toc": {"permalink": True},
    "pymdownx.emoji": {
        "emoji_index": pymdownx.emoji.twemoji,
        "emoji_generator": pymdownx.emoji.to_svg,
    },
}
GENERATED_CLASSES = {"headerlink", "twemoji", "emojione", "gemoji"}
URL_OPENERS = "(<\"' \t"
URL_CLOSERS = ")>\"' \t"


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.ids = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        classes = set((values.get("class") or "").split())
        generated = bool(classes & GENERATED_CLASSES)
        if tag == "a":
            if values.get("name"):
                self.ids.append(values["name"])
            if values.get("href") is not None and not generated:
                self.links.append({"url": values["href"], "kind": "link"})
        elif tag == "img" and values.get("src") is not None and not generated:
            self.links.append({"url": values["src"], "kind": "image"})

    handle_startendtag = handle_starttag


def source_positions(lines, url):
    """Return source line numbers where url appears as a delimited token."""
    variants = {url, url.replace("&", "&amp;")}
    found = []
    for number, line in enumerate(lines, start=1):
        for variant in variants:
            start = 0
            while variant and (index := line.find(variant, start)) != -1:
                end = index + len(variant)
                before = line[index - 1] if index > 0 else " "
                after = line[end] if end < len(line) else " "
                if before in URL_OPENERS and after in URL_CLOSERS:
                    found.append((number, index))
                start = index + 1
    return [number for number, _ in sorted(set(found))]


def assign_lines(text, links):
    """Attach Markdown source lines only when the mapping is unambiguous."""
    lines = text.splitlines()
    by_url = {}
    for link in links:
        by_url.setdefault(link["url"], []).append(link)
    for url, occurrences in by_url.items():
        positions = source_positions(lines, url)
        if len(positions) == len(occurrences):
            for link, line in zip(occurrences, positions):
                link["line"] = line
        elif len(positions) == 1:
            # One definition rendered several times (a reference link).
            for link in occurrences:
                link["line"] = positions[0]
        else:
            for link in occurrences:
                link["line"] = None


def extract(renderer, text):
    renderer.reset()
    collector = LinkCollector()
    collector.feed(renderer.convert(text))
    collector.close()
    assign_lines(text, collector.links)
    for ordinal, link in enumerate(collector.links, start=1):
        link["ordinal"] = ordinal
    return {"links": collector.links, "ids": collector.ids}


def main():
    request = json.load(sys.stdin)
    documents = request.get("documents")
    if not isinstance(documents, list):
        raise ValueError("request must contain a documents array")
    renderer = markdown.Markdown(
        extensions=EXTENSIONS, extension_configs=EXTENSION_CONFIGS
    )
    results = []
    for document in documents:
        if not isinstance(document.get("key"), str) or not isinstance(
            document.get("text"), str
        ):
            raise ValueError("each document needs string key and text values")
        results.append({"key": document["key"], **extract(renderer, document["text"])})
    json.dump(
        {
            "renderer": {
                "markdown": markdown.__version__,
                "pymdown-extensions": pymdownx.__version__,
            },
            "documents": results,
        },
        sys.stdout,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # Report any failure as an internal error.
        sys.stderr.write(f"Markdown link extraction failed: {error!r}\n")
        sys.exit(2)
