from __future__ import annotations

from markdown_it import MarkdownIt

from .models import CodeBlockInfo, HeadingInfo, LinkInfo, ParsedMarkdown


_MARKDOWN = MarkdownIt("commonmark", {"html": False})


def _line_offsets(text: str) -> list[int]:
    offsets = [0]
    running = 0
    for line in text.splitlines(keepends=True):
        running += len(line)
        offsets.append(running)
    return offsets


def _offset_for_line(offsets: list[int], line: int) -> int:
    index = max(0, min(line - 1, len(offsets) - 1))
    return offsets[index]


def parse_markdown(text: str) -> ParsedMarkdown:
    tokens = _MARKDOWN.parse(text)
    offsets = _line_offsets(text)
    headings: list[HeadingInfo] = []

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.type == "heading_open" and index + 1 < len(tokens):
            inline_token = tokens[index + 1]
            heading_text = inline_token.content.strip()
            if heading_text:
                line = (token.map[0] + 1) if token.map else 1
                headings.append(
                    HeadingInfo(
                        level=int(token.tag[1]) if token.tag.startswith("h") else 1,
                        text=heading_text,
                        line=line,
                        start_offset=_offset_for_line(offsets, line),
                    )
                )
        index += 1

    parsed = ParsedMarkdown()
    parsed.headings = headings
    parsed.title = next(
        (heading.text for heading in headings if heading.level == 1),
        headings[0].text if headings else None,
    )

    for token in tokens:
        if token.type in {"fence", "code_block"}:
            line = (token.map[0] + 1) if token.map else 1
            language = token.info.strip().split()[0] if getattr(token, "info", "").strip() else None
            parsed.code_blocks.append(
                CodeBlockInfo(
                    language=language,
                    content=token.content,
                    line=line,
                    section=parsed.section_for_line(line),
                )
            )
            continue

        if token.type != "inline" or not token.children:
            continue

        line = (token.map[0] + 1) if token.map else 1
        section = parsed.section_for_line(line)
        children = token.children
        child_index = 0
        while child_index < len(children):
            child = children[child_index]
            if child.type != "link_open":
                child_index += 1
                continue

            href = child.attrGet("href")
            link_text_parts: list[str] = []
            close_index = child_index + 1
            while close_index < len(children) and children[close_index].type != "link_close":
                content = children[close_index].content
                if content:
                    link_text_parts.append(content)
                close_index += 1

            if href:
                parsed.links.append(
                    LinkInfo(
                        url=href.strip(),
                        text="".join(link_text_parts).strip() or href.strip(),
                        line=line,
                        section=section,
                    )
                )

            child_index = close_index + 1

    return parsed

