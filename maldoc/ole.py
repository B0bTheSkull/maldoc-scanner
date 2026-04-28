"""Wrapper around oletools/olevba to extract VBA from Office documents."""

from __future__ import annotations

from pathlib import Path


def extract_vba(path: Path) -> tuple[str, list[str]]:
    """Return (concatenated VBA source, notes).

    Notes are non-fatal observations from the parser (e.g. 'no VBA found',
    'document looks encrypted'). The source is "" if extraction failed or
    no VBA is present.
    """
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return "", ["oletools is not installed"]

    notes: list[str] = []
    try:
        parser = VBA_Parser(str(path))
    except Exception as e:
        return "", [f"failed to open: {e}"]

    try:
        if not parser.detect_vba_macros():
            notes.append("no VBA macros detected by oletools")
            return "", notes

        chunks: list[str] = []
        for filename, stream_path, vba_filename, vba_code in parser.extract_macros():
            if vba_code:
                chunks.append(f"' --- {vba_filename} ({stream_path}) ---\n{vba_code}")
        if not chunks:
            notes.append("oletools reported macros present but extracted nothing")
        return "\n\n".join(chunks), notes
    finally:
        try:
            parser.close()
        except Exception:
            pass
