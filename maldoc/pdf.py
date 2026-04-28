"""PDF feature extraction.

We don't try to render or fully parse — we just walk the raw catalog and
collect the strings that the indicator catalog cares about.
"""

from __future__ import annotations

from pathlib import Path


def extract_pdf_features(path: Path) -> tuple[str, list[str]]:
    """Return (concatenated PDF object text, notes).

    Walks every object in the PDF and concatenates a string-ified representation
    so the indicator regex catalog can scan for /JavaScript, /Launch, /URI, etc.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        return "", ["pypdf is not installed"]

    notes: list[str] = []
    try:
        reader = PdfReader(str(path))
    except Exception as e:
        return "", [f"failed to open: {e}"]

    if reader.is_encrypted:
        notes.append("PDF is encrypted — feature extraction may be incomplete")

    chunks: list[str] = []
    try:
        # Catalog — the entry point that holds OpenAction, AcroForm, etc.
        catalog = reader.trailer.get("/Root")
        if catalog:
            chunks.append(str(catalog.get_object()))
    except Exception:
        pass

    # Walk indirect objects — in pypdf these are exposed via reader.resolved_objects
    try:
        for obj in (reader.resolved_objects or {}).values():
            try:
                chunks.append(str(obj))
            except Exception:
                continue
    except Exception:
        pass

    if not chunks:
        notes.append("no objects extracted — file may be malformed")
    return "\n".join(chunks), notes
