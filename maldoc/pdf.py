"""PDF feature extraction.

We don't try to render or fully parse — we just walk the raw catalog and
collect the strings that the indicator catalog cares about.
"""

from __future__ import annotations

from pathlib import Path


def _walk(obj, chunks: list[str], seen: set[int], depth: int = 0) -> None:
    """Recursively stringify a PDF object graph, resolving indirect references.

    Guards against cycles (PDF object graphs are routinely cyclic) via an
    identity set and a depth cap.
    """
    if depth > 50:
        return
    try:
        from pypdf.generic import IndirectObject
    except ImportError:  # pragma: no cover - pypdf already imported by caller
        IndirectObject = ()

    if isinstance(obj, IndirectObject):
        try:
            obj = obj.get_object()
        except Exception:
            return

    oid = id(obj)
    if oid in seen:
        return
    seen.add(oid)

    # Record a string representation of this node (keys, names, /JavaScript, etc.)
    try:
        chunks.append(str(obj))
    except Exception:
        pass

    # Recurse into containers so deeply-nested actions are reached.
    try:
        if isinstance(obj, dict):
            for key, val in obj.items():
                chunks.append(str(key))
                _walk(val, chunks, seen, depth + 1)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item, chunks, seen, depth + 1)
    except Exception:
        pass


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
    seen: set[int] = set()

    # Walk the whole document graph starting from the trailer. /Root reaches the
    # catalog (OpenAction, AcroForm, Names→JavaScript), and walking the trailer
    # also covers /Info and any other top-level entries.
    try:
        _walk(reader.trailer, chunks, seen)
    except Exception as e:
        notes.append(f"failed to walk trailer: {e}")

    # Walk every page object explicitly — page dicts hold /Annots and per-page
    # actions, and the content streams hold the actual operators.
    try:
        for page in reader.pages:
            _walk(page, chunks, seen)
            try:
                data = page.get_contents()
                if data is not None:
                    chunks.append(data.get_data().decode("latin-1", errors="replace"))
            except Exception as e:
                notes.append(f"failed to read a page content stream: {e}")
    except Exception as e:
        notes.append(f"failed to enumerate pages: {e}")

    if not chunks:
        notes.append("no objects extracted — file may be malformed")
    return "\n".join(chunks), notes
