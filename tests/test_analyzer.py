from pathlib import Path

from maldoc.analyzer import analyze_office, analyze_pdf

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_benign_macro_low():
    text = (EXAMPLES / "benign_macro.txt").read_text()
    report = analyze_office(text)
    assert report.severity == "low"
    assert report.score < 25


def test_malicious_macro_high():
    text = (EXAMPLES / "sample_macro.txt").read_text()
    report = analyze_office(text)
    assert report.severity == "high"
    assert report.score >= 60


def test_malicious_macro_specific_hits():
    text = (EXAMPLES / "sample_macro.txt").read_text()
    report = analyze_office(text)
    names = {h.name for h in report.hits}
    assert "vba_autoopen" in names
    assert "vba_wscript_shell" in names
    assert "vba_powershell_string" in names
    assert "vba_xmlhttp" in names
    assert "vba_schtasks" in names


def test_malicious_macro_extracts_urls():
    text = (EXAMPLES / "sample_macro.txt").read_text()
    report = analyze_office(text)
    assert any("attacker.example" in u for u in report.iocs.urls)


def test_pdf_features_high():
    text = (EXAMPLES / "sample_pdf_features.txt").read_text()
    report = analyze_pdf(text)
    names = {h.name for h in report.hits}
    assert "pdf_javascript" in names
    assert "pdf_launch" in names
    assert "pdf_openaction" in names
    assert "pdf_embeddedfile" in names
    assert report.severity == "high"


def test_pdf_uri_extracted():
    text = (EXAMPLES / "sample_pdf_features.txt").read_text()
    report = analyze_pdf(text)
    assert any("attacker" in u for u in report.iocs.urls)


def test_score_capped_at_100():
    # Cram many high-weight indicators into one blob
    blob = (
        "AutoOpen Document_Open Workbook_Open Shell WScript.Shell powershell IEX "
        "MSXML2.XMLHTTP WinHttp.WinHttpRequest URLDownloadToFile DownloadString "
        "VirtualAlloc RtlMoveMemory CreateRemoteThread schtasks HKCU\\Software\\Run"
    )
    report = analyze_office(blob)
    assert report.score == 100


def test_pdf_javascript_openaction_detected(tmp_path):
    """A tiny PDF carrying /JavaScript + /OpenAction must be extracted and flagged."""
    import pytest

    pypdf = pytest.importorskip("pypdf")
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    from maldoc.pdf import extract_pdf_features

    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=72)

    # Build a JavaScript action and wire it up as the document OpenAction.
    js_action = DictionaryObject(
        {
            NameObject("/S"): NameObject("/JavaScript"),
            NameObject("/JS"): TextStringObject("app.alert('pwned');"),
        }
    )
    js_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = js_ref
    # Also register it under Names → JavaScript, the other common location.
    writer._root_object[NameObject("/Names")] = DictionaryObject(
        {
            NameObject("/JavaScript"): DictionaryObject(
                {NameObject("/Names"): ArrayObject([TextStringObject("evil"), js_ref])}
            )
        }
    )

    out = tmp_path / "evil.pdf"
    with open(out, "wb") as fh:
        writer.write(fh)

    content, notes = extract_pdf_features(out)

    # Extraction must actually produce object text (the old code returned nothing).
    assert content, f"no content extracted; notes={notes}"
    assert "/OpenAction" in content
    assert "/JavaScript" in content

    report = analyze_pdf(content, source=str(out))
    hit_names = {h.name for h in report.hits}
    assert "pdf_javascript" in hit_names
    assert "pdf_openaction" in hit_names
    assert report.severity in ("medium", "high")
