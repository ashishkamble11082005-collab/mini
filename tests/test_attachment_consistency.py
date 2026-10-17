from io import BytesIO

from reportlab.pdfgen import canvas

from email_parser.schemas import AttachmentMetadata
from integration.attachment_consistency import analyze_attachment_consistency


def make_pdf(*lines: str) -> bytes:
    buffer = BytesIO()
    document = canvas.Canvas(buffer)
    for index, line in enumerate(lines):
        document.drawString(72, 720 - index * 25, line)
    document.save()
    return buffer.getvalue()


def make_attachment(*lines: str) -> AttachmentMetadata:
    return AttachmentMetadata(
        filename="college_fee_receipt.pdf",
        content_type="application/pdf",
        data=make_pdf(*lines),
    )


def test_receipt_email_with_account_security_pdf_is_flagged():
    attachment = make_attachment(
        "Your account is suspended.",
        "Verify your account and reset your password.",
    )

    findings = analyze_attachment_consistency(
        "Attached is your college fee payment receipt.",
        [attachment],
    )

    assert any(
        item["type"] == "pdf_body_content_mismatch"
        for item in findings
    )


def test_matching_receipt_email_and_pdf_are_not_flagged():
    attachment = make_attachment(
        "College fee payment receipt",
        "Payment received successfully",
    )

    findings = analyze_attachment_consistency(
        "Attached is your college fee payment receipt.",
        [attachment],
    )

    assert not any(
        item["type"] == "pdf_body_content_mismatch"
        for item in findings
    )
