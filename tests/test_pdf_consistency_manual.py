from email_parser.schemas import AttachmentMetadata
from integration.attachment_consistency import analyze_attachment_consistency
from pypdf import PdfWriter
from io import BytesIO

# Create a real PDF containing suspiciously unrelated account instructions.
writer = PdfWriter()
page = writer.add_blank_page(width=612, height=792)
page.merge_page(page) if False else None

# Generate a PDF with extractable text using a small reportlab canvas.
from reportlab.pdfgen import canvas
pdf_buffer = BytesIO()
pdf_canvas = canvas.Canvas(pdf_buffer)
pdf_canvas.drawString(72, 720, "College fee payment receipt")
pdf_canvas.drawString(72, 700, "Payment received successfully")
pdf_canvas.save()
pdf_bytes = pdf_buffer.getvalue()

attachment = AttachmentMetadata(
    filename="college_fee_receipt.pdf",
    content_type="application/pdf",
    data=pdf_bytes,
)

findings = analyze_attachment_consistency(
    "Attached is your college fee payment receipt.",
    [attachment],
)

print("Findings:", findings)
assert not any(
    finding["type"] == "pdf_body_content_mismatch"
    for finding in findings
), "FAIL: Matching receipt was incorrectly flagged"


print("PASS: Matching receipt was not flagged")
