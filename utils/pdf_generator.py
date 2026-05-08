from xhtml2pdf import pisa
from io import BytesIO

def render_to_pdf(html_content):
    """
    Converts HTML content to a PDF file in-memory.
    """
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html_content.encode("UTF-8")), result)
    if not pdf.err:
        return result.getvalue()
    return None
