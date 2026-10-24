"""Create fictional demo content and a clearly marked placeholder image."""
import io
from PIL import Image, ImageDraw, ImageFont
from starlette.datastructures import UploadFile
from app.main import connect, create_assessment, create_finding, upload_evidence, Assessment, Finding

def add_placeholder(fid):
    image=Image.new('RGB',(1200,620),(9,20,32)); draw=ImageDraw.Draw(image)
    draw.rectangle((0,0,1199,58),fill=(20,38,54)); draw.ellipse((22,22,34,34),fill=(226,99,110)); draw.ellipse((45,22,57,34),fill=(233,188,83)); draw.ellipse((68,22,80,34),fill=(86,207,163))
    draw.text((28,108),'FICTIONAL DEMO — PLACEHOLDER ONLY',fill=(92,216,198))
    draw.text((28,165),'Example application evidence image',fill=(224,235,242))
    draw.text((28,212),'Not captured from a real system. No testing was performed.',fill=(151,170,184))
    draw.rounded_rectangle((28,290,1170,390),radius=8,outline=(51,76,94),width=2)
    draw.text((52,326),'demo.example.test   |   illustrative placeholder',fill=(132,158,174))
    stream=io.BytesIO(); image.save(stream,format='PNG'); stream.seek(0)
    upload_evidence(fid,UploadFile(filename='fictional-placeholder.png',file=stream),caption='Fictional illustration only; not test evidence.')

with connect() as db:
    exists=db.execute("SELECT id FROM assessments WHERE title='Fictional Demo — Example Shop'").fetchone()
if not exists:
    a=create_assessment(Assessment(title='Fictional Demo — Example Shop',client='Fictional client',kind='Web application',target='shop.example.test',environment='Lab',tester='Demo security team',scope='Fictional lab domain only. No real systems were tested.',notes='All details are invented for UI demonstration.'))
    f=create_finding(a['id'],Finding(title='Missing Content Security Policy header (fictional)',location='https://shop.example.test/',category='Security misconfiguration',severity='Low',description='Fictional demonstration observation: the example response did not include a Content-Security-Policy header. This does not describe a real target.',evidence='Placeholder evidence only: fictional response metadata indicates the header was absent. No real request was made.',impact='A restrictive policy may reduce the impact of some client-side injection issues if present.',remediation='Define a Content-Security-Policy suited to the application, test in report-only mode, then enforce it.',validation='Check representative responses and exercise application flows for policy violations.',status='Needs Review'))
    add_placeholder(f['id'])
    print('Added fictional assessment, finding, and a marked placeholder image. No real system was tested.')
else:
    with connect() as db:
        finding=db.execute('SELECT id FROM findings WHERE assessment_id=? ORDER BY finding_code LIMIT 1',(exists['id'],)).fetchone()
        has_evidence=db.execute('SELECT COUNT(*) FROM evidence WHERE finding_id=?',(finding['id'],)).fetchone()[0] if finding else 0
    if finding and not has_evidence:
        add_placeholder(finding['id']); print('Added a marked placeholder image to the existing fictional sample.')
    else: print('Fictional demo assessment is ready.')
