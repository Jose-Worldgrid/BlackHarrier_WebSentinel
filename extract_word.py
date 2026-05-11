import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

# Extract Word document
word_path = Path("Auditoría_Web_-_2026-05-11_20260511_085857.docx")
if word_path.exists():
    with zipfile.ZipFile(word_path, 'r') as zip_ref:
        # Extract document.xml
        try:
            doc_xml = zip_ref.read('word/document.xml').decode('utf-8')
            # Parse and print readable content
            root = ET.fromstring(doc_xml)
            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            
            # Extract all text
            print("=" * 80)
            print("CONTENIDO WORD DOCUMENT")
            print("=" * 80)
            
            for para in root.findall('.//w:p', ns):
                text = ''.join(para.itertext())
                if text.strip():
                    print(text)
            
            print("\n" + "=" * 80)
            print("TABLAS EN WORD")
            print("=" * 80)
            
            for table in root.findall('.//w:tbl', ns):
                rows = table.findall('.//w:tr', ns)
                for row in rows:
                    cells = row.findall('.//w:tc', ns)
                    row_data = []
                    for cell in cells:
                        cell_text = ''.join(cell.itertext())
                        row_data.append(cell_text.strip())
                    print(" | ".join(row_data))
                print("-" * 80)
                    
        except Exception as e:
            print(f"Error extracting: {e}")
            import traceback
            traceback.print_exc()
else:
    print("Archivo no encontrado")
