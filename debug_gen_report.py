import sqlite3
import json
import traceback
from reports.word_report import generate_word_report

def main():
    try:
        conn = sqlite3.connect('audit_results.db')
        cursor = conn.cursor()
        
        # Get table name
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        if not tables:
            print("No tables found in database.")
            return
        
        table_name = tables[0][0]
        print(f"Reading from table: {table_name}")
        
        # Get last record
        cursor.execute(f"SELECT target_url, results_json FROM {table_name} ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        
        if not row:
            print("No records found in database.")
            return
            
        target_url = row[0]
        results_json_str = row[1]
        
        print(f"Target URL: {target_url}")
        
        # Parse JSON
        results_list = json.loads(results_json_str)
        if not isinstance(results_list, list):
             # Try to wrap it if it's not a list, though prompt says 'lo convierta a list'
             # often meaning parsing the JSON string which should be a list.
             results_list = [results_list]

        print(f"Results converted to list. Length: {len(results_list)}")
        
        # Call report generator
        # generate_word_report(audit_name, target_url, results, pages=[], discovery={})
        output_path = generate_word_report(
            audit_name='debug_report',
            target_url=target_url,
            results=results_list,
            pages=[],
            discovery={}
        )
        
        print(f"Report generated successfully: {output_path}")
        
    except Exception:
        print("An error occurred:")
        traceback.print_exc()
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    main()
