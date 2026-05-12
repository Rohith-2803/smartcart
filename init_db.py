import sqlite3
import os

def init_db():
    db_path = os.path.join('database', 'smartcart.db')
    schema_path = 'schema.sql'
    
    # Ensure database directory exists
    if not os.path.exists('database'):
        os.makedirs('database')
        print("Created database directory.")
        
    if not os.path.exists(schema_path):
        print(f"Error: {schema_path} not found.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Read and execute schema
    with open(schema_path, 'r') as f:
        schema = f.read()
    
    try:
        cursor.executescript(schema)
        conn.commit()
        print(f"Database successfully initialized at {db_path} using {schema_path}.")
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
