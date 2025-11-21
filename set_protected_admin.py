#!/usr/bin/env python3
"""
Script to set a worker as a protected admin
Usage: python set_protected_admin.py <worker_id>
"""
import os
import sys
from flask import Flask
from flask_mysqldb import MySQL

app = Flask(__name__)

# Database Configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'ecommerce')
app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT', 3306))

mysql = MySQL(app)

def set_protected_admin(worker_id):
    """Set a worker as protected admin"""
    try:
        with app.app_context():
            cur = mysql.connection.cursor()
            
            # Check if worker exists
            cur.execute("SELECT name FROM workers WHERE worker_id = %s", (worker_id,))
            worker = cur.fetchone()
            
            if not worker:
                print(f"✗ Worker with ID {worker_id} not found")
                return False
            
            # Update worker to be protected
            cur.execute("""
                UPDATE workers 
                SET is_protected = 1 
                WHERE worker_id = %s
            """, (worker_id,))
            
            mysql.connection.commit()
            print(f"✓ {worker[0]} is now a protected admin and cannot be deleted")
            return True
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python set_protected_admin.py <worker_id>")
        print("Example: python set_protected_admin.py 1")
        sys.exit(1)
    
    try:
        worker_id = int(sys.argv[1])
        set_protected_admin(worker_id)
    except ValueError:
        print("✗ Worker ID must be a number")
        sys.exit(1)
