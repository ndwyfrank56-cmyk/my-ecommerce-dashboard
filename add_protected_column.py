#!/usr/bin/env python3
"""
Script to add is_protected column to workers table
Run this once to add the column to your database
"""
import os
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

try:
    with app.app_context():
        cur = mysql.connection.cursor()
        
        # Check if column already exists
        cur.execute("""
            SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_NAME='workers' AND COLUMN_NAME='is_protected'
        """)
        
        if cur.fetchone():
            print("✓ Column 'is_protected' already exists")
        else:
            # Add the column
            cur.execute("""
                ALTER TABLE workers 
                ADD COLUMN is_protected TINYINT(1) DEFAULT 0 AFTER created_at
            """)
            mysql.connection.commit()
            print("✓ Column 'is_protected' added successfully")
        
        cur.close()
        
except Exception as e:
    print(f"✗ Error: {e}")
