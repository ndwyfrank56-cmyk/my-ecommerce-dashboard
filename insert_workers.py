#!/usr/bin/env python3
"""
Script to insert worker records into the database
"""
import mysql.connector
from mysql.connector import Error

# Database connection details
config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'ecommerce_db'
}

try:
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()
    
    # Worker data to insert
    workers = [
        ('Nduwayo Frank', '+250788123456', 'ndwyfrank56@gmail.com', 50000, 'Manager', 'Operations'),
        ('Alice Johnson', '+250789234567', 'alice.johnson@company.com', 45000, 'Developer', 'IT'),
        ('Marie Uwase', '+250790345678', 'marie.uwase@company.com', 42000, 'Designer', 'Marketing'),
        ('Jean Habimana', '+250791456789', 'jean.habimana@company.com', 48000, 'Accountant', 'Finance'),
    ]
    
    insert_query = """
        INSERT INTO workers (name, phone, email, salary, profession, deptName, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, NOW())
    """
    
    for worker in workers:
        try:
            cursor.execute(insert_query, worker)
            worker_id = cursor.lastrowid
            
            # Give them full access to all pages by default
            all_pages = ['dashboard', 'orders', 'products', 'reviews', 'customers', 'workers', 'reports']
            for page in all_pages:
                cursor.execute("""
                    INSERT INTO worker_page_permissions (worker_id, pages)
                    VALUES (%s, %s)
                """, (worker_id, page))
            
            print(f"✓ Added worker: {worker[0]} (ID: {worker_id})")
        except Error as e:
            print(f"✗ Error adding {worker[0]}: {e}")
    
    connection.commit()
    print("\n✓ All workers added successfully!")
    
except Error as e:
    print(f"Database connection error: {e}")
finally:
    if connection.is_connected():
        cursor.close()
        connection.close()
