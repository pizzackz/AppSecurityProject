import pandas as pd
import mysql.connector
from mysql.connector import Error


def connect_to_JacenDB():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='app_sec_log',
            user='jcen',
            password='Soulsting@123'
        )
        if connection.is_connected():
            print("success")
        return connection
    except Error as e:
        print(f"Error: {e}")
        return 'none'

def create_INFO(connection):
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS LOG_INFO (
                id INT AUTO_INCREMENT PRIMARY KEY,
                datetime DATETIME,
                priority_level VARCHAR(255),
                user_acct VARCHAR(255),
                file_subdir VARCHAR(255),
                info VARCHAR(255)
            )
        """)
        connection.commit()
        print("Table created successfully")
    except mysql.connector.Error as err:
        print(f"Error: {err}")


def create_WARNING(connection):
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS LOG_WARNING (
                id INT AUTO_INCREMENT PRIMARY KEY,
                datetime DATETIME,
                priority_level VARCHAR(255),
                user_acct VARCHAR(255),
                file_subdir VARCHAR(255),
                warning VARCHAR(255)
            )
        """)
        connection.commit()
        print("Table created successfully")
    except mysql.connector.Error as err:
        print(f"Error: {err}")


def create_CRITICAL(connection):
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS LOG_CRITICAL (
                id INT AUTO_INCREMENT PRIMARY KEY,
                datetime DATETIME,
                priority_level VARCHAR(255),
                user_acct VARCHAR(255),
                file_subdir VARCHAR(255),
                critical VARCHAR(255)
            )
        """)
        connection.commit()
        print("Table created successfully")
    except mysql.connector.Error as err:
        print(f"Error: {err}")


def create_ERROR(connection):
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS LOG_ERROR (
                id INT AUTO_INCREMENT PRIMARY KEY,
                datetime DATETIME,
                priority_level VARCHAR(255),
                user_acct VARCHAR(255),
                file_subdir VARCHAR(255),
                error VARCHAR(255)
            )
        """)
        connection.commit()
        print("Table created successfully")
    except mysql.connector.Error as err:
        print(f"Error: {err}")


def create_table(connection):
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS my_table (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255),
                age INT,
                city VARCHAR(255)
            )
        """)
        connection.commit()
        print("Table created successfully")
    except mysql.connector.Error as err:
        print(f"Error: {err}")



# jkey=connect_to_JacenDB()
# create_INFO(jkey)
# create_WARNING(jkey)
# create_CRITICAL(jkey)
# create_ERROR(jkey)