import logging
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
        return none

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


# logging.basicConfig(level=logging.INFO, filename="db_main.log", filemode="a",
#                     format="%(asctime)s - %(levelname)s - %(message)s")
class LOG:
    global DB_log_setter
    global T_log_setter
    def DB_log_setter(): 
        logging.basicConfig(level=logging.INFO, filename="db_main.log", filemode="a",
                            format="%(asctime)s \\\ %(levelname)s \\\ %(message)s")

    def T_log_setter():
        logging.basicConfig(level=logging.INFO, filename="t.log", filemode="a",
                            format="%(asctime)s \\\ %(levelname)s \\\ %(message)s")
        
    def acct_log_setter():
        logging.basicConfig(level=logging.INFO, filename="acct_base.log", filemode="a",
                            format="%(asctime)s \\\ %(levelname)s \\\ %(message)s") 
        

    def INFO(username, action):
        logging.info(f"{username} \\\ {action} \\\ {__file__}")

    def WARNING(username, action):
        logging.warning(f"{username} \\\ {action} \\\ {__file__}")

    def CRITICAL(username, action, risk):
        logging.critical(f"{username} \\\ {action} \\\ {risk} \\\ {__file__}")
    
    def SYS_ERROR(username, action, error):
        logging.error(f"{username} \\\ {action} \\\ {error} \\\ {__file__}")
    


L=LOG
DB_log_setter
L.INFO('JOHN', 'RUN')
