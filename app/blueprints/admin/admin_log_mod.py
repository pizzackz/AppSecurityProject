import logging
import os
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
            CREATE TABLE IF NOT EXISTS INFO (
                id INT AUTO_INCREMENT PRIMARY KEY,
                datetime DATETIME,
                priority_level VARCHAR(255),
                user_acct VARCHAR(255),
                program_affected
                
            )
        """)
        connection.commit()
        print("Table created successfully")
    except mysql.connector.Error as err:
        print(f"Error: {err}")


# logging.basicConfig(level=logging.INFO, filename="db_main.log", filemode="a",
#                      format="%(asctime)s - %(levelname)s - %(message)s")
class LOG:
    def DB_log_setter(): 
        logging.basicConfig(level=logging.INFO, filename="db_main.log", filemode="a",
                            format="%(asctime)s \\\ %(levelname)s \\\ %(message)s")

    def T_log_setter():
        logging.basicConfig(level=logging.INFO, filename="t.log", filemode="a",
                            format="%(asctime)s \\\ %(levelname)s \\\ %(message)s")
        
    def acct_log_setter():
        logging.basicConfig(level=logging.INFO, filename="acct_base.log", filemode="a",
                            format="%(asctime)s \\\ %(levelname)s \\\ %(message)s") 
        

    def INFO(username, action, info):
        logging.info(f"{username}\\\{action}\\\{__file__}\\\{info}")

    def WARNING(username, action, warning):
        logging.warning(f"{username}\\\{action}\\\{__file__}\\\{warning}")

    def CRITICAL(username, action, risk):
        logging.critical(f"{username} \\\ {action} \\\ {__file__} \\\ {risk}")
    
    def SYS_ERROR(username, action, error):
        logging.error(f"{username} \\\ {action} \\\ {__file__} \\\ {error}")
    


L=LOG
# L.DB_log_setter()
# L.INFO('JOHN', 'RUN')
# connect_to_JacenDB()

# Example file path
file_path = '/path/to/your/directory/subdirectory/filename.ext'

# Get the file name
file_name = os.path.basename(file_path)

# Get the subdirectory (without the root directory)
subdirectory = os.path.dirname(file_path)
root_directory = '/path/to/your/directory'
if subdirectory.startswith(root_directory):
    subdirectory = subdirectory[len(root_directory):].lstrip(os.path.sep)

print(f"File Name: {file_name}")
print(f"Subdirectory: {subdirectory}")