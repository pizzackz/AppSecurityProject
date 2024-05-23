import pymysql

"""
This is for initialising all the databases in the MySQL server
To be executed when mySQL server starts
"""

mydb = pymysql.connect(
    host='localhost',
    user='root',
    password='password123'
)

my_cursor = mydb.cursor()
my_cursor.execute("CREATE DATABASE recipes_db")



