import mysql.connector
mydb = mysql.connector.connect(
    host='localhost',
    user='root',
    passwd='123password'
)
print(mydb)