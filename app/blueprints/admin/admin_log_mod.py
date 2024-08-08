import logging
import os
import threading
from app import db

def general_log_setter(): 
    logging.basicConfig(level=logging.INFO, filename="general.log", filemode="a",
                        format="%(asctime)s||%(message)s")
def transaction_log_setter():
    logging.basicConfig(level=logging.INFO, filename="transaction.log", filemode="a",
                        format="%(asctime)s||%(message)s")
    
def account_log_setter():
    logging.basicConfig(level=logging.INFO, filename="account.log", filemode="a",
                        format="%(asctime)s||%(message)s") 
    

# def log_trans(self, priority_level, category, username, action, info):
#     file_name = os.path.basename(__file__)
#     # Get the subdirectory (without the root directory)
#     subdirectory = os.path.dirname(file_path)
#     root_directory = '/path/to/your/directory'
#     if subdirectory.startswith(root_directory):
#         subdirectory = subdirectory[len(root_directory):].lstrip(os.path.sep)
#     if priority_level=='info':
#         if category=='general':
#             self.general_log_setter()
#             logging.info(f"Info||General||{username}||{subdirectory}\\{file_name}||{action}||{info}")
#         elif category=='transaction':
#             self.transaction_log_setter()
#             logging.info(f"Info||Transaction||{username}||{subdirectory}\\{file_name}||{action}||{info}")
#         elif category=='account':
#             self.account_log_setter()
#             logging.info(f"Info||Account||{username}||{subdirectory}\\{file_name}||{action}||{info}")

def log_trans(priority_level, category, user_id, action, info):
    file_name = os.path.basename(__file__)
    # Get the subdirectory (without the root directory)
    subdirectory = os.path.dirname(file_path)
    root_directory = '/path/to/your/directory'
    if subdirectory.startswith(root_directory):
        subdirectory = subdirectory[len(root_directory):].lstrip(os.path.sep)
    if category=='general':
        new_log=General(priority_level=priority_level, category=category, user=user_id, action=action, message_info=info)
    elif category=='transaction':
        new_log=Transaction(priority_level=priority_level, category=category, user=user_id, action=action, message_info=info)
    elif category=='account':
        new_log=Account(priority_level=priority_level, category=category, user=user_id, action=action, message_info=info)
    else:
        print("Error! category can only be: \'general\', \'transactions\' or \'account\'")
    
    try:
        db.session.add(new_log)
        db.session.commit()
    except:
        return 'empty'


L=LOG
# L.DB_log_setter()
# L.INFO('JOHN', 'RUN')
# connect_to_JacenDB()

# Example file path
file_path = '/path/to/your/directory/subdirectory/filename.ext'

# Get the file name
file_name = os.path.basename(__file__)

# Get the subdirectory (without the root directory)
subdirectory = os.path.dirname(file_path)
root_directory = '/path/to/your/directory'
if subdirectory.startswith(root_directory):
    subdirectory = subdirectory[len(root_directory):].lstrip(os.path.sep)

print(f"File Name: {file_name}")
print(f"Subdirectory: {subdirectory}")