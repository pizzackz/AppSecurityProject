import logging

# logging.basicConfig(level=logging.INFO, filename="db_main.log", filemode="a",
#                     format="%(asctime)s - %(levelname)s - %(message)s")
class LOG:
    global DB_log_setter
    global T_log_setter
    def DB_log_setter(): 
        logging.basicConfig(level=logging.INFO, filename="db_main.log", filemode="a",
                            format="%(asctime)s - %(levelname)s - %(message)s")

    def T_log_setter():
        logging.basicConfig(level=logging.INFO, filename="t.log", filemode="a",
                            format="%(asctime)s - %(levelname)s - %(message)s")
        
    def acct_log_setter():
        logging.basicConfig(level=logging.INFO, filename="acct_base.log", filemode="a",
                            format="%(asctime)s - %(levelname)s - %(message)s") 
        

    def INFO(username, action):
        logging.info(f"{username}, {action}, {__file__}")

    def WARNING(username, action):
        logging.warning(f"{username}, {action}, {__file__}")

    def CRITICAL(username, action, risk):
        logging.critical(f"{username}, {action}, {risk}, {__file__}")
    
    def ERROR(username, action, error):
        logging.error(f"{username}, {action}, {error}, {__file__}")
    


DB_log_setter()
logging.warning("helloawd")
