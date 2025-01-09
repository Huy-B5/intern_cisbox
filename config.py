# config.py
from dotenv import load_dotenv
import os


# Configurations for file paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# File Paths for Excel Documents
EXCEL_PATH_SYSTEM_ACCOUNT = r'C:\Users\internship.dev\Documents\system_account.xlsx'
EXCEL_PATH_COMPANY_ACCOUNT = r'C:\Users\internship.dev\Documents\company_account.xlsx'


load_dotenv()
class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://dinhhuy1311:1234@localhost:3306/test_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = True
    HOST = "127.0.0.1"
    PORT = 8011





