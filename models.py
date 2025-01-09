from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Enum, ForeignKey
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship
from extensions import db

DATABASE_URL = "mysql+pymysql://dinhhuy1311:1234@localhost:3306/test_db"

engine = create_engine(DATABASE_URL, echo=True)

Base = declarative_base()
class Company(Base):
    __tablename__ = 'Company'

    id = Column(Integer, primary_key=True, autoincrement=True)
    company_name = Column(String(255), nullable=False)
    company_no = Column(String(50), nullable=False, unique=True)  # Make company_no unique
    address = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Company {self.company_name}>"

class User(Base):
    __tablename__ = 'User'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False, unique=True)
    company_no = Column(String(50), ForeignKey('Company.company_no'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum('user', 'admin', name='user_roles'), default='user')

    company = relationship('Company', backref='users')  # Add relationship for easier access

    def __repr__(self):
        return f"<User {self.username}, Role: {self.role}>"




class CompanyAccount(Base):
    __tablename__ = 'company_account'

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    company_no = Column(String(50), nullable=False)
    account_no = Column(String(50), nullable=False)
    account_name = Column(String(255), nullable=True)
    account_name_vn = Column(String(255), nullable=False)
    system_account_ref = Column(Integer, ForeignKey('system_account.id'))
    total_item = Column(Integer)
    last_allocation = Column(DateTime)
    status = Column(Boolean, default=True)
    active = Column(Boolean, default=True)

class SystemAccount(Base):
    __tablename__ = 'system_account'

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    account_no = Column(String(50), nullable=False)
    account_name_de = Column(String(255))
    account_name_vn = Column(String(255))
    parent_account_id = Column(Integer, nullable=True)
    parent_account_no = Column(String(50))
    is_default = Column(Boolean, default=False)

    # Quan hệ với bảng 'CompanyAccount' nếu cần
    company_accounts = relationship("CompanyAccount", backref="system_account")

class TokenBlacklist(Base):
    __tablename__ = 'token_blacklist'

    id = Column(Integer, primary_key=True, autoincrement=True)
    jti = Column(String(120), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Token {self.jti}>"

def create_tables():

    try:
        Base.metadata.drop_all(engine)  # Xóa toàn bộ bảng
        print("Tables dropped successfully.")
        Base.metadata.create_all(engine)  # Tạo lại bảng
        print("Tables created successfully.")
    except Exception as e:
        print("Error creating tables:", str(e))


# Hàm chính
if __name__ == "__main__":
    create_tables()


