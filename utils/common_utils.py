from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base


DATABASE_URL = "mysql+pymysql://dinhhuy1311:1234@localhost:3306/test_db"

engine = create_engine(DATABASE_URL, echo=True)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_connection():
    try:
        with engine.connect() as connection:
            result = connection.execute("SELECT 1")
            print("Connection successful:", result.fetchall())
    except Exception as e:
        print("Error connecting to database:", str(e))
