import random

import pandas as pd
from flask_bcrypt import generate_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import EXCEL_PATH_SYSTEM_ACCOUNT, EXCEL_PATH_COMPANY_ACCOUNT
from models import SystemAccount, CompanyAccount, Company, User

DATABASE_URL = "mysql+pymysql://dinhhuy1311:1234@localhost:3306/test_db"
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_all_records(account_type):
    try:
        if account_type == 'system':
            df = pd.read_excel(EXCEL_PATH_SYSTEM_ACCOUNT)
        elif account_type == 'company':
            df = pd.read_excel(EXCEL_PATH_COMPANY_ACCOUNT)
        else:
            raise ValueError("Invalid account type.")
        return df
    except Exception as e:
        raise Exception(f"Error while getting records: {str(e)}")


# Function to insert data into the SystemAccount table
def insert_system_accounts(system_df):
    with SessionLocal() as session:
        for _, record in system_df.iterrows():
            parent_account_id = None if pd.isna(record.get('parent_account_id')) else int(
                record.get('parent_account_id'))
            parent_account_no = None if pd.isna(record.get('parent_account_no')) else int(
                record.get('parent_account_no'))
            system_account = SystemAccount(
                account_no=str(record['account_no']),
                account_name_de=record.get('account_name_de', None),
                account_name_vn=record.get('account_name_vn', None),
                parent_account_id=parent_account_id,
                parent_account_no=parent_account_no,
                is_default=True if record['is_default'] == 1 else False
            )
            session.add(system_account)
        session.commit()


# Function to insert data into the CompanyAccount table
def insert_company_accounts(company_df):
    with SessionLocal() as session:
        for _, record in company_df.iterrows():
            account_name_vn = record['account_name_vn'] if pd.notna(record['account_name_vn']) else 'No Vietnamese Name'

            system_account_ref = None if pd.isna(record.get('system_account_ref')) else record.get('system_account_ref')
            total_item = None if pd.isna(record.get('total_item')) else record.get('total_item')
            last_allocation = None if pd.isna(record.get('last_allocation')) else record.get('last_allocation')
            company_no = None if pd.isna(record.get('company_no')) else record.get('company_no')
            company_account = CompanyAccount(
                company_no=company_no,
                account_no=record.get('account_no', None),
                account_name=record.get('account_name', None),
                account_name_vn=account_name_vn,
                system_account_ref=system_account_ref,
                total_item=total_item,
                last_allocation=last_allocation,
                status=record.get('status', 0),
                active=record.get('active', 1),
            )
            session.add(company_account)
        session.commit()


# Function to insert 3 companies and 10 users
def insert_companies_and_users():
    with SessionLocal() as session:
        # Create 3 new companies
        for i in range(1, 4):
            company = Company(company_name=f"Company {i}", company_no=f"COMPANY_{i}")
            session.add(company)
        session.commit()

        # Create 10 users and assign them random companies
        company_no_values = session.query(Company.company_no).all()
        company_no_values = [company[0] for company in company_no_values]

        for i in range(1, 11):
            company_no = random.choice(company_no_values)

            # Generate a hashed password
            password = f"user{i}password"  # You can customize the password logic as needed
            hashed_password = generate_password_hash(password)

            user = User(
                username=f"user{i}",
                company_no=company_no,
                password_hash=hashed_password,  # Store the hashed password
                role="user"
            )
            session.add(user)
        session.commit()

        print("Inserted 3 companies and 10 users with hashed passwords.")


# Main function to insert all data
def insert_companies():
    try:
        # Load the company account data from the Excel file
        company_df = pd.read_excel(EXCEL_PATH_COMPANY_ACCOUNT)

        if 'company_no' not in company_df.columns:
            raise ValueError("Column 'company_no' does not exist in the Excel file.")

        # Clean data: Remove any rows with NaN in the 'company_no' column
        company_df = company_df[company_df['company_no'].notna()]
        print(f"Total records in company file: {len(company_df)}")

        # Extract all company_no values (including duplicates) from the DataFrame
        company_no_values = company_df['company_no'].astype(str).str.strip().tolist()
        print(f"Extracted company_no values: {company_no_values}")

        with SessionLocal() as session:
            # Retrieve all existing company_no values from the Company table
            existing_company_nos = {company.company_no for company in session.query(Company).all()}

            new_companies = []
            for company_no in company_no_values:
                company_no = str(company_no).strip()  # Ensure correct formatting
                if company_no not in existing_company_nos:
                    # Add to the list of new companies if not already present in the table
                    new_companies.append(Company(company_name=f"Company {company_no}", company_no=company_no))
                    existing_company_nos.add(company_no)  # Add to the set to prevent future duplicates

            if new_companies:
                session.bulk_save_objects(new_companies)
                session.commit()
                print(f"Inserted {len(new_companies)} new company_no values into the Company table.")
            else:
                print("No new company_no values to insert.")
    except Exception as e:
        print(f"Error inserting company_no into Company table: {str(e)}")


def insert_data_from_excel():
    try:
        # Read data from the Excel files
        system_df = get_all_records('system')
        company_df = get_all_records('company')

        print(f"Total records in system file: {len(system_df)}")
        print(f"Total records in company file: {len(company_df)}")


        # Insert data into the SystemAccount table
        insert_system_accounts(system_df)

        # Insert data into the Company table
        insert_companies()


        # Insert data into the CompanyAccount table
        insert_company_accounts(company_df)

        # Insert all company_no into the Company table

        # Create 10 users
        insert_companies_and_users()

    except Exception as e:
        print(f"Error inserting data into database: {str(e)}")


# Function to check data in the database
def check_data_in_db():
    with SessionLocal() as session:
        result_system = session.execute("SELECT * FROM system_account LIMIT 10").fetchall()
        result_company = session.execute("SELECT * FROM company_account LIMIT 10").fetchall()

        print("System Account Data:")
        for row in result_system:
            print(row)

        print("\nCompany Account Data:")
        for row in result_company:
            print(row)


# Main entry point to run
if __name__ == "__main__":
    try:
        # Insert data into the database
        insert_data_from_excel()
        # Check data if needed
        # check_data_in_db()
    except Exception as e:
        print(f"An error occurred: {str(e)}")
