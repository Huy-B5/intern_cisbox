from datetime import datetime

from flask import jsonify
from flask import request
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, Company, TokenBlacklist
from utils.common_utils import get_session



def create_admin_user():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    company_no = request.json.get('company_no', None)
    role = 'admin'

    if not username or not password or not company_no:
        return jsonify({'message': 'Username, password, and company_no are required'}), 400

    hashed_password = generate_password_hash(password)

    session = next(get_session())
    try:
        company = session.query(Company).filter_by(company_no=company_no).one_or_none()
        if company is None:
            company = Company(company_no=company_no, name=f"Company {company_no}")
            session.add(company)
            session.commit()

        existing_admin = session.query(User).filter_by(role="admin", company_no=company_no).first()
        if existing_admin:
            return jsonify({'message': f'Admin already exists for company {company_no}.'}), 400

        admin_user = User(username=username, password_hash=hashed_password, company_no=company_no, role=role)
        session.add(admin_user)
        session.commit()

        return jsonify({'message': 'Admin user created successfully'}), 201
    except Exception as e:
        session.rollback()
        return jsonify({'message': str(e)}), 400
    finally:
        session.close()


def register_user(username, password, company_no, role='user'):
    if role not in ['user', 'admin']:
        return jsonify({'message': 'Role must be either "user" or "admin"'}), 400

    hashed_password = generate_password_hash(password)
    session = next(get_session())
    try:
        # Check if the company exists
        company = session.query(Company).filter_by(company_no=company_no).one_or_none()
        if company is None:
            return jsonify({'message': f'Company with number {company_no} does not exist'}), 404

        new_user = User(username=username, password_hash=hashed_password, company_no=company_no, role=role)
        session.add(new_user)
        session.commit()

        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        session.rollback()
        return jsonify({'message': str(e)}), 400
    finally:
        session.close()


def login_user(username, password, company_no):
    session = next(get_session())
    try:
        user = session.query(User).filter_by(username=username, company_no=company_no).first()

        if user and check_password_hash(user.password_hash, password):
            if user.role == 'admin':
                access_token, refresh_token = create_token(user)
                return access_token, refresh_token
            else:
                return None, None
        return None, None

    finally:
        session.close()


def get_all_users():
    session = next(get_session())
    try:
        users = session.query(User).all()
        return jsonify([{
            'id': user.id,
            'username': user.username,
            'company_no': user.company_no,
            'role': user.role
        } for user in users]), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 400
    finally:
        session.close()


def update_user(user_id, data):
    username = data.get('username')
    password = data.get('password')
    company_no = data.get('company_no')
    role = data.get('role')

    session = next(get_session())
    try:
        user = session.query(User).filter_by(id=user_id).one_or_none()
        if user:
            if username:
                user.username = username
            if password:
                user.password_hash = generate_password_hash(password)
            if company_no:
                user.company_no = company_no
            if role:
                user.role = role
            session.commit()
            return jsonify({'message': 'User updated successfully'}), 200
        return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        session.rollback()
        return jsonify({'message': str(e)}), 400
    finally:
        session.close()

def delete_user(user_id):
    session = next(get_session())
    try:
        user = session.query(User).filter_by(id=user_id).one_or_none()
        if user:
            session.delete(user)
            session.commit()
            return jsonify({'message': 'User deleted successfully'}), 200
        return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        session.rollback()
        return jsonify({'message': str(e)}), 400
    finally:
        session.close()

def create_token(user):
    access_token = create_access_token(identity={
        "id": str(user.id),
        "username": str(user.username),
        "role": str(user.role),
        "company_no": str(user.company_no)
    })
    refresh_token = create_refresh_token(identity={"id": str(user.id)})
    return access_token, refresh_token



#blacklisted_tokens = set()

def add_to_blacklist():
    current_user = get_jwt_identity()

    if not isinstance(current_user, dict) or 'role' not in current_user or 'username' not in current_user:
        raise ValueError('Invalid token data.')

    if current_user.get('role') == 'admin':
        return

    jti = get_jwt()["jti"]
    session = next(get_session())
    try:
        token_entry = TokenBlacklist(jti=jti, created_at=datetime.utcnow())
        session.add(token_entry)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

# Function to check if a token is blacklisted in the database
def is_token_blacklisted(jti):
    session = next(get_session())
    try:
        # Query the database to see if the token exists in the blacklist
        token = session.query(TokenBlacklist).filter_by(jti=jti).first()
        return token is not None
    finally:
        session.close()


def refresh_token(current_user):
    access_token = create_access_token(identity=current_user)
    return access_token


