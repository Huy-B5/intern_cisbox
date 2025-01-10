# controllers/account_api.py
import json
from datetime import datetime

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, get_jwt
from sqlalchemy import text
from models import User, TokenBlacklist
from services.auth_service import add_to_blacklist, \
    is_token_blacklisted, create_admin_user, register_user, update_user, delete_user, login_user_as_user, login_admin
from utils.common_utils import get_session

account_bp = Blueprint('account', __name__)


@account_bp.route('/check_connection', methods=['GET'])
def check_db_connection():
    try:
        session = next(get_session())
        session.execute(text('SELECT 1'))
        session.close()
        return "Database connection checked", 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@account_bp.route('/create_admin', methods=['POST'])
def create_admin():
    try:
        return create_admin_user()
    except Exception as e:
        return jsonify({'message': str(e)}), 400


@account_bp.route('/login_admin', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    company_no = data.get('company_no')

    if not username or not password or not company_no:
        return jsonify({'message': 'Username, password, and company_no are required'}), 400

    try:
        access_token, refresh_token = login_admin(username, password, company_no)

        if not access_token:
            return jsonify({"message": "Invalid credentials or you are not an admin for this company"}), 401

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'company_no': company_no
        }), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


# controllers/account_api.py
@account_bp.route('/login_user', methods=['POST'])
def login_user_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    company_no = data.get('company_no')

    if not username or not password or not company_no:
        return jsonify({'message': 'Username, password, and company_no are required'}), 400

    try:
        access_token, refresh_token,user_data = login_user_as_user(username, password, company_no)

        if not access_token:
            return jsonify({"message": "Invalid credentials or you are not a user for this company"}), 401

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user_data': user_data
        }), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500




@account_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_identity = get_jwt_identity()
    user_data = json.loads(user_identity)

    new_access_token = create_access_token(identity=user_identity)
    return jsonify(access_token=new_access_token), 200
@account_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jwt_claims = get_jwt()
        current_user_id = get_jwt_identity()

        print(f"Current user ID: {current_user_id}")
        print(f"JWT Claims: {jwt_claims}")

        if not jwt_claims:
            return jsonify({'message': 'Token is invalid or expired.'}), 400

        if 'role' not in jwt_claims:
            return jsonify({'message': 'Role is missing in the token data.'}), 400

        if jwt_claims.get('role') == 'admin':
            return jsonify({'message': 'Admin logged out successfully'}), 200

        add_to_blacklist()

        return jsonify({'message': 'Logged out successfully, token blacklisted.'}), 200
    except Exception as e:
        print(f"Error during logout: {str(e)}")
        return jsonify({'message': 'Error logging out', 'error': str(e)}), 500



@account_bp.route('/protected', methods=['POST'])
@jwt_required()
def protected():
    jwt_payload = get_jwt()
    jti = jwt_payload["jti"]
    if is_token_blacklisted(jti):
        return jsonify({"message": "Token has been revoked."}), 401

    return jsonify({"message": "You have access!"}), 200


def check_if_token_revoked(jwt_payload):
    jti = jwt_payload["jti"]
    return is_token_blacklisted(jti)

@account_bp.route('/admin', methods=['GET'])
@jwt_required()
def admin():
    # Check the role of the current user
    current_user = get_jwt_identity()
    if current_user.get('role') == 'admin':
        return jsonify(message="Welcome Admin!"), 200
    else:
        return jsonify(message="Permission denied."), 403

@account_bp.route('/user', methods=['POST'])
@jwt_required()  # Ensure JWT is required to access this route
def create_user():
    # Get the user ID (identity) from the JWT token
    current_user_id = get_jwt_identity()  # This is the user ID (as a string)
    # Fetch user data based on the user ID from the database
    session = next(get_session())
    user = session.query(User).filter_by(id=current_user_id).first()

    # Check if the current user is an admin
    if not user or user.role != 'admin':
        return jsonify({'message': 'Permission denied. Admins only.'}), 403

    admin_company_no = user.company_no  # Get the admin's company number

    # Get the data from the request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    company_no = data.get('company_no')

    # Validate input
    if not username or not password or not company_no:
        return jsonify({'message': 'Username, password, and company_no are required'}), 400

    # Ensure admins can only create users within their company
    if admin_company_no != company_no:
        return jsonify({'message': 'Admins can only create users within their own company.'}), 403

    # Call the function to register the user
    return register_user(username, password, company_no, role='user')

@account_bp.route('/user/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user_route(user_id):
    current_user = get_jwt_identity()
    if isinstance(current_user, dict) and current_user.get('role') != 'admin':
        return jsonify({'message': 'Permission denied. Admins only.'}), 403

    data = request.get_json()
    return update_user(user_id, data)

@account_bp.route('/user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user_route(user_id):
    current_user = get_jwt_identity()
    if isinstance(current_user, dict) and current_user.get('role') != 'admin':
        return jsonify({'message': 'Permission denied. Admins only.'}), 403

    return delete_user(user_id)


