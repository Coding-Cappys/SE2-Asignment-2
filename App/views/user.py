from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from App.controllers import (
    create_student, create_staff, create_employer,
    get_all_users_json, get_user, update_username, update_firstname,
    update_lastname, update_password, delete_user
)

api_user_views = Blueprint('api_user_views', __name__, url_prefix='/api/users')

@api_user_views.route('/all_users', methods=['GET'])
@jwt_required()
def list_users():
    return jsonify(get_all_users_json())

@api_user_views.route('/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_detail(user_id):
    user = get_user(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user.get_json())

@api_user_views.route('/', methods=['POST'])
def create_user():
    data = request.json
    role = data.get('role')
    if role == 'student':
        user = create_student(data['username'], data['password'], data['first_name'], data['last_name'], data.get('major', 'Undeclared'))
    elif role == 'staff':
        user = create_staff(data['username'], data['password'], data['first_name'], data['last_name'], data.get('position', 'Staff'))
    elif role == 'employer':
        user = create_employer(data['username'], data['password'], data['first_name'], data['last_name'], data.get('company', 'Tech Corp'))
    else:
        return jsonify({'error': 'Invalid role'}), 400
    return jsonify({'message': f"{role.capitalize()} user created"}), 201

@api_user_views.route('/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user_api(user_id):
    data = request.json
    if 'username' in data:
        update_username(user_id, data['username'])
    if 'first_name' in data:
        update_firstname(user_id, data['first_name'])
    if 'last_name' in data:
        update_lastname(user_id, data['last_name'])
    if 'password' in data:
        update_password(user_id, data['password'])
    return jsonify({'message': 'User updated'})

@api_user_views.route('/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user_api(user_id):
    if delete_user(user_id):
        return jsonify({'message': 'User deleted'})
    return jsonify({'error': 'User not found'}), 404