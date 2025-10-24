from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from App.controllers import (
    create_internship_position, get_position_id, get_all_positions,
    get_positions_by_employer, update_position_title, update_position_description,
    update_position_requirements, delete_position
)

api_internship_views = Blueprint('api_internship_views', __name__, url_prefix='/api/internships')

@api_internship_views.route('/', methods=['GET'])
@jwt_required()
def list_positions():
    return jsonify([p.get_json() for p in get_all_positions()])

@api_internship_views.route('/<int:position_id>', methods=['GET'])
@jwt_required()
def get_position(position_id):
    position = get_position_id(position_id)
    if not position:
        return jsonify({'error': 'Position not found'}), 404
    return jsonify(position.get_json())

@api_internship_views.route('/create', methods=['POST'])
def create_position():
    data = request.json
    position = create_internship_position(
        data['employer_id'], data['title'], data['description'], data['requirements']
    )
    return jsonify({
        'message': f"Position '{position.title}' created", 
        'id': position.id,
        'title': position.title,
        'employer_id': position.employer_id,
        'description': position.description,
        'requirements': position.requirements
    }), 201

""" @api_internship_views.route('/create', methods=['POST'])
def create_position():
    data = request.json
    position = create_internship_position(
        data['employer_id'], data['title'], data['description'], data['requirements']
    )
    return jsonify({'message': f"Position '{position.title}' created", 'id': position.id}), 201
 """
@api_internship_views.route('/<int:position_id>', methods=['PUT'])
@jwt_required()
def update_position(position_id):
    data = request.json
    if 'title' in data:
        update_position_title(position_id, data['title'])
    if 'description' in data:
        update_position_description(position_id, data['description'])
    if 'requirements' in data:
        update_position_requirements(position_id, data['requirements'])
    return jsonify({'message': 'Position updated'})

@api_internship_views.route('/<int:position_id>', methods=['DELETE'])
@jwt_required()
def delete_position_api(position_id):
    delete_position(position_id)
    return jsonify({'message': 'Position deleted'})
