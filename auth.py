from flask import Blueprint, request , jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import validators
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity


from models import User, db
from status_code import HTTP_400_BAD_REQUEST, HTTP_409_CONFLICT, HTTP_201_CREATED, HTTP_401_UNAUTHORIZED, HTTP_200_OK

auth = Blueprint('auth', __name__, url_prefix='/api/v1/auth')

@auth.post('/register')
def register():
	name = request.json['name']
	email = request.json['email']
	password = request.json['password']

	if len(password) < 6:
		return jsonify({'error':'Password is too short'}), HTTP_400_BAD_REQUEST

	if len(name) < 3:
		return jsonify({'error':'Name is too short'}), HTTP_400_BAD_REQUEST

	if not name.isalnum() or ' ' in name:
		return jsonify({'error':'Name should be alpanumeric, also no spaces'}), HTTP_400_BAD_REQUEST
	
	if not validators.email(email):
		return jsonify({'error':'Email is not valid'}), HTTP_400_BAD_REQUEST

	if User.query.filter_by(email=email).first() is not None:
		return jsonify({'error':'Email is taken'}), HTTP_409_CONFLICT
	
	if User.query.filter_by(name=name).first() is not None:
		return jsonify({'error':'Name is taken'}), HTTP_409_CONFLICT

	pwd_hash = generate_password_hash(password)

	user = User(name=name, email=email, password=pwd_hash)
	db.session.add(user)
	db.session.commit()

	return jsonify({'message': 'User created',
					'user': {'name': name, 'email': email}	}), HTTP_201_CREATED

@auth.post('/login')
def login():
	email  = request.json.get('email', '')
	password  = request.json.get('password', '')

	user = User.query.filter_by(email=email).first()

	if user:
		is_pass_correct = check_password_hash(user.password, password)

		if is_pass_correct:
			refresh = create_refresh_token(identity=user.id)
			access = create_access_token(identity=user.id)

			return jsonify({
				'user':{
					'refresh':refresh,
					'access':access,
					'username':user.name,
					'email':user.email

				}	
			}), HTTP_200_OK
	
	return jsonify({'error':'Wrong credentials'}), HTTP_401_UNAUTHORIZED

@auth.get('/me')
@jwt_required()
def me():
	user_id = get_jwt_identity()
	user = User.query.filter_by(id=user_id).first()

	return jsonify({
		'username': user.name,
		'email': user.email
	}), HTTP_200_OK

@auth.get('/token/refresh')
@jwt_required(refresh=True)
def refresh_users_token():
	identity = get_jwt_identity()
	access = create_access_token(identity=identity)

	return jsonify({
		'access':access,
	}), HTTP_200_OK
