from flask import Flask, jsonify, redirect
from auth import auth
from bookmarks import bookmarks
from flask_jwt_extended import JWTManager


from models import db, User, Bookmark
from status_code import HTTP_400_BAD_REQUEST, HTTP_409_CONFLICT, HTTP_201_CREATED, HTTP_404_NOT_FOUND , HTTP_200_OK, HTTP_204_NO_CONTENT


app = Flask(__name__)
app.config['SECRET_KEY'] = '73870e7f-634d-433b-946a-8d20132bafac'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'JWT_SECRET_KEY'

app.register_blueprint(auth)
app.register_blueprint(bookmarks)


db.init_app(app)
JWTManager(app)



@app.get('/')
def index():
	return 'Hello world'

@app.get('/<short_url>')
def redirect_to_url(short_url):
	bookmark = Bookmark.query.filter_by(short_url=short_url).first_or_404()

	if bookmark:
		bookmark.visits = bookmark.visits + 1
		db.session.commit()

		return redirect(bookmark.url)

@app.errorhandler(HTTP_404_NOT_FOUND)
def handle_404(e):
	return jsonify({'error':'Not Found'}), HTTP_404_NOT_FOUND


@app.get('/hello')
def say_hello():
	return jsonify({'message':'Hello world'})

if __name__ == '__main__':
	app.run(debug=True)