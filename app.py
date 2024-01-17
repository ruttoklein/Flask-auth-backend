from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager
from models import db, bcrypt
from flask_cors import CORS
from resources import (
    ProductResource,
    AdminProductResource,
    UserRegistrationResource,
    UserLoginResource,
    RefreshTokenResource,
    UserResource
)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies'] 
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable CSRF protection for cookies
app.config['JWT_COOKIE_SECURE'] = False  # Set to True in a production environment with HTTPS
app.config['JWT_REFRESH_COOKIE_PATH'] = '/refresh'  
app.config['JWT_REFRESH_COOKIE_SECURE'] = False  # Set to True in a production environment with HTTPS
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = False  # Use False to make refresh tokens never expire

api = Api(app)
jwt = JWTManager(app)

db.init_app(app)
bcrypt.init_app(app)
CORS(app)

with app.app_context():
    db.create_all()

api.add_resource(UserRegistrationResource, '/register')
api.add_resource(UserLoginResource, '/login')
api.add_resource(RefreshTokenResource, '/refresh')
api.add_resource(ProductResource, '/products', '/products/<int:product_id>')
api.add_resource(AdminProductResource, '/products/<int:product_id>')
api.add_resource(UserResource, '/user')

if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)
