from flask import request
from flask_restful import Resource,reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from models import db, User, Product, bcrypt

class UserRegistrationResource(Resource):
    def post(self):
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return {"error": "Username and password are required."}, 400

            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                return {"error": "Username is already taken."}, 400

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return {"message": "User registered successfully."}, 201
        except Exception as e:
            return {"error": str(e)}, 500

class UserLoginResource(Resource):
   def post(self):
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                access_token = create_access_token(identity=username)
                refresh_token = create_refresh_token(identity=username)
                return {"access_token": access_token, "refresh_token": refresh_token}, 200
            else:
                return {"error": "Invalid username or password."}, 401
        except Exception as e:
            return {"error": str(e)}, 500

class ProductResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('name', type=str, required=True, help='Name cannot be blank')
    parser.add_argument('quantity', type=int, required=True, help='Quantity cannot be blank')
    parser.add_argument('price', type=float, required=True, help='Price cannot be blank')
    @jwt_required()
    def get(self, product_id=None):
        if product_id is None:
            products = Product.query.all()
            return [{"id": product.id, "name": product.name, "quantity": product.quantity, "price": product.price} for product in products]

        product = Product.query.get(product_id)
        if not product:
            return {"message": "Product not found."}, 404

        return {
            "id": product.id,
            "name": product.name,
            "quantity": product.quantity,
            "price": product.price
        }

    @jwt_required()
    def post(self):
        try:
            current_user = User.query.filter_by(username=get_jwt_identity()).first()
            if current_user.role != 'admin':
                return {"error": "Access denied. Admins only."}, 403

            data = request.get_json()
            new_product = Product(name=data['name'], quantity=data['quantity'], price=data['price'])
            db.session.add(new_product)
            db.session.commit()

            # Return the details of the created product
            return {
                "message": "Product added successfully.",
                "product": {
                    "id": new_product.id,
                    "name": new_product.name,
                    "quantity": new_product.quantity,
                    "price": new_product.price
                }
            }
        except Exception as e:
            return {"error": str(e.message)}, 500

class AdminProductResource(Resource):
    @jwt_required()
    def post(self):
        try:
            current_user = User.query.filter_by(username=get_jwt_identity()).first()
            if current_user.role != 'admin':
                return {"error": "Access denied. Admins only."}, 403

            data = request.get_json()
            new_product = Product(name=data['name'], quantity=data['quantity'], price=data['price'])
            db.session.add(new_product)
            db.session.commit()

            # Return the details of the created product
            return {
                "message": "Product added successfully.",
                "product": {
                    "id": new_product.id,
                    "name": new_product.name,
                    "quantity": new_product.quantity,
                    "price": new_product.price
                }
            }
        except Exception as e:
            return {"error": str(e.message)}, 500

    @jwt_required()
    def put(self, product_id):
        try:
            current_user = User.query.filter_by(username=get_jwt_identity()).first()
            if current_user.role != 'admin':
                return {"message": "Access denied. Admins only."}, 403

            product = Product.query.get(product_id)
            if not product:
                return {"message": "Product not found."}, 404

            data = request.get_json()
            product.name = data['name']
            product.quantity = data['quantity']
            product.price = data['price']
            db.session.commit()

            # Return the details of the updated product
            return {
                "message": "Product updated successfully.",
                "product": {
                    "id": product.id,
                    "name": product.name,
                    "quantity": product.quantity,
                    "price": product.price
                }
            }
        except Exception as e:
            return {"error": str(e.message)}, 500

    @jwt_required()
    def delete(self, product_id):
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if current_user.role != 'admin':
            return {"message": "Access denied. Admins only."}, 403

        product = Product.query.get(product_id)
        if not product:
            return {"message": "Product not found."}, 404

        db.session.delete(product)
        db.session.commit()
        return {"message": "Product deleted successfully."}

class RefreshTokenResource(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {"access_token": access_token}, 200
class UserResource(Resource):
    @jwt_required()
    def get(self):
        try:
            current_user = get_jwt_identity()
            user = User.query.filter_by(username=current_user).first()

            if user:
                return {
                    "id": user.id,
                    "username": user.username,
                    "role": user.role,
                }, 200
            else:
                return {"message": "User not found."}, 404
        except Exception as e:
            return {"error": str(e)}, 500