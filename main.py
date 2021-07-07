from datetime import datetime, timedelta
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required
from flask_jwt_extended import create_access_token, create_refresh_token
from flask_jwt_extended import current_user
from flask_pydantic import validate
from pydantic import BaseModel, EmailStr, validator


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/marketplace'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer(), primary_key=True)
    first_name = db.Column(db.String(length=80), nullable=False)
    last_name = db.Column(db.String(length=80), nullable=False)
    email = db.Column(db.String(length=255), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=255), nullable=False)
    addresses = db.relationship(
        'Address', secondary="user_addresses", lazy=True)
    orders = db.relationship('Order', lazy=True)

    def __init__(self, name: str, email: str, password: str):
        [self.first_name, self.last_name] = name.rsplit(" ", 1)
        self.password_hash = self.hash_password(password)
        self.email = email

    def __repr__(self) -> str:
        return f"{self.first_name} {self.last_name}"

    def hash_password(self, password: str):
        return "fakehash" + password

    def check_password(self, password: str):
        return self.hash_password(password) == self.password_hash


class UserAddress(db.Model):
    __tablename__ = "user_addresses"

    address_id = db.Column(db.Integer(), db.ForeignKey(
        'addresses.id'), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))


class Address(db.Model):
    __tablename__ = "addresses"

    id = db.Column(db.Integer(), primary_key=True)
    street1 = db.Column(db.String(length=120), nullable=False)
    street2 = db.Column(db.String(length=120))
    street3 = db.Column(db.String(length=120))
    district = db.Column(db.String(length=120), nullable=False)
    city = db.Column(db.String(length=120), nullable=False)
    country = db.Column(db.String(length=120), nullable=False)
    postal_code = db.Column(db.String(length=16), nullable=False)


class Shop(db.Model):
    __tablename__ = "shops"

    id = db.Column(db.Integer(), primary_key=True)
    address_id = db.Column(db.Integer(), db.ForeignKey('addresses.id'))
    name = db.Column(db.String(length=255), nullable=False)
    about = db.Column(db.Text())
    contact_email = db.Column(db.String(length=255),
                              nullable=False, unique=True)
    username = db.Column(db.String(length=255), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=255), nullable=False)
    address = db.relationship('Address', lazy=True)

    def __repr__(self) -> str:
        return self.name


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer(), primary_key=True)
    shop_id = db.Column(db.Integer(), db.ForeignKey('shops.id'))
    name = db.Column(db.String(length=255), nullable=False)
    description = db.Column(db.Text(), nullable=False)
    images = db.relationship('ProductImage', lazy=True)

    def __repr__(self) -> str:
        return self.name


class ProductImage(db.Model):
    __tablename__ = "product_images"

    id = db.Column(db.String(length=255), primary_key=True)
    product_id = db.Column(db.Integer(), db.ForeignKey('products.id'))


class Order(db.Model):
    __tablename__ = "orders"

    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime(), nullable=False, default=datetime.now)
    products = db.relationship(
        'Product', secondary="product_orders", lazy=True)


class ProductOrder(db.Model):
    __tablename__ = "product_orders"

    id = db.Column(db.Integer(), primary_key=True)
    order_id = db.Column(db.Integer(), db.ForeignKey('orders.id'))
    product_id = db.Column(db.Integer(), db.ForeignKey('products.id'))


app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


API_ROUTE = "api/v1"


class ErrorResponse(BaseModel):
    msg: str


AUTH_ROUTE = "auth"


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

    @validator('name')
    def name_must_contain_space(cls, name):
        if ' ' not in name:
            raise ValueError('should be full name')
        return name.title()


class ProfileResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str


class RefreshTokenResponse(BaseModel):
    access_token: str


@app.post(f"/{API_ROUTE}/{AUTH_ROUTE}/register")
@validate()
def auth_register(body: RegisterRequest):
    user_exist = User.query.filter_by(email=body.email).one_or_none()
    if user_exist:
        return ErrorResponse(msg="User already exists!"), 400

    user = User(body.name, body.email, body.password)
    db.session.add(user)
    db.session.commit()

    return ProfileResponse(
        id=user.id,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email), 201


@app.post(f"/{API_ROUTE}/{AUTH_ROUTE}/login")
@validate()
def auth_login(body: LoginRequest):
    user = User.query.filter_by(email=body.email).one_or_none()

    if user and user.check_password(body.password):
        access = create_access_token(identity=user)
        refresh = create_refresh_token(identity=user)
        return LoginResponse(access_token=access, refresh_token=refresh)

    return ErrorResponse(msg="Email or password is not correct!"), 400


@app.post(f"/{API_ROUTE}/{AUTH_ROUTE}/refresh_token")
@jwt_required(refresh=True)
def auth_refresh_token():
    access = create_access_token(identity=current_user)
    return RefreshTokenResponse(access_token=access)


@app.get(f"/{API_ROUTE}/{AUTH_ROUTE}/profile")
@jwt_required()
def auth_profile():
    return ProfileResponse(
        id=current_user.id,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        email=current_user.email
    )


if __name__ == "__main__":
    app.run(port=8080, debug=True)
