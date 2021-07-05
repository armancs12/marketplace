from datetime import datetime
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy

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
  
  addresses = db.relationship('Address', secondary="UserAddress", lazy=True)
  orders = db.relationship('Order', lazy=True)

  def __repr__(self) -> str:
      return f"{self.first_name} {self.last_name}"


class UserAddress(db.Model):
  __tablename__ = "user_addresses"
  
  address_id = db.Column(db.Integer(), db.ForeignKey('addresses.id'), primary_key=True)
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
  contact_email = db.Column(db.String(length=255), nullable=False, unique=True)
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

  products = db.relationship('Product', secondary="ProductOrder", lazy=True)


class ProductOrder(db.Model):
  __tablename__ = "product_orders"
  
  id = db.Column(db.Integer(), primary_key=True)
  order_id = db.Column(db.Integer(), db.ForeignKey('orders.id'))
  product_id = db.Column(db.Integer(), db.ForeignKey('products.id'))

db.drop_all()
db.create_all()
