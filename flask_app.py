from flask import Flask, request, abort, render_template, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_user, logout_user, current_user, LoginManager, UserMixin, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
import git
import hmac
import hashlib
import os
import json
import uuid

app = Flask(__name__)

# Set a variable to the specifically-formatted string SQLAlchemy needs to connect to your database.
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="strongape",
    password=os.environ['SQLDB_PASSWORD'],
    hostname="strongape.mysql.pythonanywhere-services.com",
    databasename="strongape$default",
)

app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
db.init_app(app)

migrate = Migrate(app, db)

w_secret = os.environ['WEBHOOK_SECRET']

app.secret_key = os.environ['LOGIN_SECRET']
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify the login view
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Add this after creating the Flask app
@app.template_filter('currency')
def currency_filter(value):
    return "${:,.2f}".format(float(value))

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'merchant', 'customer'

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        # Convert the ID to string as required by Flask-Login
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    try:
        # Convert user_id to integer since it comes as string from the session
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    stock_count = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=True)
    image_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    merchant_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Add relationship to merchant
    merchant = db.relationship('User', backref='products')

    # Establish a relationship with the Review class
    reviews = db.relationship('Review', backref='product', lazy=True)

    def __repr__(self):
        return f'<Product {self.name}>'

class Review(db.Model):
    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    commenter = db.relationship('User', foreign_keys=commenter_id)
    content = db.Column(db.String(4096))
    posted = db.Column(db.DateTime, default=datetime.now)

    # Foreign key to link to the Product class
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)

    # Add relationships
    merchant_replies = db.relationship('MerchantReply', back_populates='review', lazy=True)

    def __repr__(self):
        return f'<Review {self.id} for Product {self.product_id}>'

class MerchantReply(db.Model):
    __tablename__ = 'merchant_replies'
    id = db.Column(db.Integer, primary_key=True)
    review_id = db.Column(db.Integer, db.ForeignKey('reviews.id'), nullable=False)
    merchant_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    posted = db.Column(db.DateTime, default=datetime.now)

    # Add relationships
    merchant = db.relationship('User', backref='replies')
    review = db.relationship('Review', back_populates='merchant_replies')

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref='orders', lazy=True)
    total_amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationship to store order items
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

    def __repr__(self):
        return f'<Order {self.id} by User {self.user_id}>'

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    product = db.relationship('Product', backref='order_items', lazy=True)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)  # Price at the time of purchase

    def __repr__(self):
        return f'<OrderItem {self.id} for Order {self.order_id}>'

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

# Required for webhook
def is_valid_signature(x_hub_signature, data, private_key):
    hash_algorithm, github_signature = x_hub_signature.split('=', 1)
    algorithm = hashlib.__dict__.get(hash_algorithm)
    encoded_key = bytes(private_key, 'latin-1')
    mac = hmac.new(encoded_key, msg=data, digestmod=algorithm)
    return hmac.compare_digest(mac.hexdigest(), github_signature)

# Routes
@app.route('/')
def index():
    # Query all products from the database
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    users = User.query.all()

    return render_template('admin_dashboard.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role not in ['admin', 'merchant']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_product = Product(
            name=request.form['name'],
            description=request.form['description'],
            price=float(request.form['price']),
            stock_count=int(request.form['stock_count']),
            category=request.form['category'],
            image_url=request.form['image_url'],
            merchant_id=current_user.id  # Set the merchant_id to current user
        )
        db.session.add(new_product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        if current_user.role == 'merchant':
            return redirect(url_for('merchant_dashboard'))
        return redirect(url_for('admin_dashboard'))

    return render_template('add_product.html')

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if current_user.role not in ['admin', 'merchant']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)
    
    # Check if the merchant owns this product
    if current_user.role == 'merchant' and product.merchant_id != current_user.id:
        flash('You can only edit your own products.', 'danger')
        return redirect(url_for('merchant_dashboard'))

    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.stock_count = int(request.form['stock_count'])
        product.category = request.form['category']
        product.image_url = request.form['image_url']
        db.session.commit()
        flash('Product updated successfully!', 'success')
        if current_user.role == 'merchant':
            return redirect(url_for('merchant_dashboard'))
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    if current_user.role not in ['admin', 'merchant']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)
    
    # Check if the merchant owns this product
    if current_user.role == 'merchant' and product.merchant_id != current_user.id:
        flash('You can only delete your own products.', 'danger')
        return redirect(url_for('merchant_dashboard'))

    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    if current_user.role == 'merchant':
        return redirect(url_for('merchant_dashboard'))
    return redirect(url_for('admin_dashboard'))

@app.route('/view_order/<int:order_id>')
@login_required
def view_order(order_id):
    if current_user.role not in ['admin', 'merchant']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    order = Order.query.get_or_404(order_id)
    
    # For merchants, verify they can only view orders containing their products
    if current_user.role == 'merchant':
        has_merchant_products = any(
            item.product.merchant_id == current_user.id 
            for item in order.order_items
        )
        if not has_merchant_products:
            flash('You can only view orders containing your products.', 'danger')
            return redirect(url_for('merchant_dashboard'))

    return render_template('view_order.html', order=order)

@app.route('/merchant')
@app.route('/merchant/page/<int:page>')
@login_required
def merchant_dashboard(page=1):
    if current_user.role != 'merchant':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    # Get products owned by this merchant with pagination
    per_page = 10
    
    # Get total number of products
    total_products = Product.query.filter_by(merchant_id=current_user.id).count()
    
    # If there are 10 or fewer products, or show_all is requested, show all products
    show_all = request.args.get('show_all', '0') == '1'
    if total_products <= 10 or show_all:
        products = Product.query.filter_by(merchant_id=current_user.id)\
            .order_by(Product.created_at.desc()).all()
        pagination = None
    else:
        pagination = Product.query.filter_by(merchant_id=current_user.id)\
            .order_by(Product.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        products = pagination.items

    # Get orders containing this merchant's products
    merchant_orders = (Order.query
             .join(OrderItem)
             .join(Product)
             .filter(Product.merchant_id == current_user.id)
             .distinct()
             .all())

    # Calculate total earnings with default value of 0
    total_earnings = 0
    if merchant_orders:
        total_earnings = sum(
            sum(item.price * item.quantity 
                for item in order.order_items 
                if item.product.merchant_id == current_user.id)
            for order in merchant_orders
        )

    # Calculate average order value
    average_order_value = total_earnings / len(merchant_orders) if merchant_orders else 0

    return render_template('merchant_dashboard.html', 
                         products=products, 
                         orders=merchant_orders,
                         total_earnings=total_earnings,
                         average_order_value=average_order_value,
                         pagination=pagination,
                         show_all=show_all)

@app.route('/merchant/earnings/<period>')
@login_required
def merchant_earnings(period):
    if current_user.role != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 403

    # Calculate date range based on period
    end_date = datetime.now()
    if period == 'week':
        start_date = end_date - timedelta(days=7)
    elif period == 'month':
        start_date = end_date - timedelta(days=30)
    elif period == 'year':
        start_date = end_date - timedelta(days=365)
    else:  # alltime
        start_date = datetime.min

    # Query orders within date range
    orders = (Order.query
             .join(OrderItem)
             .join(Product)
             .filter(Product.merchant_id == current_user.id)
             .filter(Order.created_at.between(start_date, end_date))
             .all())

    # Calculate statistics
    total_earnings = 0
    order_count = len(orders)
    product_sales = {}  # Track sales volume per product
    
    # Process orders
    for order in orders:
        for item in order.order_items:
            if item.product.merchant_id == current_user.id:
                total_earnings += item.price * item.quantity
                # Track product sales
                if item.product.id in product_sales:
                    product_sales[item.product.id]['quantity'] += item.quantity
                else:
                    product_sales[item.product.id] = {
                        'name': item.product.name,
                        'quantity': item.quantity
                    }

    # Find best-selling product
    best_selling = {'name': 'No sales', 'quantity': 0}
    if product_sales:
        best_product_id = max(product_sales.items(), key=lambda x: x[1]['quantity'])[0]
        best_selling = product_sales[best_product_id]

    # Calculate average order value
    average_order_value = total_earnings / order_count if order_count > 0 else 0

    return jsonify({
        'stats': {
            'total_earnings': total_earnings,
            'total_orders': order_count,
            'average_order_value': average_order_value,
            'best_selling': best_selling
        }
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        # Check if the user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User already exists!', 'danger')
            return render_template('register.html')

        # Create a new user
        new_user = User(
            email=email,
            password_hash=generate_password_hash(password),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        # Automatically log in the new user
        login_user(new_user)
        flash('Registration successful! You are now logged in.', 'success')

        # Redirect to the next page or index
        next_page = request.args.get('next', url_for('index'))
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect based on role
    if current_user.is_authenticated:
        if current_user.role == 'merchant':
            return redirect(url_for('merchant_dashboard'))
        elif current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('index'))

    next_page = request.args.get('next', None)
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Successfully logged in!', 'success')
            
            # Redirect based on user role
            if user.role == 'merchant':
                return redirect(url_for('merchant_dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            
            # For customers or if next page is specified
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('index'))

        flash('Invalid email or password!', 'danger')
        return render_template('login.html', error=True)

    return render_template('login.html', error=False)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found!'}), 404

    quantity = int(request.form.get('quantity', 1))
    
    if product.stock_count < quantity:
        return jsonify({'error': 'Not enough stock available!'}), 400

    cart = session.get('cart', {})
    product_id_str = str(product_id)
    
    if product_id_str in cart:
        if product.stock_count < (cart[product_id_str]['quantity'] + quantity):
            return jsonify({'error': 'Not enough stock available!'}), 400
        cart[product_id_str]['quantity'] += quantity
    else:
        cart[product_id_str] = {
            'name': product.name,
            'price': product.price,
            'quantity': quantity
        }

    product.stock_count -= quantity
    db.session.commit()
    
    session['cart'] = cart
    total_quantity = sum(item['quantity'] for item in cart.values())
    
    return jsonify({
        'success': f'Added {quantity} {product.name} to cart!',
        'total_quantity': total_quantity,
        'stock_left': product.stock_count
    })

@app.route('/cart')
def cart():
    cart = session.get('cart', {})
    cart_items = [{'product': Product.query.get(pid), 'quantity': details['quantity']} for pid, details in cart.items()]
    total_price = sum(item['product'].price * item['quantity'] for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/update_cart/<int:product_id>', methods=['POST'])
def update_cart(product_id):
    try:
        quantity = int(request.form.get('quantity', 0))
        cart = session.get('cart', {})
        product_id_str = str(product_id)
        
        if quantity <= 0:
            if product_id_str in cart:
                del cart[product_id_str]
        else:
            product = Product.query.get(product_id)
            if not product:
                flash('Product not found!', 'error')
                return redirect(url_for('cart'))
                
            # Check if requested quantity exceeds available stock
            if product.stock_count < quantity:
                flash(f'Only {product.stock_count} items available in stock!', 'error')
                return redirect(url_for('cart'))
                
            if product_id_str in cart:
                cart[product_id_str]['quantity'] = quantity

        session['cart'] = cart
        flash('Cart updated successfully!', 'success')
        return redirect(url_for('cart'))
        
    except ValueError:
        flash('Invalid quantity!', 'error')
        return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    if str(product_id) in cart:
        del cart[str(product_id)]
    session['cart'] = cart
    return redirect(url_for('cart'))

@app.route('/checkout')
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash('Your cart is empty!', 'warning')
        return redirect(url_for('index'))
        
    cart_items = [{'product': Product.query.get(pid), 'quantity': details['quantity']} 
                  for pid, details in cart.items()]
    total_price = sum(item['product'].price * item['quantity'] for item in cart_items)
    return render_template('checkout.html', total_price=total_price)

@app.route('/process_payment', methods=['POST'])
@login_required
def process_payment():
    payment_method = request.form.get('payment_method')
    cart = session.get('cart', {})
    
    if not cart:
        flash('Your cart is empty!', 'error')
        return redirect(url_for('index'))

    try:
        # Generate a unique order ID
        order_id = str(uuid.uuid4())[:8].upper()
        
        # Create new order
        cart_items = [{'product': Product.query.get(int(pid)), 'quantity': details['quantity']} 
                     for pid, details in cart.items()]
        total_price = sum(item['product'].price * item['quantity'] for item in cart_items)
        
        # Create the order first
        new_order = Order(
            user_id=current_user.id,
            total_amount=total_price
        )
        db.session.add(new_order)
        db.session.flush()  # This assigns the ID to new_order without committing
        
        # Now create order items with the order ID
        for item in cart_items:
            order_item = OrderItem(
                order_id=new_order.id,
                product_id=item['product'].id,
                quantity=item['quantity'],
                price=item['product'].price
            )
            db.session.add(order_item)
        
        # Commit all changes
        db.session.commit()
        
        # Clear the cart
        session['cart'] = {}
        
        # Render confirmation page
        return render_template('order_confirmation.html',
                             order_id=order_id,
                             order_items=cart_items,
                             total_price=total_price,
                             payment_method=payment_method,
                             user_email=current_user.email)
                             
    except Exception as e:
        # If anything goes wrong, rollback the transaction
        db.session.rollback()
        flash('An error occurred while processing your payment. Please try again.', 'error')
        print(f"Payment processing error: {str(e)}")  # For debugging
        return redirect(url_for('checkout'))

@app.route('/update_server', methods=['POST'])
def webhook():
    if request.method != 'POST':
        return 'OK'
    
    event = request.headers.get('X-GitHub-Event')

    if event == "ping":
        return json.dumps({'msg': 'Hi!'})
    
    elif event == "push":
        x_hub_signature = request.headers.get('X-Hub-Signature')
        if not is_valid_signature(x_hub_signature, request.data, w_secret):
            print('Deploy signature failed: {sig}'.format(sig=x_hub_signature))
            abort(401)

        payload = request.get_json()
        if payload is None:
            print('Deploy payload is empty: {payload}'.format(
                payload=payload))
            abort(400)

        if payload['ref'] != 'refs/heads/main':
            return json.dumps({'msg': 'Not main; ignoring'})

        repo = git.Repo('/home/strongape/.virtualenvs/ecommerce')
        origin = repo.remotes.origin
        pull_info = origin.pull()

        if len(pull_info) == 0:
            return json.dumps({'msg': "Didn't pull any information from remote!"})
        if pull_info[0].flags > 128:
            return json.dumps({'msg': "Didn't pull any information from remote!"})

        commit_hash = pull_info[0].commit.hexsha
        build_commit = f'build_commit = "{commit_hash}"'
        print(build_commit)
        return f'Updated PythonAnywhere server to commit {commit_hash}'
    else:
        return json.dumps({'msg': "Wrong event type"})

@app.route('/product/<int:product_id>/review', methods=['POST'])
@login_required
def add_review(product_id):
    content = request.form.get('content')
    
    if not content:
        flash('Review content cannot be empty.', 'error')
        return redirect(url_for('view_product', product_id=product_id))
    
    # Check if user already reviewed this product
    existing_review = Review.query.filter_by(
        commenter_id=current_user.id,
        product_id=product_id
    ).first()
    
    if existing_review:
        flash('You have already reviewed this product. You can edit your existing review.', 'warning')
        return redirect(url_for('view_product', product_id=product_id))
    
    review = Review(
        commenter_id=current_user.id,
        product_id=product_id,
        content=content
    )
    
    db.session.add(review)
    db.session.commit()
    
    flash('Thank you for your review!', 'success')
    return redirect(url_for('view_product', product_id=product_id))

@app.route('/review/<int:review_id>/edit', methods=['POST'])
@login_required
def edit_review(review_id):
    review = Review.query.get_or_404(review_id)
    
    # Check if the current user is the author of the review
    if review.commenter_id != current_user.id:
        flash('You can only edit your own reviews.', 'error')
        return redirect(url_for('view_product', product_id=review.product_id))
    
    content = request.form.get('content')
    if not content:
        flash('Review content cannot be empty.', 'error')
        return redirect(url_for('view_product', product_id=review.product_id))
    
    review.content = content
    review.posted = datetime.now()  # Update the timestamp
    db.session.commit()
    
    flash('Your review has been updated.', 'success')
    return redirect(url_for('view_product', product_id=review.product_id))

@app.route('/review/<int:review_id>/delete')
@login_required
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    
    # Check if the current user is the author of the review or an admin
    if review.commenter_id != current_user.id and current_user.role != 'admin':
        flash('You can only delete your own reviews.', 'error')
        return redirect(url_for('view_product', product_id=review.product_id))
    
    db.session.delete(review)
    db.session.commit()
    
    flash('Your review has been deleted.', 'success')
    return redirect(url_for('view_product', product_id=review.product_id))

@app.route('/product/<int:product_id>')
def view_product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_details.html', product=product)

@app.route('/product/<int:product_id>/review/<int:review_id>/reply', methods=['POST'])
@login_required
def add_merchant_reply(product_id, review_id):
    if current_user.role != 'merchant':
        flash('Only merchants can reply to reviews.', 'error')
        return redirect(url_for('view_product', product_id=product_id))
    
    product = Product.query.get_or_404(product_id)
    
    if product.merchant_id != current_user.id:
        flash('You can only reply to reviews of your own products.', 'error')
        return redirect(url_for('view_product', product_id=product_id))
    
    content = request.form.get('content')
    if not content:
        flash('Reply content cannot be empty.', 'error')
        return redirect(url_for('view_product', product_id=product_id))
    
    reply = MerchantReply(
        review_id=review_id,
        merchant_id=current_user.id,
        content=content
    )
    
    db.session.add(reply)
    db.session.commit()
    
    flash('Your reply has been posted.', 'success')
    return redirect(url_for('view_product', product_id=product_id))

@app.route('/merchant-reply/<int:reply_id>/edit', methods=['POST'])
@login_required
def edit_merchant_reply(reply_id):
    reply = MerchantReply.query.get_or_404(reply_id)
    
    if current_user.id != reply.merchant_id:
        flash('You can only edit your own replies.', 'error')
        return redirect(url_for('view_product', product_id=reply.review.product_id))
    
    content = request.form.get('content')
    if not content:
        flash('Reply content cannot be empty.', 'error')
        return redirect(url_for('view_product', product_id=reply.review.product_id))
    
    reply.content = content
    reply.posted = datetime.now()
    db.session.commit()
    
    flash('Your reply has been updated.', 'success')
    return redirect(url_for('view_product', product_id=reply.review.product_id))

@app.route('/merchant-reply/<int:reply_id>/delete')
@login_required
def delete_merchant_reply(reply_id):
    reply = MerchantReply.query.get_or_404(reply_id)
    
    if current_user.id != reply.merchant_id:
        flash('You can only delete your own replies.', 'error')
        return redirect(url_for('view_product', product_id=reply.review.product_id))
    
    db.session.delete(reply)
    db.session.commit()
    
    flash('Your reply has been deleted.', 'success')
    return redirect(url_for('view_product', product_id=reply.review.product_id))

if __name__ == '__main__':
    app.run(debug=True)