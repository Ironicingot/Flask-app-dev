from brand_rumour import app, db

from brand_rumour.forms import RegistrationForm, LoginForm, ResetRequestForm, ResetPasswordForm, UploadProductForm, CreateProductForm
from brand_rumour.models import User
from brand_rumour.product import Product

from flask import render_template, url_for, redirect, flash, make_response, abort, request, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from itsdangerous import TimestampSigner, SignatureExpired
from flask_mail import Mail, Message
from datetime import datetime, timedelta

import sqlite3
import base64
import random
import stripe
import os
import json
import pyperclip

bcrypt = Bcrypt(app)

signer = TimestampSigner(app.config['SECRET_KEY'].encode())

mail = Mail(app)

login_manager = LoginManager(app)

@app.route('/')

@app.route('/home')
def homepage():
    return render_template('homepage.html', title='Home Page') # declare title

@app.route('/account')
@login_required
def account():
    return render_template('homepage.html', title='Account') # declare title

@app.route('/register', methods=['POST','GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    form = RegistrationForm()
    if form.validate_on_submit():
        encrypted_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username = form.username.data, email = form.email.data, password = encrypted_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created successfully for {form.username.data}', category='success')     # form.username.data will retrieve the username data
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('register'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f'Login successful for {form.username.data}', category='success')
            return redirect(url_for('account'))
        else:
            flash(f'Login unsuccessful for {form.username.data}', category='danger')
            return redirect(url_for('login'))
    return render_template('login.html', title='Login', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = signer.sign(user.email.encode())
            reset_link = url_for('reset_password_token', token=token, _external=True)
            msg = Message(subject='Password Reset Request',
                          sender='br.brandrumours@gmail.com',
                          recipients=[user.email],
                          body=f'To reset your password, please click on the following link: {reset_link}')
            mail.send(msg)
            flash(f'An email has been sent to {user.email} with instructions to reset your password', category='info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found', 'danger')
    return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = signer.unsign(token, max_age=300)
    except SignatureExpired:
        flash('The reset link has expired', 'danger')
        return redirect(url_for('reset_password'))
    user = User.query.filter_by(email=email.decode()).first()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Your password has been reset', category='success')
        return redirect(url_for('login'))
    return render_template('change_password.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been deleted', category='success')
    else:
        flash(f'User not found', 'danger')
    return redirect(url_for('homepage'))

stripe.api_key = app.config['STRIPE_SECRET_KEY']

def get_cart_items():
    # Retrieve cart items from the database (implement as per your database setup)
    # Sample code assuming SQLite
    conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT cart.product_name, inventory.* FROM cart JOIN inventory ON cart.product_name = inventory.name GROUP BY cart.product_name')
    cart_items = cursor.fetchall()
    conn.close()

    return cart_items

@app.route('/checkout', methods=['POST'])
def checkout():
    # Retrieve cart items from the database
    cart_items = get_cart_items()

    session_ids = []

    # Create a Stripe Checkout Session for each item
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'sgd',
                'product_data': {
                    'name': item[2],
                },
                'unit_amount': int(item[2] * 100),  # Stripe uses cents
            },
            'quantity': 1,
        } for item in cart_items ],
        shipping_address_collection={"allowed_countries": ["SG"]},
        shipping_options=[
            {
            "shipping_rate_data": {
                "type": "fixed_amount",
                "fixed_amount": {"amount": 150, "currency": "sgd"},
                "display_name": "Shipping Fee",
                "delivery_estimate": {
                "minimum": {"unit": "business_day", "value": 5},
                "maximum": {"unit": "business_day", "value": 7},
                },
            },
        }],
        mode='payment',
        success_url=request.url_root + 'checkout-success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=request.url_root + f'shoppingcart?cancel',
    )

    session_ids.append(session.id)

    return jsonify(session_ids=session_ids)

@app.route('/checkout-success', methods=['GET'])
def checkout_success():
    session_id = request.args.get('session_id')

    # Retrieve the session from Stripe to check the payment status
    session = stripe.checkout.Session.retrieve(session_id)

    if session.payment_status == 'paid':
        # Payment succeeded, move items to history
        cart_items = get_cart_items()
        move_items_to_history(cart_items)
        return redirect('/myorders?success')

    # Payment failed or not completed
    return "Payment failed or not completed."

def move_items_to_history(items):
    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS myorder (id INTEGER PRIMARY KEY, username VARCHAR(20), product_name TEXT, FOREIGN KEY (username) REFERENCES user(username), FOREIGN KEY (product_name) REFERENCES inventory(name))")
        c.execute("SELECT * FROM cart")
        items = c.fetchall()
        for item in items:
            c.execute("INSERT INTO myorder (username, product_name) VALUES (?, ?)", (current_user.username, item[2]))
        c.execute("DELETE FROM cart")
        conn.commit()
        conn.close()

def delete_cart_item(product_name):
    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("SELECT * FROM cart WHERE username=? AND product_name=?", (current_user.username, product_name))
        conn.commit()
        conn.close()

@app.route('/men')
def men():
    products = get_products('Men')
    return render_template('men.html', products = products)

@app.route('/women')
def women():
     products = get_products('Women')
     return render_template('women.html', products = products)

@app.route('/kids')
def kids():
    products = get_products('Kids')
    return render_template('kids.html', products = products)

@app.route('/newin')
def newin():
    products = get_products('New In')
    return render_template('newin.html', products = products)

# This code is a function for inserting a product into a SQLite database. It connects to the database, creates the table and adds a new column if it doesn't exist, checks if the product already exists in the database, inserts the product if it doesn't exist, and finally commits the changes and closes the database connection.
def insert_product(product: Product):
    conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
    c = conn.cursor()

    c.execute("CREATE TABLE IF NOT EXISTS inventory (name text, price real, size text, category text, image BLOB)")
    c.execute("SELECT * FROM inventory WHERE name = ? AND price = ? AND size = ? AND category = ? AND image = ?", (product.get_name(), product.get_price(), product.get_size(), product.get_category(), product.get_image()))

    existing_product = c.fetchone()

    if existing_product is None:
        c.execute("INSERT INTO inventory (name, price, size, category, image) VALUES (?, ?, ?, ?, ?)", (product.get_name(), product.get_price(), product.get_size(), product.get_category(), sqlite3.Binary(product.get_image())))
    conn.commit()
    conn.close()

# This code is a function that retrieves products from a SQLite database based on their category. It connects to the database, retrieves all rows from the "inventory" table where the "category" column matches the goods_type parameter, creates a new Product object for each row, stores the objects in a list, closes the database connection, and returns the list of Product objects.
def get_products(goods_type):
    products = []
    conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
    c = conn.cursor()
    c.execute("SELECT * FROM inventory WHERE category=?", (goods_type,))
    rows = c.fetchall()

    for row in rows:
        product = Product(row[0], row[1], row[2], row[3], row[4])
        products.append(product)

    conn.close()
    return products

def show_products():
    products = get_products()
    for product in products:
        goods_type = product['category']
        if goods_type == 'Kids':
            return render_template('kids.html', products=product)
        elif goods_type == 'Women':
            return render_template('women.html', products=product)
        elif goods_type == 'Men':
            return render_template('men.html', products=product)
        elif goods_type == 'New In':
            return render_template('newin.html', products=product)

@app.route('/product_image/<name>')
def serve_product_image(name):
    conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
    c = conn.cursor()
    c.execute("SELECT * FROM inventory WHERE name=?", (name,))
    row = c.fetchone()
    if row:
        image_data = row[4]

        # Create an HTTP response with the correct MIME type
        response = make_response(image_data)
        response.headers.set('Content-Type', 'image/jpeg')
        return response
    else:
        abort(404)

@app.route('/shoppingcart')
def shoppingcart():
    products = get_cart_products()
    total= get_cart_total()
    return render_template('shoppingcart.html', products=products, total=total)

@app.route('/add_to_cart/<type>', methods=['POST'])
def add_to_cart(type):
    # Retrieve the product information from the form submission
    product_name = request.form['product_name']

    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS cart (id INTEGER PRIMARY KEY, username VARCHAR(20), product_name TEXT, FOREIGN KEY (username) REFERENCES user(username), FOREIGN KEY (product_name) REFERENCES inventory(name))")
        c.execute("SELECT * FROM cart WHERE username=? AND product_name=?", (current_user.username, product_name))
        rows = c.fetchone()
        if rows:
            flash("Item already in cart!")
        else:
            c.execute("INSERT INTO cart (username, product_name) VALUES (?, ?)", (current_user.username, product_name))
            flash("Item added to cart successfully!")

        conn.commit()
        conn.close()

        # Get the referrer URL (search page URL) from the request
        referrer = request.referrer

        # If the referrer is available and not None, redirect to the referrer
        if referrer:
            return redirect(referrer)
        else:
            # If referrer is not available, redirect to the specified type (fallback)
            return redirect(url_for(type))
    else:
        return redirect('/login')

# new wishlist for each user
@app.route('/add_to_wishlist/<type>', methods=['POST'])
def add_to_wishlist(type):
    if current_user.is_authenticated:
    # Retrieve the product information from the form submission
        product_name = request.form['product_name']

        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS wishlist (id INTEGER PRIMARY KEY, username VARCHAR(20), product_name TEXT, FOREIGN KEY (username) REFERENCES user(username), FOREIGN KEY (product_name) REFERENCES inventory(name))")
        c.execute("SELECT * FROM wishlist WHERE username=? AND product_name=?", (current_user.username, product_name))
        rows = c.fetchone()
        if rows:
            flash("Item already in wishlist!")
        else:
            c.execute("INSERT INTO wishlist (username, product_name) VALUES (?, ?)", (current_user.username, product_name))
            flash("Item added to wishlist successfully!")

        conn.commit()
        conn.close()

        # Get the referrer URL (search page URL) from the request
        referrer = request.referrer

        # If the referrer is available and not None, redirect to the referrer
        if referrer:
            return redirect(referrer)
        else:
            # If referrer is not available, redirect to the specified type (fallback)
            return redirect(url_for(type))
    else:
        return redirect(url_for('login'))

def add_to_history(id):
    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        wonn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        w = wonn.cursor()
        print(id)
        w.execute("SELECT * FROM inventory WHERE id=?",(id,))
        rows = w.fetchall()
        c.execute("CREATE TABLE IF NOT EXISTS orderhistory (id integer, name text, price real, size text, category text, image BLOB)")
        for row in rows:
            c.execute("INSERT INTO orderhistory (id, name, price, size, category, image) VALUES (?, ?, ?, ?, ?, ?)",
            (row[0],row[1],row[2],row[3],row[4],row[5]))
        conn.commit()
        wonn.commit()
        c.close()
        w.close()

# This code is a function that retrieves products from a SQLite database stored in a "cart". It connects to the database, selects all rows from the "cart" table, loops through the rows and creates a dictionary for each row with product information such as ID, name, price, size, category, and image, adds the dictionaries to a list, closes the database connection, and returns the list of dictionaries.
def get_cart_products():
    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("""
                      SELECT DISTINCT cart.product_name, inventory.price, inventory.size, inventory.category, inventory.image
                      FROM cart
                      JOIN inventory ON cart.product_name = inventory.name
                      WHERE cart.username = ?
                      GROUP BY cart.product_name
                  """, (current_user.username,))
        rows = c.fetchall()
        products = []
        for row in rows:
            products.append({'name': row[0], 'price': float(row[1]), 'size': row[2], 'category': row[3], 'image': row[4]})
        conn.close()
        return products

@app.route("/deletecart", methods=["POST"])
def deletecart():
    if current_user.is_authenticated:
        product_name = request.form["product_name"]

        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("DELETE FROM cart WHERE username=? AND product_name=?", (current_user.username, product_name))
        flash("Item deleted from cart!")
        conn.commit()
        conn.close()
        return redirect(url_for("shoppingcart"))

@app.route('/addwishlist', methods=['POST'])
def addwishlist():
    # Retrieve the product information from the form submission
    product_name = request.form['product_name']

    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS wishlist (id INTEGER PRIMARY KEY, username VARCHAR(20), product_name TEXT, FOREIGN KEY (username) REFERENCES user(username), FOREIGN KEY (product_name) REFERENCES inventory(name))")
        c.execute("SELECT * FROM wishlist WHERE username=? AND product_name=?", (current_user.username, product_name))
        rows = c.fetchone()
        if rows:
            flash("Item already in wishlist!")
        else:
            c.execute("INSERT INTO wishlist (username, product_name) VALUES (?, ?)", (current_user.username, product_name))
            flash("Item added to wishlist successfully!")
        conn.commit()
        conn.close()

        return redirect(url_for('shoppingcart'))

def get_total_price(products):
    total_price = get_total_price(products)
    for product in products:
        total_price += product['price']
    return total_price

def get_cart_total():
    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()

        c.execute("""
                      SELECT cart.product_name, inventory.price, inventory.size, inventory.category, inventory.image
                      FROM cart
                      JOIN inventory ON cart.product_name = inventory.name
                      WHERE cart.username = ?
                  """, (current_user.username,))

        rows = c.fetchall()

        total= 0
        for row in rows:
            total += row[1]
        conn.close()
        return total

@app.route('/wishlist')
def wishlist():
    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()

        product = []
        c.execute("CREATE TABLE IF NOT EXISTS wishlist (id INTEGER PRIMARY KEY, username VARCHAR(20), product_name TEXT, FOREIGN KEY (username) REFERENCES user(username), FOREIGN KEY (product_name) REFERENCES inventory(name))")
        c.execute("""
                      SELECT DISTINCT wishlist.product_name, inventory.price, inventory.size, inventory.category, inventory.image
                      FROM wishlist
                      JOIN inventory ON wishlist.product_name = inventory.name
                      WHERE wishlist.username = ?
                      GROUP BY wishlist.product_name
                  """, (current_user.username,))
        items = c.fetchall()
        for row in items:
            product.append({'name':row[0],'price':row[1],'size':row[2],'category':row[3],'image':row[4]})
        conn.close()

        products = get_products('New In')
        random_products = random.sample(products, 4)

        return render_template('wishlist.html', items=product, products=random_products)
    else:
        return redirect('/login')

@app.route('/addtocart_fromwishlist', methods=['POST'])
def addtocart_fromwishlist():
    # Retrieve the product information from the form submission
    if current_user.is_authenticated:
        item_name = request.form['item_name']
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS cart (id INTEGER PRIMARY KEY, username VARCHAR(20), product_name TEXT, FOREIGN KEY (username) REFERENCES user(username), FOREIGN KEY (product_name) REFERENCES inventory(name))")
        c.execute("SELECT * FROM cart WHERE username=? AND product_name=?", (current_user.username, item_name))
        rows = c.fetchone()
        if rows:
            flash("Item already in cart!")
        else:
            c.execute("INSERT INTO cart (username, product_name) VALUES (?, ?)", (current_user.username, item_name))
            flash("Item added to cart successfully!")

        conn.commit()
        conn.close()
        return redirect('/wishlist')
    else:
        return redirect('/login')

@app.route('/deletewishlist', methods=['POST'])
def deletewishlist():
    item_name = request.form['item_name']

    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("DELETE FROM wishlist WHERE username=? AND product_name=?", (current_user.username, item_name))
        flash("Item successfully removed from wishlist!")
        conn.commit()
        conn.close()

        return redirect('/wishlist')
    else:
        return redirect(url_for('login'))

# The route uses a "UploadProductForm" to retrieve the form data, validates the form data, creates a product object with the information such as name, price, category, size, ID, and image data. Then the image data is read into memory, and the product object is passed to the "insert_product" function to add the product to the inventory database. 
@app.route('/uploadproduct', methods=['GET', 'POST'])
def uploadproduct():
    if current_user.is_authenticated:
        form = UploadProductForm(request.form)
        if request.method == 'POST' and form.validate():
            name = form.name.data
            price = form.price.data
            category = form.category.data
            size = form.size.data
            image = form.image.data
            size = size.upper()
            file = request.files['image']
            # Read the image file into memory
            image_data = file.read()
            #product = Product(name, price, color, size, qty, goods, image_data)
            # Insert the product into the "inventory" table
            insert_product(Product(name, price, size, category, image_data))
            flash("Product has been uploaded successfully!")
            return redirect(url_for('inventory'))
        return render_template('uploadproduct.html', form=form)
    else:
        return redirect(url_for('login'))

@app.route('/inventory')
def inventory():
    if current_user.is_authenticated:
        products = get_inventory()
        return render_template('inventory.html', products = products)
    else:
        return redirect(url_for('login'))

#UPDATE INVENTORY
@app.route('/updateInventoryItem/<name>/', methods=['GET', 'POST'])
def update_inventory_item(name):
    if current_user.is_authenticated:
        update_item_form = CreateProductForm(request.form)
        if request.method == 'POST':
            conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
            c = conn.cursor()

            # Check if a new image is uploaded
            if 'image' in request.form:
                file = request.form['image']
                image_data = file.read()
                c.execute("UPDATE inventory SET name=?, price=?, size=?, category=?, image=? WHERE name=?",
                        (update_item_form.name.data, update_item_form.price.data,
                        update_item_form.size.data, update_item_form.category.data,
                        sqlite3.Binary(image_data), name))
            else:
                # If no new image is uploaded, update without changing the image
                c.execute("UPDATE inventory SET name=?, price=?, size=?, category=? WHERE name=?",
                        (update_item_form.name.data, update_item_form.price.data,
                        update_item_form.size.data, update_item_form.category.data, name))

            flash("Product has been updated successfully!")
            conn.commit()
            conn.close()
            return redirect(url_for('inventory'))
        else:
            products = []
            conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
            c = conn.cursor()
            try:
                c.execute("SELECT * FROM inventory WHERE name=?", (name,))
                rows = c.fetchall()

                for row in rows:
                    update_item_form.name.data = row[0]
                    update_item_form.price.data = row[1]
                    update_item_form.size.data = row[2]
                    update_item_form.category.data = row[3]
                    update_item_form.image.data = row[4]

            except sqlite3.OperationalError:
                products = []
                return products

            return render_template('updateInventory.html', form=update_item_form, name=name)
    else:
        return redirect(url_for('login'))

@app.route('/deleteInventoryItem/<name>/', methods=['GET'])
def delete_inventory_item(name):
    conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
    c = conn.cursor()
    c.execute("DELETE FROM inventory WHERE name=?", (name,))
    flash("Product has been deleted successfully!")
    conn.commit()
    conn.close()
    return redirect(url_for('inventory'))

def get_inventory():
    conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
    c = conn.cursor()
    products = []
    c.execute("SELECT * FROM inventory")
    rows = c.fetchall()
    for row in rows:
        products.append({'name': row[0], 'price': row[1], 'size': row[2], 'category': row[3], 'image': row[4]})
    conn.close()
    return products

@app.route('/search', methods=["GET", "POST"])
def search():
    # Retrieve the search term from the form submission or the URL
    input_query = request.args.get('query', '')

    if request.method == "POST":
        # If the form is submitted, redirect to the same route with the search query in the URL
        return redirect(url_for('search', query=input_query))

    products = []  # Initialize products here

    if input_query:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()

        # Use parameterized query to prevent SQL injection
        c.execute("SELECT * FROM inventory WHERE name LIKE ? AND category != 'New In'", ("%" + input_query + "%",))
        rows = c.fetchall()

        for row in rows:
            product = Product(row[0], row[1], row[2], row[3], row[4])
            products.append(product)

        conn.close()

    # Render the search results page with the products and search input
    return render_template('search.html', products=products, query=input_query, count=len(products))

#my orders part
@app.route('/myorders')
def myorders():
    if current_user.is_authenticated:
        conn = sqlite3.connect('C:/brand rumour/brand_rumour/database/brandrumour.db')
        c = conn.cursor()
        c.execute("""
                      SELECT DISTINCT myorder.product_name, inventory.price, inventory.size, inventory.category, inventory.image
                      FROM myorder
                      JOIN inventory ON myorder.product_name = inventory.name
                      WHERE myorder.username = ?
                      GROUP BY myorder.product_name
                  """, (current_user.username,))
        rows = c.fetchall()
        products = []
        for row in rows:
            products.append({'name': row[0], 'price': float(row[1]), 'size': row[2], 'category': row[3], 'image': row[4]})
        conn.close()
        return render_template('myorders.html', products=products)
    else:
        return redirect(url_for('login'))

# Maintenance Ongoing
# @app.route('/tracking')
# def tracking():
#      # Hardcoded order details
#     order = {
#         'order_number': '12345678',
#         'photo': '/static/images/photo_6136643586444343250_y.jpg',
#         'order_date': '01-01-2023',
#         'received': False
#     }
#     # Convert the order_date string to a datetime object
#     order_date = datetime.strptime(order['order_date'], '%d-%m-%Y')
#     # Get the current date and time
#     now = datetime.now()
#     # Calculate the estimated delivery time
#     estimated_delivery_time = order_date + timedelta(days=5)
#     estimated_delivery_time2 = order_date + timedelta(days=8)
#     #recs
#     products = get_products('New In')
#     random_products = random.sample(products, 4)

#     return render_template('tracking.html', order=order, products=random_products, estimated_delivery_time=estimated_delivery_time, estimated_delivery_time2=estimated_delivery_time2)

# @app.route("/deliverystatus")
# def delivery_status():
#     delivery_stages = ["In Dispatch", "In Transit", "Processed for Clearance", "Arrived at Local Facility", "Received by Receiver"]
#     return render_template("tracking.html", stages=delivery_stages)

# @app.route('/copy_order_number')
# def copy_order_number():
#     order_number = request.args.get('order_number')
#     try:
#         pyperclip.copy(order_number)
#         return '', 204
#     except:
#         return '', 200


# def save_to_db(rating, feedback):
#     if not feedback:
#         feedback = ''
#     # Connect to the database
#     conn = sqlite3.connect("reviews.db")
#     c = conn.cursor()
#     # Create the table if it doesn't exist
#     c.execute("""CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, rating INTEGER, feedback TEXT)""")
#     # Insert the data into the table
#     c.execute("INSERT INTO reviews (rating, feedback) VALUES (?, ?)", (rating, feedback))
#     # Commit the changes and close the connection
#     conn.commit()
#     conn.close()

# @app.route("/submit_review", methods=["POST"])
# def submit_review():
#     # Get the values from the form
#     if request.method == "POST":
#         rating = request.form.get("rating")
#         feedback = request.form.get("feedback")
#     # Check if both fields are filled
#     if not rating or not feedback:
#         return render_template("reviewform.html", error_message="Both fields are required")
#     # Save the data to the database
#     save_to_db(rating, feedback)
#     return render_template("successreview.html")

# @app.route('/review')
# def review():
#     reviews = get_reviews_from_db()
#     return render_template('reviewform.html', reviews=reviews)

# @app.route("/retrieve_reviews")
# def get_reviews_from_db():
#     # Connect to the database
#     conn = sqlite3.connect("reviews.db")
#     c = conn.cursor()
#     # Check if the table exists
#     c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reviews'")
#     if c.fetchone() is None:
#         # Table does not exist
#         conn.close()
#         return "No reviews found."
#     else:
#         # Retrieve all the data from the table
#         c.execute("SELECT * FROM reviews")
#         # Fetch all the rows
#         rows = c.fetchall()
#         # Close the connection
#         conn.close()
#         # Create a list of Review objects
#         review_list = [Review(*row[:3]) for row in rows]
#         # Pass the list of Review objects to the template
#         return render_template("retrieveReview.html", reviews=review_list)


# @app.route("/delete_review", methods=["POST"])
# def delete_review():
#     # Get the review id from the form
#     review_id = request.form.get("review_id")
#     # Connect to the database
#     conn = sqlite3.connect("reviews.db")
#     c = conn.cursor()
#     # Delete the review with the specified id
#     c.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
#     # Commit the changes
#     conn.commit()
#     # Close the connection
#     conn.close()
#     # Redirect to the reviews page
#     return redirect(url_for("get_reviews_from_db"))