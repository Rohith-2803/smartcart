from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from config import Config
import os
import random
import secrets
import razorpay

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Extensions
mail = Mail(app)
bcrypt = Bcrypt(app)

from datetime import datetime

@app.template_filter('strftime')
def _jinja2_filter_datetime(date, fmt=None):
    if date is None:
        return ""
    if isinstance(date, str):
        try:
            # Handle standard SQLite timestamp format
            date = datetime.strptime(date, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                date = datetime.strptime(date, '%Y-%m-%d')
            except ValueError:
                return date
    
    if fmt:
        return date.strftime(fmt)
    else:
        return date.strftime('%d %b, %Y')

# Initialize Razorpay Client
razorpay_client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))

def get_db_connection():
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'], detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except sqlite3.Error as err:
        print(f"Error: {err}")
        return None

# --- ROUTES ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('user_login'))

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    try:
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            conn = get_db_connection()
            if not conn:
                flash("Database connection error.", "danger")
                return render_template('admin/admin_login.html')
                
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
            admin = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if admin and bcrypt.check_password_hash(admin['password'], password):
                if admin['status'] == 'Pending':
                    flash("Your account is pending approval from Super Admin.", "warning")
                    return redirect(url_for('admin_login'))
                elif admin['status'] == 'Rejected':
                    flash("Your account registration request was rejected.", "danger")
                    return redirect(url_for('admin_login'))

                session['admin_id'] = admin['admin_id']
                session['admin_name'] = admin['name']
                session['admin_role'] = admin['role']
                session['profile_image'] = admin['profile_image'] or 'default.png'
                flash(f"Welcome back, {admin['name']}!", "success")
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Invalid email or password", "danger")
                
        return render_template('admin/admin_login.html')
    except Exception as e:
        print(f"Admin Login Error: {e}")
        flash(f"An unexpected error occurred: {e}", "danger")
        return render_template('admin/admin_login.html')

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if email exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
        existing_admin = cursor.fetchone()
        
        if existing_admin:
            flash("Email already registered!", "danger")
            return redirect(url_for('admin_signup'))
        
        # Generate OTP
        otp = random.randint(100000, 999999)
        session['signup_data'] = {
            'name': name,
            'email': email,
            'password': bcrypt.generate_password_hash(password).decode('utf-8'),
            'otp': otp
        }
        
        # Send Email
        try:
            msg = Message('SmartCart - Email Verification', 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"Hello {name},\n\nYour OTP for admin registration is: {otp}\n\nPlease do not share this code."
            mail.send(msg)
            flash("OTP sent to your email!", "success")
            return redirect(url_for('verify_otp'))
        except Exception as e:
            print(f"Mail Error: {e}")
            flash("Error sending email. Please check your credentials.", "danger")
            
    return render_template('admin/admin_signup.html')

@app.route('/admin/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'signup_data' not in session:
        return redirect(url_for('admin_signup'))
        
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        signup_data = session['signup_data']
        
        if str(user_otp) == str(signup_data['otp']):
            # Insert into DB (default status is Pending from schema, but let's be explicit)
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO admin (name, email, password, role, status) VALUES (?, ?, ?, 'admin', 'Pending')", 
                           (signup_data['name'], signup_data['email'], signup_data['password']))
            conn.commit()

            # --- NOTIFY SUPER ADMINS ---
            try:
                # Fetch all super admin emails
                cursor = conn.cursor()
                cursor.execute("SELECT email FROM admin WHERE role = 'superadmin'")
                super_admins = cursor.fetchall()
                
                recipients = [sa['email'] for sa in super_admins]
                # Also include the developer email from config if not already in list
                dev_email = app.config.get('MAIL_USERNAME')
                if dev_email and dev_email not in recipients:
                    recipients.append(dev_email)

                if recipients:
                    msg = Message('SmartCart - New Admin Registration Request', 
                                  sender=app.config['MAIL_USERNAME'], 
                                  recipients=recipients)
                    
                    approval_link = url_for('superadmin_admins', _external=True)
                    
                    msg.body = f"""Hello Super Admin,

A new admin registration request has been received:

Name: {signup_data['name']}
Email: {signup_data['email']}

Please login to the Super Admin panel to accept or reject this request.
Link: {approval_link}

Regards,
SmartCart Team"""
                    mail.send(msg)
            except Exception as e:
                print(f"Error notifying super admins: {e}")

            cursor.close()
            conn.close()
            
            session.pop('signup_data', None)
            flash("Registration successful! Your account is pending approval from the Super Admin.", "success")
            return redirect(url_for('admin_login'))
        else:
            flash("Invalid OTP!", "danger")
            
    return render_template('admin/verify_otp.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('admin_login'))

@app.route('/admin/add-product', methods=['GET', 'POST'])
def add_item():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('category')
        price = request.form.get('price')
        stock = request.form.get('stock')
        description = request.form.get('description')
        file = request.files.get('image')
        
        image_name = 'default_product.png'
        if file and file.filename != '':
            image_name = secure_filename(f"prod_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_name))
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO products (name, category, price, stock, description, image) VALUES (?, ?, ?, ?, ?, ?)",
                       (name, category, price, stock, description, image_name))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Product added successfully!", "success")
        return redirect(url_for('item_list'))

    return render_template('admin/add_item.html')

@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    admin_id = session['admin_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        file = request.files.get('profile_image')
        
        # Current admin data to get old image name
        cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
        admin = cursor.fetchone()
        
        profile_image = admin['profile_image']
        
        # Handle Image Upload
        if file and file.filename != '':
            filename = secure_filename(f"admin_{admin_id}_{file.filename}")
            file_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Delete old image if it exists and is not default
            if profile_image and profile_image != 'default.png':
                old_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], profile_image)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            profile_image = filename

        # Handle Password Update
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute("UPDATE admin SET name=?, email=?, password=?, profile_image=? WHERE admin_id=?",
                           (name, email, hashed_password, profile_image, admin_id))
        else:
            cursor.execute("UPDATE admin SET name=?, email=?, profile_image=? WHERE admin_id=?",
                           (name, email, profile_image, admin_id))
        
        conn.commit()
        
        # Update Session
        session['admin_name'] = name
        session['profile_image'] = profile_image or 'default.png'
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for('admin_profile'))

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return render_template('admin/profile.html', admin=admin)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
        
    admin_id = session.get('admin_id')
    role = session.get('admin_role', 'admin')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if admin is approved (Super Admin is always approved)
    cursor.execute("SELECT status, role FROM admin WHERE admin_id = ?", (admin_id,))
    admin_info = cursor.fetchone()
    
    if not admin_info:
        session.clear()
        flash("Admin account not found.", "danger")
        return redirect(url_for('admin_login'))
        
    if admin_info['status'] != 'Approved' and admin_info['role'] != 'superadmin':
        flash("Your account is pending approval from Super Admin.", "warning")
        return redirect(url_for('admin_login'))

    # --- ANALYTICS ---
    # Total Revenue
    cursor.execute("SELECT SUM(total_amount) as total FROM orders WHERE status = 'Paid' OR status = 'Delivered'")
    total_revenue = cursor.fetchone()['total'] or 0
    
    # Total Orders
    cursor.execute("SELECT COUNT(*) as count FROM orders")
    total_orders = cursor.fetchone()['count'] or 0
    
    # Most Sold Item
    cursor.execute("""
        SELECT p.name, SUM(oi.quantity) as sold 
        FROM order_items oi 
        JOIN products p ON oi.product_id = p.product_id 
        GROUP BY p.product_id 
        ORDER BY sold DESC LIMIT 1
    """)
    most_sold = cursor.fetchone()
    
    # Today's Sales
    cursor.execute("SELECT SUM(total_amount) as total FROM orders WHERE DATE(created_at) = date('now')")
    today_sales = cursor.fetchone()['total'] or 0
    
    # Sales History for Chart (Last 7 Days)
    cursor.execute("""
        SELECT DATE(created_at) as date, SUM(total_amount) as total 
        FROM orders 
        WHERE created_at >= date('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY date ASC
    """)
    sales_history = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('admin/dashboard.html', 
                           total_revenue=total_revenue, 
                           total_orders=total_orders,
                           most_sold=most_sold,
                           today_sales=today_sales,
                           sales_history=sales_history)

@app.route('/admin/products')
def item_list():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('admin/item_list.html', products=products)

@app.route('/admin/view-product/<int:product_id>')
def view_item(product_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not product:
        flash("Product not found!", "danger")
        return redirect(url_for('item_list'))
        
    return render_template('admin/view_item.html', product=product)

@app.route('/admin/update-product/<int:product_id>', methods=['GET', 'POST'])
def update_item(product_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('category')
        price = request.form.get('price')
        stock = request.form.get('stock')
        description = request.form.get('description')
        file = request.files.get('image')
        
        cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
        product = cursor.fetchone()
        
        image_name = product['image']
        
        if file and file.filename != '':
            # Delete old image if it exists
            if image_name and image_name != 'default_product.png':
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            image_name = secure_filename(f"prod_upd_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_name))
            
        cursor.execute("UPDATE products SET name=?, category=?, price=?, stock=?, description=?, image=? WHERE product_id=?",
                       (name, category, price, stock, description, image_name, product_id))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Product updated successfully!", "success")
        return redirect(url_for('item_list'))

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return render_template('admin/update_item.html', product=product)

@app.route('/admin/delete-product/<int:product_id>')
def delete_item(product_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get image name to delete file
    cursor.execute("SELECT image FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()
    
    if product:
        if product['image'] and product['image'] != 'default_product.png':
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], product['image'])
            if os.path.exists(image_path):
                os.remove(image_path)
                
        cursor.execute("DELETE FROM products WHERE product_id = ?", (product_id,))
        conn.commit()
        flash("Product deleted successfully!", "success")
    
    cursor.close()
    conn.close()
    return redirect(url_for('item_list'))

@app.route('/admin/orders')
def admin_orders():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all orders with user names
    cursor.execute("""
        SELECT o.*, u.name as user_name, u.email as user_email 
        FROM orders o 
        JOIN users u ON o.user_id = u.user_id 
        ORDER BY o.created_at DESC
    """)
    orders = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return render_template('admin/orders.html', orders=orders)

@app.route('/admin/order/<string:order_id>')
def admin_order_details(order_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get Order Info
    cursor.execute("""
        SELECT o.*, u.name as user_name, u.email as user_email 
        FROM orders o 
        JOIN users u ON o.user_id = u.user_id 
        WHERE o.order_id = ?
    """, (order_id,))
    order = cursor.fetchone()
    
    if not order:
        flash("Order not found!", "danger")
        return redirect(url_for('admin_orders'))
        
    # Get Order Items
    cursor.execute("""
        SELECT oi.*, p.name, p.image 
        FROM order_items oi 
        JOIN products p ON oi.product_id = p.product_id 
        WHERE oi.order_id = ?
    """, (order_id,))
    order_items = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return render_template('admin/order_details.html', order=order, items=order_items)

@app.route('/admin/update-status/<string:order_id>', methods=['POST'])
def update_order_status(order_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
        
    status = request.form.get('status')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = ? WHERE order_id = ?", (status, order_id))
    conn.commit()
    cursor.close()
    conn.close()
    
    flash(f"Order status updated to {status}!", "success")
    return redirect(url_for('admin_order_details', order_id=order_id))

# --- SUPER ADMIN AUTH ROUTES ---

@app.route('/superadmin/signup', methods=['GET', 'POST'])
def superadmin_signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if email exists
        cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
        if cursor.fetchone():
            flash("Email already registered!", "danger")
            return redirect(url_for('superadmin_signup'))
        
        # Insert Super Admin (Automatically Approved)
        cursor.execute("INSERT INTO admin (name, email, password, role, status) VALUES (?, ?, ?, 'superadmin', 'Approved')", 
                       (name, email, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Super Admin account created successfully! Please login.", "success")
        return redirect(url_for('superadmin_login'))
        
    return render_template('superadmin/superadmin_signup.html')

@app.route('/superadmin/login', methods=['GET', 'POST'])
def superadmin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ? AND role = 'superadmin'", (email,))
        admin = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if admin and bcrypt.check_password_hash(admin['password'], password):
            session['admin_id'] = admin['admin_id']
            session['admin_name'] = admin['name']
            session['admin_role'] = admin['role']
            session['profile_image'] = admin['profile_image'] or 'default.png'
            flash(f"Welcome back, Super Admin {admin['name']}!", "success")
            return redirect(url_for('superadmin_dashboard'))
        else:
            flash("Invalid super admin email or password", "danger")
            
    return render_template('superadmin/superadmin_login.html')

@app.route('/superadmin/forgot-password', methods=['GET', 'POST'])
def superadmin_forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ? AND role = 'superadmin'", (email,))
        admin = cursor.fetchone()
        
        if admin:
            token = secrets.token_urlsafe(32)
            cursor.execute("UPDATE admin SET reset_token = ? WHERE email = ?", (token, email))
            conn.commit()
            
            reset_link = url_for('superadmin_reset_password', token=token, _external=True)
            
            try:
                msg = Message('SmartCart Super Admin - Password Reset Link', 
                              sender=app.config['MAIL_USERNAME'], 
                              recipients=[email])
                msg.body = f"Hello {admin['name']},\n\nPlease click the link below to reset your super admin password:\n\n{reset_link}\n\nIf you did not request this, please ignore this email."
                mail.send(msg)
                flash("Reset link sent to your email!", "success")
            except Exception as e:
                print(f"Mail Error: {e}")
                flash("Error sending email.", "danger")
        else:
            flash("Super Admin email not found!", "danger")
            
        cursor.close()
        conn.close()
        return redirect(url_for('superadmin_login'))
            
    return render_template('superadmin/forgot_password.html')

@app.route('/superadmin/reset-password/<token>', methods=['GET', 'POST'])
def superadmin_reset_password(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE reset_token = ? AND role = 'superadmin'", (token,))
    admin = cursor.fetchone()
    
    if not admin:
        flash("Invalid or expired token!", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('superadmin_forgot_password'))
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        cursor.execute("UPDATE admin SET password = ?, reset_token = NULL WHERE reset_token = ?", 
                       (hashed_password, token))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Super Admin password reset successful! Please login.", "success")
        return redirect(url_for('superadmin_login'))
        
    cursor.close()
    conn.close()
    return render_template('superadmin/reset_password.html', token=token)

@app.route('/superadmin/profile', methods=['GET', 'POST'])
def superadmin_profile():
    if session.get('admin_role') != 'superadmin':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('superadmin_login'))
    
    admin_id = session['admin_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        file = request.files.get('profile_image')
        
        # Current admin data to get old image name
        cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
        admin = cursor.fetchone()
        
        profile_image = admin['profile_image']
        
        # Handle Image Upload
        if file and file.filename != '':
            filename = secure_filename(f"superadmin_{admin_id}_{file.filename}")
            file_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Delete old image if it exists and is not default
            if profile_image and profile_image != 'default.png':
                old_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], profile_image)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            profile_image = filename

        # Handle Password Update
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute("UPDATE admin SET name=?, email=?, password=?, profile_image=? WHERE admin_id=?",
                           (name, email, hashed_password, profile_image, admin_id))
        else:
            cursor.execute("UPDATE admin SET name=?, email=?, profile_image=? WHERE admin_id=?",
                           (name, email, profile_image, admin_id))
        
        conn.commit()
        
        # Update Session
        session['admin_name'] = name
        session['profile_image'] = profile_image or 'default.png'
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for('superadmin_profile'))

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return render_template('superadmin/profile.html', admin=admin)

# --- SUPER ADMIN ROUTES ---

@app.route('/superadmin/dashboard')
def superadmin_dashboard():
    if session.get('admin_role') != 'superadmin':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('admin_login'))
        
    from datetime import datetime
    now = datetime.now()
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Global Stats
    cursor.execute("SELECT SUM(total_amount) as total FROM orders WHERE status IN ('Paid', 'Delivered')")
    total_revenue = cursor.fetchone()['total'] or 0
    
    cursor.execute("SELECT COUNT(*) as count FROM admin WHERE role = 'admin'")
    total_admins = cursor.fetchone()['count'] or 0
    
    cursor.execute("SELECT COUNT(*) as count FROM orders")
    total_orders = cursor.fetchone()['count'] or 0
    
    cursor.execute("SELECT COUNT(*) as count FROM products")
    total_products = cursor.fetchone()['count'] or 0
    
    # Recent Admin Requests
    cursor.execute("SELECT * FROM admin WHERE status = 'Pending' LIMIT 5")
    pending_admins = cursor.fetchall()
    
    # NEW: Revenue by Admin for Graph
    cursor.execute("""
        SELECT a.name as admin_name, SUM(o.total_amount) as revenue
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        JOIN products p ON oi.product_id = p.product_id
        JOIN admin a ON p.admin_id = a.admin_id
        WHERE o.status IN ('Paid', 'Delivered')
        GROUP BY a.admin_id
    """)
    admin_revenue_graph = cursor.fetchall()
    
    # NEW: Order Status Distribution for Graph
    cursor.execute("SELECT status, COUNT(*) as count FROM orders GROUP BY status")
    order_status_dist = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('superadmin/dashboard.html', 
                           revenue=total_revenue, 
                           admins=total_admins, 
                           orders=total_orders, 
                           products=total_products,
                           pending_admins=pending_admins,
                           admin_revenue_graph=admin_revenue_graph,
                           order_status_dist=order_status_dist,
                           now=now)

@app.route('/superadmin/admins')
def superadmin_admins():
    if session.get('admin_role') != 'superadmin':
        return redirect(url_for('admin_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE role = 'admin' ORDER BY created_at DESC")
    admins = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('superadmin/admins.html', admins=admins)

@app.route('/superadmin/approve-admin/<int:admin_id>/<string:action>')
def approve_admin(admin_id, action):
    if session.get('admin_role') != 'superadmin':
        return redirect(url_for('admin_login'))
        
    status = 'Approved' if action == 'approve' else 'Rejected'
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get Admin Email before updating
    cursor.execute("SELECT email, name FROM admin WHERE admin_id = ?", (admin_id,))
    target_admin = cursor.fetchone()
    
    cursor.execute("UPDATE admin SET status = ? WHERE admin_id = ?", (status, admin_id))
    conn.commit()
    
    # Send Notification to the Admin
    if target_admin:
        try:
            msg = Message(f'SmartCart Admin Account - {status}', 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[target_admin['email']])
            
            if status == 'Approved':
                msg.body = f"Hello {target_admin['name']},\n\nYour admin account registration has been APPROVED. You can now login to the admin panel.\n\nLink: {url_for('admin_login', _external=True)}\n\nRegards,\nSmartCart Team"
            else:
                msg.body = f"Hello {target_admin['name']},\n\nYour admin account registration request has been REJECTED. Please contact the developer for more information.\n\nRegards,\nSmartCart Team"
            
            mail.send(msg)
        except Exception as e:
            print(f"Error sending status email: {e}")

    cursor.close()
    conn.close()
    
    flash(f"Admin account {status} successfully!", "success")
    return redirect(url_for('superadmin_admins'))

@app.route('/superadmin/products')
def superadmin_products():
    if session.get('admin_role') != 'superadmin':
        return redirect(url_for('admin_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.*, a.name as admin_name 
        FROM products p 
        LEFT JOIN admin a ON p.admin_id = a.admin_id 
        ORDER BY p.created_at DESC
    """)
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('superadmin/products.html', products=products)

@app.route('/superadmin/orders')
def superadmin_orders():
    if session.get('admin_role') != 'superadmin':
        return redirect(url_for('admin_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT o.*, u.name as user_name 
        FROM orders o 
        JOIN users u ON o.user_id = u.user_id 
        ORDER BY o.created_at DESC
    """)
    orders = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('superadmin/orders.html', orders=orders)

@app.route('/superadmin/revenue')
def superadmin_revenue():
    if session.get('admin_role') != 'superadmin':
        return redirect(url_for('admin_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Revenue by Admin
    cursor.execute("""
        SELECT a.name as admin_name, SUM(o.total_amount) as revenue
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        JOIN products p ON oi.product_id = p.product_id
        JOIN admin a ON p.admin_id = a.admin_id
        WHERE o.status IN ('Paid', 'Delivered')
        GROUP BY a.admin_id
    """)
    admin_revenue = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return render_template('superadmin/revenue.html', admin_revenue=admin_revenue)

# --- USER ROUTES (Day 9) ---

@app.route('/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if email exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            flash("Email already registered!", "danger")
            return redirect(url_for('user_signup'))
        
        # Insert user
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                       (name, email, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('user_login'))
        
    return render_template('user/user_register.html')

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['user_id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            session['user_profile_image'] = user['profile_image'] or 'default.png'
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid email or password", "danger")
            
    return render_template('user/user_login.html')

@app.route('/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash("Please login to access your dashboard.", "warning")
        return redirect(url_for('user_login'))
    
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Fetch all products for general sections
    cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
    products = cursor.fetchall()
    
    # 2. Recommendation Logic
    # Get categories from user's orders
    cursor.execute("""
        SELECT DISTINCT p.category 
        FROM order_items oi
        JOIN products p ON oi.product_id = p.product_id
        JOIN orders o ON oi.order_id = o.order_id
        WHERE o.user_id = ?
    """, (user_id,))
    order_categories = [row['category'] for row in cursor.fetchall()]
    
    # Get categories from user's wishlist
    cursor.execute("""
        SELECT DISTINCT p.category 
        FROM wishlist w
        JOIN products p ON w.product_id = p.product_id
        WHERE w.user_id = ?
    """, (user_id,))
    wishlist_categories = [row['category'] for row in cursor.fetchall()]
    
    # Combine and deduplicate preferred categories
    preferred_categories = list(set(order_categories + wishlist_categories))
    
    recommended_products = []
    if preferred_categories:
        # Fetch products from preferred categories that the user hasn't bought yet (or just from those categories)
        query = "SELECT * FROM products WHERE category IN (%s) ORDER BY RANDOM() LIMIT 8" % (
            ",".join(["'%s'" % c for c in preferred_categories])
        )
        cursor.execute(query)
        recommended_products = cursor.fetchall()
    
    # Fallback if no recommendations found
    if not recommended_products:
        recommended_products = products[6:14] if len(products) > 14 else products[:8]
        
    cursor.close()
    conn.close()
        
    return render_template('user/user_home.html', products=products, recommended_products=recommended_products)

@app.route('/logout')
def user_logout():
    # Preserve cart before clearing session
    cart = session.get('cart', {})
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)
    session.pop('user_profile_image', None)
    session.pop('checkout_info', None)
    session.pop('selected_checkout_items', None)
    # Restore cart so items are still there on next login
    if cart:
        session['cart'] = cart
    flash("You have been logged out.", "success")
    return redirect(url_for('user_login'))

# --- SHOP & PRODUCT ROUTES (Day 10) ---

@app.route('/shop')
def shop():
    search_query = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM products WHERE 1=1"
    params = []
    
    if search_query:
        query += " AND (name LIKE ? OR description LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
    
    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)
        
    query += " ORDER BY created_at DESC"
    
    cursor.execute(query, tuple(params))
    products = cursor.fetchall()
    
    # Get all categories for filter
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = [row['category'] for row in cursor.fetchall()]
    
    cursor.close()
    conn.close()
    
    return render_template('user/shop.html', products=products, categories=categories, 
                           search_query=search_query, selected_category=category_filter)

@app.route('/product/<int:product_id>')
def product_details(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()
    
    # Get related products
    if product:
        cursor.execute("SELECT * FROM products WHERE category = ? AND product_id != ? LIMIT 4", 
                       (product['category'], product_id))
        related_products = cursor.fetchall()
    else:
        related_products = []
        
    cursor.close()
    conn.close()
    
    if not product:
        flash("Product not found!", "danger")
        return redirect(url_for('shop'))
        
    return render_template('user/product_details.html', product=product, related_products=related_products)

@app.route('/wishlist')
def view_wishlist():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
        
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT p.* 
        FROM wishlist w 
        JOIN products p ON w.product_id = p.product_id 
        WHERE w.user_id = ?
    """, (user_id,))
    products = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return render_template('user/wishlist.html', products=products)

@app.route('/add-to-wishlist/<int:product_id>')
def add_to_wishlist(product_id):
    if 'user_id' not in session:
        flash("Please login to manage your wishlist.", "warning")
        return redirect(url_for('user_login'))
        
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)", (user_id, product_id))
        conn.commit()
        flash("Product added to wishlist!", "success")
    except:
        flash("Product is already in your wishlist.", "info")
        
    cursor.close()
    conn.close()
    return redirect(request.referrer or url_for('shop'))

@app.route('/remove-from-wishlist/<int:product_id>')
def remove_from_wishlist(product_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
        
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM wishlist WHERE user_id = ? AND product_id = ?", (user_id, product_id))
    conn.commit()
    
    cursor.close()
    conn.close()
    flash("Removed from wishlist.", "success")
    return redirect(request.referrer or url_for('view_wishlist'))

# --- CART ROUTES (Day 11) ---

@app.route('/add-to-cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash("Please login to add items to cart.", "warning")
        return redirect(url_for('user_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not product:
        flash("Product not found!", "danger")
        return redirect(url_for('shop'))
        
    if product['stock'] <= 0:
        flash("Sorry, this product is out of stock.", "danger")
        return redirect(request.referrer or url_for('shop'))
    
    # Initialize cart if it doesn't exist
    if 'cart' not in session:
        session['cart'] = {}
        
    cart = session['cart']
    pid = str(product_id)
    
    if pid in cart:
        if cart[pid]['quantity'] >= product['stock']:
            flash(f"Cannot add more. Only {product['stock']} left in stock.", "warning")
        else:
            cart[pid]['quantity'] += 1
            flash(f"{product['name']} added to cart!", "success")
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }
        flash(f"{product['name']} added to cart!", "success")
        
    session['cart'] = cart
    session.modified = True
    return redirect(request.referrer or url_for('shop'))

@app.route('/buy-now/<int:product_id>')
def buy_now(product_id):
    if 'user_id' not in session:
        flash("Please login to purchase items.", "warning")
        return redirect(url_for('user_login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if product:
        if product['stock'] <= 0:
            flash("Sorry, this product is out of stock.", "danger")
            return redirect(request.referrer or url_for('shop'))
            
        session['cart'] = {
            str(product_id): {
                'name': product['name'],
                'price': float(product['price']),
                'image': product['image'],
                'quantity': 1
            }
        }
        session.modified = True
        return redirect(url_for('checkout'))
    
    return redirect(url_for('shop'))

@app.route('/cart')
def view_cart():
    if 'user_id' not in session:
        flash("Please login to view your cart.", "warning")
        return redirect(url_for('user_login'))
        
    cart = session.get('cart', {})
    total_price = sum(item['price'] * item['quantity'] for item in cart.values())
    
    return render_template('user/cart.html', cart=cart, total_price=total_price)

@app.route('/update-cart/<string:product_id>/<string:action>')
def update_cart(product_id, action):
    if 'cart' not in session:
        return redirect(url_for('view_cart'))
        
    cart = session['cart']
    
    if product_id in cart:
        if action == 'increase':
            cart[product_id]['quantity'] += 1
        elif action == 'decrease':
            cart[product_id]['quantity'] -= 1
            if cart[product_id]['quantity'] <= 0:
                cart.pop(product_id)
        elif action == 'remove':
            cart.pop(product_id)
            
    session['cart'] = cart
    session.modified = True
    return redirect(url_for('view_cart'))

@app.route('/clear-cart')
def clear_cart():
    session.pop('cart', None)
    flash("Cart cleared!", "success")
    return redirect(url_for('view_cart'))

# --- FORGOT PASSWORD ROUTES ---

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if user:
            token = secrets.token_urlsafe(32)
            cursor.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, email))
            conn.commit()
            
            reset_link = url_for('reset_password', token=token, _external=True)
            
            try:
                msg = Message('SmartCart - Password Reset Link', 
                              sender=app.config['MAIL_USERNAME'], 
                              recipients=[email])
                msg.body = f"Hello {user['name']},\n\nPlease click the link below to reset your password:\n\n{reset_link}\n\nIf you did not request this, please ignore this email."
                mail.send(msg)
                flash("Reset link sent to your email!", "success")
            except Exception as e:
                print(f"Mail Error: {e}")
                flash("Error sending email.", "danger")
        else:
            flash("Email not found!", "danger")
            
        cursor.close()
        conn.close()
        return redirect(url_for('user_login'))
            
    return render_template('user/forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
    user = cursor.fetchone()
    
    if not user:
        flash("Invalid or expired token!", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        cursor.execute("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?", 
                       (hashed_password, token))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Password reset successful! Please login.", "success")
        return redirect(url_for('user_login'))
        
    cursor.close()
    conn.close()
    return render_template('user/reset_password.html', token=token)

@app.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
        admin = cursor.fetchone()
        
        if admin:
            token = secrets.token_urlsafe(32)
            cursor.execute("UPDATE admin SET reset_token = ? WHERE email = ?", (token, email))
            conn.commit()
            
            reset_link = url_for('admin_reset_password', token=token, _external=True)
            
            try:
                msg = Message('SmartCart Admin - Password Reset Link', 
                              sender=app.config['MAIL_USERNAME'], 
                              recipients=[email])
                msg.body = f"Hello {admin['name']},\n\nPlease click the link below to reset your admin password:\n\n{reset_link}\n\nIf you did not request this, please ignore this email."
                mail.send(msg)
                flash("Reset link sent to your email!", "success")
            except Exception as e:
                print(f"Mail Error: {e}")
                flash("Error sending email.", "danger")
        else:
            flash("Admin email not found!", "danger")
            
        cursor.close()
        conn.close()
        return redirect(url_for('admin_login'))
            
    return render_template('admin/forgot_password.html')

@app.route('/admin/reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE reset_token = ?", (token,))
    admin = cursor.fetchone()
    
    if not admin:
        flash("Invalid or expired token!", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('admin_forgot_password'))
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        cursor.execute("UPDATE admin SET password = ?, reset_token = NULL WHERE reset_token = ?", 
                       (hashed_password, token))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Admin password reset successful! Please login.", "success")
        return redirect(url_for('admin_login'))
        
    cursor.close()
    conn.close()
    return render_template('admin/reset_password.html', token=token)

# --- RAZORPAY PAYMENT ROUTES (Day 12) ---

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        flash("Please login to checkout.", "warning")
        return redirect(url_for('user_login'))
        
    cart = session.get('cart', {})
    if not cart:
        flash("Your cart is empty!", "warning")
        return redirect(url_for('shop'))

    # Filter cart based on selection if coming from cart page
    selected_ids = request.form.getlist('selected_items')
    if selected_ids:
        # Save selection in session for payment_success
        session['selected_checkout_items'] = selected_ids
        filtered_cart = {pid: item for pid, item in cart.items() if str(pid) in selected_ids}
    elif 'selected_checkout_items' in session:
        # Retrieve previously saved selection
        selected_ids = session['selected_checkout_items']
        filtered_cart = {pid: item for pid, item in cart.items() if str(pid) in selected_ids}
    else:
        # Default to full cart if no selection specified (backward compatibility)
        filtered_cart = cart
        
    if not filtered_cart:
        flash("No items selected for checkout!", "warning")
        return redirect(url_for('view_cart'))

    total_amount = sum(item['price'] * item['quantity'] for item in filtered_cart.values())
    amount_in_paise = int(total_amount * 100)
    
    # Fetch saved addresses for this user
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, created_at DESC", (user_id,))
    saved_addresses = cursor.fetchall()
    cursor.close()
    conn.close()
    
    if request.method == 'POST':
        # Check if user selected a saved address or entered a new one
        address_id = request.form.get('address_id')
        
        if address_id:
            # User selected a saved address
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM addresses WHERE address_id = ? AND user_id = ?", (address_id, user_id))
            addr = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not addr:
                flash("Invalid address selected.", "danger")
                return render_template('user/checkout.html', total_amount=total_amount, step='address', saved_addresses=saved_addresses)
            
            # Build full address string
            full_address = f"{addr['full_name']}\n{addr['address_line1']}"
            if addr['address_line2']:
                full_address += f"\n{addr['address_line2']}"
            full_address += f"\n{addr['city']} - {addr['pincode']}\n{addr['state']}"
            
            session['checkout_info'] = {'address': full_address, 'phone': addr['phone']}
        else:
            # User entered a new address
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            address_line1 = request.form.get('address_line1')
            address_line2 = request.form.get('address_line2', '')
            city = request.form.get('city')
            state = request.form.get('state')
            pincode = request.form.get('pincode')
            label = request.form.get('label', 'Home')
            save_address = request.form.get('save_address')
            
            if not full_name or not phone or not address_line1 or not city or not state or not pincode:
                flash("Please fill in all required address fields.", "warning")
                return render_template('user/checkout.html', total_amount=total_amount, step='address', saved_addresses=saved_addresses)
            
            # Save to DB if user opted in
            if save_address:
                conn = get_db_connection()
                cursor = conn.cursor()
                # If no other addresses, make this default
                is_default = 1 if len(saved_addresses) == 0 else 0
                cursor.execute("""
                    INSERT INTO addresses (user_id, label, full_name, phone, address_line1, address_line2, city, state, pincode, is_default)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (user_id, label, full_name, phone, address_line1, address_line2, city, state, pincode, is_default))
                conn.commit()
                cursor.close()
                conn.close()
            
            full_address = f"{full_name}\n{address_line1}"
            if address_line2:
                full_address += f"\n{address_line2}"
            full_address += f"\n{city} - {pincode}\n{state}"
            
            session['checkout_info'] = {'address': full_address, 'phone': phone}
        
        # Create Razorpay Order
        data = {
            "amount": amount_in_paise,
            "currency": "INR",
            "payment_capture": "1"
        }
        
        try:
            razorpay_order = razorpay_client.order.create(data=data)
            razorpay_order_id = razorpay_order['id']
            return render_template('user/checkout.html', 
                                   order_id=razorpay_order_id, 
                                   amount=amount_in_paise,
                                   total_amount=total_amount,
                                   key_id=app.config['RAZORPAY_KEY_ID'],
                                   user_name=session.get('user_name'),
                                   user_email=session.get('user_email'),
                                   step='payment')
        except Exception as e:
            print(f"Razorpay Error: {e}")
            flash("Error initializing payment gateway.", "danger")
            return redirect(url_for('view_cart'))
            
    # Step 1: Show address selection/form
    return render_template('user/checkout.html', total_amount=total_amount, step='address', saved_addresses=saved_addresses)

@app.route('/payment-success', methods=['POST'])
def payment_success():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
        
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')
    
    # 1. VERIFY SIGNATURE
    params_dict = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }
    
    try:
        # 1. VERIFY SIGNATURE (Enhanced Manual Check)
        import hmac
        import hashlib
        
        # Calculate expected signature
        msg = f"{razorpay_order_id}|{razorpay_payment_id}"
        secret = app.config['RAZORPAY_KEY_SECRET']
        
        expected_signature = hmac.new(
            key=secret.encode('utf-8'),
            msg=msg.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest()
        
        if expected_signature != razorpay_signature:
            # Try SDK verification as second chance
            client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))
            client.utility.verify_payment_signature(params_dict)
            
    except Exception as e:
        print(f"--- RAZORPAY VERIFICATION FAILED ---")
        print(f"Error: {e}")
        print(f"Received Order ID: {razorpay_order_id}")
        print(f"Received Payment ID: {razorpay_payment_id}")
        flash("Payment security verification failed. Please check your credentials.", "danger")
        return redirect(url_for('view_cart'))

    # 2. SAVE ORDER TO DATABASE
    try:
        full_cart = session.get('cart', {})
        selected_ids = session.get('selected_checkout_items')
        
        if selected_ids:
            cart = {pid: item for pid, item in full_cart.items() if str(pid) in selected_ids}
        else:
            cart = full_cart

        total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
        user_id = session.get('user_id')
        checkout_info = session.get('checkout_info', {})
        shipping_address = checkout_info.get('address', 'N/A')
        phone = checkout_info.get('phone', 'N/A')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (order_id, user_id, total_amount, shipping_address, phone, payment_id, status)
            VALUES (?, ?, ?, ?, ?, ?, 'Paid')
        """, (razorpay_order_id, user_id, total_amount, shipping_address, phone, razorpay_payment_id))
        
        # Insert items into order_items table
        for product_id, item in cart.items():
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, quantity, price)
                VALUES (?, ?, ?, ?)
            """, (razorpay_order_id, product_id, item['quantity'], item['price']))
            
            # Reduce stock
            cursor.execute("UPDATE products SET stock = stock - ? WHERE product_id = ?", 
                           (item['quantity'], product_id))
            
        conn.commit()
        cursor.close()
        conn.close()
        
        # Remove ONLY selected items from the main cart
        if selected_ids:
            for pid in selected_ids:
                if pid in full_cart:
                    full_cart.pop(pid)
            session['cart'] = full_cart
        else:
            session.pop('cart', None)
            
        session.pop('selected_checkout_items', None)
        session.pop('checkout_info', None)
        
        # Redirect to a GET-accessible success page
        return redirect(url_for('order_success', order_id=razorpay_order_id))
        
    except Exception as e:
        print(f"--- DATABASE ERROR DURING ORDER SAVE ---")
        print(f"Error: {e}")
        flash("Payment received but error saving order details. Please contact support.", "danger")
        return redirect(url_for('my_orders'))

@app.route('/user/order-success/<string:order_id>')
def order_success(order_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
        
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get Order Info
    cursor.execute("SELECT * FROM orders WHERE order_id = ? AND user_id = ?", (order_id, user_id))
    result = cursor.fetchone()
    order = dict(result) if result else None
    
    if not order:
        flash("Order not found!", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('my_orders'))
        
    # Get Order Items
    cursor.execute("""
        SELECT oi.*, p.name 
        FROM order_items oi 
        JOIN products p ON oi.product_id = p.product_id 
        WHERE oi.order_id = ?
    """, (order_id,))
    order['order_items'] = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return render_template('user/order_success.html', order=order)

@app.route('/my-orders')
def my_orders():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
        
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all orders for this user
    cursor.execute("""
        SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC
    """, (user_id,))
    orders = [dict(row) for row in cursor.fetchall()]
    
    # Get items for each order
    for order in orders:
        cursor.execute("""
            SELECT oi.*, p.name, p.image 
            FROM order_items oi 
            JOIN products p ON oi.product_id = p.product_id 
            WHERE oi.order_id = ?
        """, (order['order_id'],))
        order['order_items'] = cursor.fetchall()
        
    cursor.close()
    conn.close()
    
    return render_template('user/my_orders.html', orders=orders)

@app.route('/track-order/<string:order_id>')
def track_order(order_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
        
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get Order Info
    cursor.execute("SELECT * FROM orders WHERE order_id = ? AND user_id = ?", (order_id, user_id))
    order = cursor.fetchone()
    
    if not order:
        flash("Order not found!", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('my_orders'))
        
    # Get Order Items
    cursor.execute("""
        SELECT oi.*, p.name, p.image 
        FROM order_items oi 
        JOIN products p ON oi.product_id = p.product_id 
        WHERE oi.order_id = ?
    """, (order_id,))
    items = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return render_template('user/track_order.html', order=order, items=items)

from utils.pdf_generator import render_to_pdf
from flask import make_response

@app.route('/download-invoice/<string:order_id>')
def download_invoice(order_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
        
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get Order Details
    cursor.execute("SELECT * FROM orders WHERE order_id = ? AND user_id = ?", (order_id, user_id))
    result = cursor.fetchone()
    order = dict(result) if result else None
    
    if not order:
        flash("Order not found!", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('my_orders'))
        
    # Get Order Items
    cursor.execute("""
        SELECT oi.*, p.name 
        FROM order_items oi 
        JOIN products p ON oi.product_id = p.product_id 
        WHERE oi.order_id = ?
    """, (order_id,))
    order['order_items'] = cursor.fetchall()
    
    # Get User Details
    cursor.execute("SELECT name, email FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    # Render HTML for PDF
    html_content = render_template('user/invoice_template.html', order=order, user=user)
    
    # Generate PDF
    pdf_data = render_to_pdf(html_content)
    
    if pdf_data:
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=invoice_{order_id}.pdf'
        return response
    
    flash("Error generating invoice.", "danger")
    return redirect(url_for('my_orders'))

@app.route('/about')
def about():
    return render_template('user/about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        try:
            msg = Message(f"Contact Query: {subject}",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[app.config['MAIL_USERNAME']]) # Sending to developer mail
            msg.body = f"Message from {name} ({email}):\n\n{message}"
            mail.send(msg)
            flash("Your query has been sent successfully! We will get back to you soon.", "success")
        except Exception as e:
            print(f"Mail Error: {e}")
            flash("Error sending your query. Please try again later.", "danger")
            
        return redirect(url_for('contact'))
        
    return render_template('user/contact.html')

# --- ADDRESS MANAGEMENT ROUTES ---

@app.route('/user/addresses')
def user_addresses():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
    
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, created_at DESC", (user_id,))
    addresses = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('user/addresses.html', addresses=addresses)

@app.route('/user/add-address', methods=['POST'])
def add_address():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
    
    user_id = session.get('user_id')
    label = request.form.get('label', 'Home')
    full_name = request.form.get('full_name')
    phone = request.form.get('phone')
    address_line1 = request.form.get('address_line1')
    address_line2 = request.form.get('address_line2', '')
    city = request.form.get('city')
    state = request.form.get('state')
    pincode = request.form.get('pincode')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if this is the first address
    cursor.execute("SELECT COUNT(*) as count FROM addresses WHERE user_id = ?", (user_id,))
    count = cursor.fetchone()['count']
    is_default = 1 if count == 0 else 0
    
    cursor.execute("""
        INSERT INTO addresses (user_id, label, full_name, phone, address_line1, address_line2, city, state, pincode, is_default)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, label, full_name, phone, address_line1, address_line2, city, state, pincode, is_default))
    conn.commit()
    cursor.close()
    conn.close()
    
    flash("Address added successfully!", "success")
    # Redirect back to where user came from
    return redirect(request.referrer or url_for('user_addresses'))

@app.route('/user/delete-address/<int:address_id>')
def delete_address(address_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
    
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM addresses WHERE address_id = ? AND user_id = ?", (address_id, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    
    flash("Address deleted.", "success")
    return redirect(request.referrer or url_for('user_addresses'))

@app.route('/user/set-default-address/<int:address_id>')
def set_default_address(address_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
    
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Remove default from all
    cursor.execute("UPDATE addresses SET is_default = 0 WHERE user_id = ?", (user_id,))
    # Set new default
    cursor.execute("UPDATE addresses SET is_default = 1 WHERE address_id = ? AND user_id = ?", (address_id, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    
    flash("Default address updated!", "success")
    return redirect(request.referrer or url_for('user_addresses'))

@app.route('/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session:
        flash("Please login to view your profile.", "warning")
        return redirect(url_for('user_login'))
        
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        file = request.files.get('profile_image')
        
        # Get current user data for old image
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        current_user = cursor.fetchone()
        profile_image = current_user['profile_image']
        
        # Handle Image Upload
        if file and file.filename != '':
            filename = secure_filename(f"user_{user_id}_{file.filename}")
            file_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Delete old image if it exists and is not default
            if profile_image and profile_image != 'default.png':
                old_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], profile_image)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            profile_image = filename
        
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute("UPDATE users SET name=?, email=?, password=?, profile_image=? WHERE user_id=?",
                           (name, email, hashed_password, profile_image, user_id))
        else:
            cursor.execute("UPDATE users SET name=?, email=?, profile_image=? WHERE user_id=?",
                           (name, email, profile_image, user_id))
                           
        conn.commit()
        
        session['user_name'] = name
        session['user_email'] = email
        session['user_profile_image'] = profile_image or 'default.png'
        flash("Profile updated successfully!", "success")
        return redirect(url_for('user_profile'))
        
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return render_template('user/profile.html', user=user)

# Start the application
if __name__ == '__main__':
    # Ensure upload folders exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['ADMIN_UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['USER_UPLOAD_FOLDER'], exist_ok=True)
    
    app.run(debug=True)
