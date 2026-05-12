import os

class Config:
    # Flask Secret Key
    SECRET_KEY = 'your_secret_key_here'
    
    # SQLite Database Configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database', 'smartcart.db')
    DATABASE_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database', 'smartcart.db')

    
    # Upload Configurations
    UPLOAD_FOLDER = os.path.join('static', 'uploads', 'product_images')
    ADMIN_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'admin_profiles')
    USER_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'user_profiles')
    
    # Flask-Mail Configuration (for Day 2 OTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'rohith252002@gmail.com'
    MAIL_PASSWORD = 'rjiv ntoj evmz ymgl'
    
    # Razorpay Configuration
    RAZORPAY_KEY_ID = 'rzp_test_SiQRg8Dlz7Jy1N'
    RAZORPAY_KEY_SECRET = 'zAH1RdHfw9zJkfnK6Njwgu3H'
