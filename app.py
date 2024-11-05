from flask import Flask, request, render_template, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy  # Import SQLAlchemy
import bcrypt
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from functools import wraps
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'manohar6299254553@gmail.com'
app.config['MAIL_PASSWORD'] = 'jyyzfpexrfrpcnmm'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'
db = SQLAlchemy(app)  # Initialize SQLAlchemy
mail = Mail(app)
app.secret_key = 'man_mn'
CORS(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)  # New field

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def __init__(self, username, email, password, is_admin=False):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.is_admin = is_admin

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    video_url = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # New field

    def __init__(self, title, description, video_url):
        self.title = title
        self.description = description
        self.video_url = video_url

with app.app_context():
    db.create_all()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        video_url = request.form['video_url']

        new_course = Course(title=title, description=description, video_url=video_url)
        db.session.add(new_course)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    admin = Users.query.filter_by(email=session['email']).first()
    courses = Course.query.filter(Course.created_at >= admin.registered_at).all()
    return render_template('admin_dashboard.html', courses=courses)

@app.route('/delete_course/<int:course_id>', methods=['POST'])
@admin_required  # Optional: Ensure only admins can delete
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)  # Find the course or return 404 if not found
    db.session.delete(course)  # Delete the course from the database
    db.session.commit()  # Save changes
    return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard

@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def edit_course(course_id):
    course = Course.query.get_or_404(course_id)

    if request.method == 'POST':
        course.title = request.form['title']
        course.description = request.form['description']
        course.video_url = request.form['video_url']

        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_course.html', course=course)

@app.route('/')
def get_start():
    return render_template('get_start.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Users.query.filter_by(email=email).first()

        if user:
            print(f"Found user: {user.email}")  # Debug user check
            if user.check_password(password):
                session['email'] = user.email
                session['username'] = user.username
                session['is_admin'] = user.is_admin
                print(f"Session after login: {session}")  # Debug session
                return redirect(url_for('home'))
            else:
                print("Invalid password!")  # Debug invalid password

        return render_template('login.html', error='Invalid credentials. Please try again.')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = request.form.get('is_admin') == 'on'  # Checkbox for admin

        existing_user = Users.query.filter_by(email=email).first()
        if existing_user:
            return render_template('register.html', error='Email already registered.')

        new_user = Users(username=username, email=email, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/navbar')
@login_required
def navbar():
    return render_template('navbar.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html')

@app.route('/services')
@login_required
def services():
    return render_template('services.html')

@app.route('/courses')
@login_required
def courses():
    all_courses = Course.query.all()  # Fetch all courses from the database
    return render_template('courses.html', courses=all_courses)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = Users.query.filter_by(email=email).first()

        if user:
            s = URLSafeTimedSerializer(app.secret_key)
            token = s.dumps(email, salt='email-reset-salt')
            reset_link = url_for('reset_with_token', token=token, _external=True)

            # Send email
            msg = Message('Password Reset Request',
                          recipients=[email])
            msg.body = f'Please click the link to reset your password: {reset_link}'
            mail.send(msg)

            return render_template('reset_password.html', message='Check your email for a password reset link.')
        else:
            return render_template('reset_password.html', error='Email not found. Please register or try a different email.')

    return render_template('reset_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    s = URLSafeTimedSerializer(app.secret_key)
    try:
        email = s.loads(token, salt='email-reset-salt', max_age=3600)
    except:
        return 'The reset link is invalid or has expired.'

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm-password']

        if new_password != confirm_password:
            return render_template('reset_with_token.html', token=token, error='Passwords do not match.')

        user = Users.query.filter_by(email=email).first()
        user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.session.commit()
        return redirect('/login')

    return render_template('reset_with_token.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('get_start'))

if __name__ == '__main__':
    app.run(debug=True)
