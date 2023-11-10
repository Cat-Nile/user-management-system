from flask import Flask, render_template, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_session import Session


app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ums.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "edf11f3beb5d1ba8ccc30ee2"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = 'filesystem'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)
Migrate(app, db)

# User Class
class User(db.Model):
    """_summary_

    Args:
        db (_type_): _description_
    """
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(255), nullable=False)
    lname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    edu = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'User({self.id},{self.fname},{self.lname},{self.email},{self.edu},{self.username}, {self.status}, {self.is_admin})'

# Main index
@app.route('/')
def index():
    """Index

    Returns:
        _type_: _description_
    """
    return render_template('index.html', title="")


# ----------------------- user area -------------------------
# User Login
@app.route('/user/', methods=["POST", "GET"])
def user_index():
    """_User Login_

    Returns:
        _type_: _description_
    """
    if session.get('user_id'):
        return redirect('dashboard')
    
    if request.method == "POST":
        # Get the name of the field
        email = request.form.get('email')
        password = request.form.get('password')
        
        # check user exists in this email or not
        users = User.query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password, password):
            # check the admin approve your account are not
            is_approved = User.query.filter_by(id=users.id).first()
            if is_approved.status == 0:
                flash('Your account is not approved yet by administrator', 'danger')
                return redirect('/user/')
            else:
                session['user_id'] = users.id
                session['username'] = users.username
                flash('Login successful', 'success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Email and password', 'danger')
            return redirect('/user/')

    else:
        return render_template('user/index.html', title="User Login")


# User Register
@app.route('/user/signup', methods=['POST', 'GET'])
def user_signup():
    """_summary_

    Returns:
        _type_: _description_
    """
    if session.get('user_id'):
        return redirect('user/dashboard')
    
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        edu = request.form.get('edu')
        password = request.form.get('password')
        
        # check all the field is filled are not
        if fname == "" or lname == "" or email == "" or username == "" or edu == "" or password == "":
            flash('Please fill all the field', 'danger')
            return redirect('/user/signup')
        else:
            is_email = User.query.filter_by(email=email).first()
            if is_email:
                flash('Email already exists', 'danger')
                return redirect('/user/signup')
            else:
                hash_password = bcrypt.generate_password_hash(password, 10)
                user = User(fname=fname, lname=lname, email=email, password=hash_password, edu=edu, username=username)
                db.session.add(user)
                db.session.commit()
                flash('Account created successfully, Admin will approve your account in 10 to 30 minutes', 'success')
                return redirect('/user/')
    else:
        return render_template('user/signup.html', title="User Signup")


# user dashboard
@app.route('/user/dashboard')
def user_dashboard():
    """User Dashboard

    Returns:
        _type_: _description_
    """
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/user/')

    users = User.query.filter_by(id=user_id).first()        
    return render_template('user/dashboard.html', title="User Dashboard", users=users)


# user logout
@app.route('/user/logout')
def user_logout():
    """Logout

    Returns:
        _type_: _description_
    """
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        return redirect('/user/')


@app.route('/user/change-password', methods=["POST", "GET"])
def change_password():
    """Change Password

    Returns:
        _type_: _description_
    """
    if not session.get('user_id'):
        return redirect('/user/')

    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        if email == "" or password == "":
            flash('Please fill the field', 'danger')
            return redirect('/user/change-password')
        else:
            users = User.query.filter_by(email=email).first()
            if users:
                hashed_password = bcrypt.generate_password_hash(password, 10)
                users.password = hashed_password
                db.session.commit()
                flash('Password changed successfully', 'success')
                return redirect('/user/')
            else:
                flash('Invalid email entered!', 'danger')
                return redirect('/user/change-password')
    else:
        return render_template('user/change-password.html', title="Change Password")


@app.route('/user/update-profile', methods=["POST", "GET"])
def update_profile():
    """Update User Profile Information

    Returns:
        _type_: _description_
    """
    if not session.get('user_id'):
        return redirect('/user/')
    else:
        user_id = session.get('user_id')

    users = User.query.get(user_id)

    if request.method == "POST":
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        username = request.form.get('username')
        email = request.form.get('email')
        edu = request.form.get('edu')

        if fname == "" or lname == "" or username == "" or email == "" or edu == "":
            flash('Please fill all the field', 'danger')
            return redirect('/user/update-profile')
        else:
            users.fname = fname
            users.lname = lname
            users.email = email
            users.username = username
            users.edu = edu
            db.session.commit()
            flash('User profile is successfully updated', 'success')
            return redirect('/user/update-profile')
    else:
        return render_template('user/update-profile.html', title="Update User Profile", users=users)


# ----------------------- admin area -------------------------
# admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin Dashboard

    Returns:
        _type_: _description_
    """
    admin_id = session.get('admin_id')
    if not admin_id:
        return redirect('/admin/')
    total_user = User.query.count()
    approved = User.query.filter_by(status=1).count()
    disapproved = total_user - approved
    context = {
        'total': total_user,
        'approved': approved,
        'disapproved': disapproved
    }
    return render_template('admin/dashboard.html', title="Admin Dashboard", context=context)


# Admin page
@app.route('/admin/', methods=["POST", "GET"])
def admin_index():
    """_Admin login

    Returns:
        _type_: _description_
    """
    # check the request is post or not
    if request.method == "POST":
        # get the value of field
        username = request.form.get('username')
        password = request.form.get('password')
        # check the value is not empty
        if username == "" or password == "":
            flash('Please fill all the field', 'danger')
            return redirect('/admin/')

        admin = User.query.filter_by(username=username).first()
        is_matched = bcrypt.check_password_hash(admin.password, password)
        is_admin = admin.is_admin
        if is_matched:
            if is_admin:
                session['admin_id'] = admin.id
                session['admin_name'] = admin.username
                flash('Logined successfully', 'success')
                return redirect('/admin/dashboard')
            else:
                flash('Permission denied', 'danger')
                return redirect('/admin/')
        else:
            flash('Username and password is invalid', 'danger')
            return redirect('/admin/')
    else:
        return render_template('admin/index.html', title="Admin Login")


# Admin logout
@app.route('/admin/logout')
def admin_logout():
    """Admin Logout

    Returns:
        _type_: _description_
    """
    admin_id = session.get('admin_id')
    if not admin_id:
        return redirect('/admin/')

    session['admin_id'] = None
    session['admin_name'] = None
    return redirect('/')


# get all user list
@app.route('/admin/get-all-user', methods=["POST", "GET"])
def get_all_users():
    """User approval
    """
    admin_id = session.get('admin_id')
    if not admin_id:
        return redirect('/admin/')

    if request.method == "POST":
        search = request.form.get('search')
        users = User.query.filter(User.username.like('%'+search+'%')).all()
        return render_template('admin/all-user.html', title='Approve User', users=users)
 
    users = User.query.all()
    return render_template('admin/all-user.html', title="Approve User", users=users)


# Approve user
@app.route('/admin/approve-user/<int:user_id>')
def admin_approve(user_id):
    """Approve user
    """
    admin_id = session.get('admin_id')
    if not admin_id:
        return redirect('/admin/')

    users = User.query.filter_by(id=user_id).first()
    users.status = 1
    db.session.commit()

    flash('Approved successfully', 'success')
    return redirect('/admin/get-all-user')


# Change admin password
@app.route('/admin/change-password', methods=['POST', 'GET'])
def admin_change_password():
    """Admin Change Password
    """
    admin_id = session.get('admin_id')
    if not admin_id:
        flash('Login needed', 'danger')
        return redirect('/admin/')
    
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "" or password == "":
            flash("Please fill all the field.", 'danger')
            return redirect('/admin/change-password')

        admin = User.query.filter_by(username=username).first() 
        is_admin = admin.is_admin
        if not is_admin:
            flash('Permission denied', 'danger')
            return redirect('/admin/')
        admin.password = bcrypt.generate_password_hash(password, 10)
        db.session.commit()
        flash('Admin password is updated successfully', 'success')
        return redirect('/admin/dashboard')
    else:
        admin = User.query.filter_by(id=admin_id).first()
        return render_template('admin/admin-change-password.html', title="Admin Change Password", admin=admin)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)
