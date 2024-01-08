from flask import Flask, render_template, request, redirect, url_for, flash
from config import SECRET_KEY, SQLALCHEMY_DATABASE_URI
from models import db, User, Role, user_roles
from forms import LoginForm
from auth import login_manager, load_user
from flask_login import login_required, logout_user, current_user, AnonymousUserMixin, login_user

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Function to insert the predefined "admin" user
def insert_admin_user():
    admin = User.query.filter_by(username='admin').first()
    if admin is None:
        admin = User(username='admin', password='admin')  # Replace 'admin' with the actual hashed password
        admin_role = Role(name='admin')
        db.session.add(admin)
        db.session.add(admin_role)
        db.session.commit()
        admin = User.query.filter_by(username='admin').first()
        admin_role = Role.query.filter_by(name='admin').first()
        admin_role_connection = user_roles.insert().values(role_id=admin_role.id, user_id=admin.id)
        db.session.execute(admin_role_connection)
        db.session.commit()
    

def has_role(role_name):
    user_roles_data = db.session.query(user_roles).filter_by(user_id=current_user.id).all()
    roles = [Role.query.get(user_role.role_id).name for user_role in user_roles_data]
    return role_name in roles


@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Assuming you have a LoginForm class defined
    if request.method == 'POST' and form.validate_on_submit():
        next_url = request.args.get('next')
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user)
            flash('Login successful', 'success')
            if username == 'admin' and password == 'admin' :
                return redirect(url_for('admin'))
            else :
                if next_url:
                    return redirect(next_url)  # Redirect to the original page if 'next' exists
                else:
                    return redirect(url_for('home'))  # Redirect to a default page if 'next' is not set

        else:
            flash('Login failed. Please check your username and password.', 'danger')

    return render_template('login.html', form=form)  # Pass the form to the template

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.username == 'admin':
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            selected_role_ids = request.form.getlist('roles')  # Get selected role IDs as a list
            existing_user = User.query.filter_by(username=username).first()

            if not existing_user:
                new_user = User(username=username, password=password)
                db.session.add(new_user)
                # Now that the new_user has been added to the database, you can get its id
                new_user = User.query.filter_by(username=username).first()
                new_user_id = new_user.id

                # Create user-role associations
                for role_id in selected_role_ids:
                    role = Role.query.get(role_id)
                    user_role = user_roles.insert().values(role_id=role_id, user_id=new_user_id)
                    db.session.execute(user_role)

                db.session.commit()
                flash('User added successfully', 'success')
            else:
                flash('Username already exists. Please choose a different one.', 'danger')

        users = User.query.all()
        roles = Role.query.all()  # Retrieve all available roles for the form
        user_roles_data = db.session.query(user_roles).all()  # Query all user-role associations

        return render_template('admin.html', users=users, roles=roles, user_roles=user_roles_data)
    else:
        return render_template('reject.html')

@app.route('/add_role', methods=['POST'])
@login_required
def add_role():
    if current_user.username == 'admin':
        role_name = request.form['role_name']
        if not Role.query.filter_by(name=role_name).first():
            new_role = Role(name=role_name)
            db.session.add(new_role)
            db.session.commit()
            flash(f'Role "{role_name}" added successfully', 'success')
        else:
            flash(f'Role "{role_name}" already exists. Please choose a different name.', 'danger')
    else:
        flash('Access denied. You are not authorized to add roles.', 'danger')

    return redirect(url_for('admin'))

@app.route('/door1')
def door1():
    if isinstance(current_user, AnonymousUserMixin):
        return redirect(url_for('login', next=request.path))  # Store the target URL

    # Check IPs
    user_ip = request.remote_addr
    approved_ip = '127.0.0.1' # finds local host ip address. For real use, set value to local wifi/VPN ip address 
    
    if user_ip == approved_ip:
        if has_role("door1"):
            print("doors opened")
            return render_template("accept.html")
        else :
            print("doors closed")
            return render_template('reject.html')
    else:
        print("doors closed, wrong ip")
        return render_template('reject.html')
    
@app.route('/door2')
def door2():
    if isinstance(current_user, AnonymousUserMixin):
        return redirect(url_for('login', next=request.path))  # Store the target URL

    # Check IPs
    user_ip = request.remote_addr
    approved_ip = '127.0.0.1' # finds local host ip address. For real use, set value to local wifi/VPN ip address 
    
    if user_ip == approved_ip:
        if has_role("door1"):
            print("doors opened")
            return render_template("accept.html")
        else :
            print("doors closed")
            return render_template('reject.html')
    else:
        print("doors closed, wrong ip")
        return render_template('reject.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        insert_admin_user()
    app.run(debug=True)