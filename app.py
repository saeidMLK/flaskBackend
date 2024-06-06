import json
import bson
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from forms import LoginForm, SignUpForm, RemoveUserForm, ExtractDBForm, AddLabelForm, ReadOneRowDataForm, \
    ReportTaskForm, ConflictSearchForm, AdminLabelConfigForm, ImportDBForm
from models import find_user, add_user, check_password, find_user_by_id, remove_user_by_name, get_all_users, \
    extract_db_collection, read_one_row_of_data, add_label_to_data, get_user_performance, get_first_conflict_row, \
    set_admin_label_for_conflicts, set_admin_label_config, import_db_collection, convert_oid, rename_collection_if_exist
from config import ConfigApp
from flask_cors import CORS
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from extensions import sanitize_input, generate_captcha, clear_old_captchas  # , limiter
from bson.objectid import ObjectId

app = Flask(__name__)
app.config.from_object(ConfigApp)
CORS(app, resources={r"/*": {"origins": app.config['CORS_ORIGINS']}}, supports_credentials=True)
csrf = CSRFProtect(app)  # to prevent CSRF attacks
# limiter.init_app(app)

# app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
# jwt = JWTManager(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return find_user_by_id(user_id)


@app.route('/home')
@app.route('/')
def home():
    return render_template('main/home.html')


# @limiter.limit("3 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    captcha_text, captcha_path = generate_captcha()
    if request.method == 'POST':
        if form.validate_on_submit():
            entered_captcha = form.captcha.data.lower()
            actual_captcha = request.form.get('captcha_text').lower()
            if entered_captcha == actual_captcha:
                sanitized_username = sanitize_input(form.username.data)
                user = find_user(sanitized_username)
                if user and check_password(user, form.password.data):
                    login_user(user)
                    role = user.role
                    if role == 'admin':
                        flash(f'Login successful, admin access!', 'success')
                        return redirect(url_for('admin'))
                    else:
                        flash(f'Login successful, user access!', 'success')
                        return redirect(url_for('user'))
                else:
                    flash('Invalid username or password', 'danger')
            else:
                flash('Invalid CAPTCHA. Please try again.', 'danger')
        else:
            flash('Form validation failed. Please try again.', 'danger')
    return render_template('registration/login.html', form=form, captcha_text=captcha_text, captcha_image_url=captcha_path)


@app.route('/sign-up', methods=['GET', 'POST'])
# @limiter.limit("1 per minute")
def sign_up():
    form = SignUpForm()  # Create an instance of the sign-up form
    if form.validate_on_submit():
        # Process the form data (e.g., save user to database)
        sanitized_username = sanitize_input(form.username.data)
        if add_user(sanitized_username, form.password.data, form.role.data):
            flash('Sign-up successful!', 'success')
        else:
            flash('Not successful', 'danger')
        return redirect(url_for('admin_user_management'))
    return render_template('registration/sign_up.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        @login_required
        def decorated_view(*args, **kwargs):
            if current_user.role != role:
                flash('You do not have access to this page. Login required!', 'danger')
                return redirect(url_for('home'))
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


@app.route('/admin', methods=['GET', 'POST'])
@role_required('admin')
def admin():
    return render_template('access/admin/admin_base.html')


@app.route('/admin_user_management', methods=['GET', 'POST'])
@role_required('admin')
def admin_user_management():
    users = get_all_users()
    remove_user_form = RemoveUserForm()
    # loading users to user management form as an initialisation.
    if users:
        remove_user_form.username.choices = [(user.username, f"{user.username} -- {user.role}") for user in users]
    else:
        flash('No users found.', 'warning')
        remove_user_form = None
    return render_template('access/admin/admin_user_management.html', users=users, remove_user_form=remove_user_form)


@app.route('/remove_user', methods=['POST'])
@role_required('admin')
def remove_user():
    users = get_all_users()
    remove_user_form = RemoveUserForm()
    if users:
        remove_user_form.username.choices = [(user.username, f"{user.username} -- {user.role}") for user in users]
    if remove_user_form.validate_on_submit():
        username = remove_user_form.username.data
        if remove_user_by_name(username):
            flash('User has been removed successfully.', 'success')
        else:
            flash('Admin cannot be removed!', 'danger')
    else:
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_user_management'))


@app.route('/admin_report', methods=['GET', 'POST'])
@role_required('admin')
def admin_report():
    users = get_all_users()
    report_task_form = ReportTaskForm()
    if users:
        report_task_form.username.choices = [(user.username, f"{user.username} -- {user.role}") for user in users]

    report_data = {}
    if report_task_form.validate_on_submit():
        username = report_task_form.username.data
        task = request.form['task']

        if task == 'labels':
            number_of_labels, consensus_degree = get_user_performance(username)
            report_data = {
                'type': 'labels',
                'username': username,
                'number_of_labels': number_of_labels,
                'consensus_degree': consensus_degree
            }
        elif task == 'updates':
            number_of_updates = 33
            report_data = {
                'type': 'updates',
                'username': username,
                'number_of_updates': number_of_updates
            }

    return render_template('access/admin/admin_report.html', users=users, report_task_form=report_task_form,
                           report_data=report_data)


@app.route('/admin_db_management', methods=['GET', 'POST'])
@role_required('admin')
def admin_db_management():
    users = get_all_users()
    conflict_search_form = ConflictSearchForm()
    conflict_search_form.set_label_choices()
    extract_db_form = ExtractDBForm()
    import_db_form = ImportDBForm()
    admin_label_config_form = AdminLabelConfigForm()
    extracted = request.args.get('extracted', False)
    collection_name = request.args.get('collection_name', '')
    conflict_row = None
    if request.method == 'POST':
        if 'search' in request.form:
            conflict_row = get_first_conflict_row()
        elif 'set_label' in request.form:
            if conflict_search_form.validate_on_submit():
                label = conflict_search_form.label.data
                row_id = request.form.get('row_id')
                if row_id:
                    try:
                        row_id = ObjectId(row_id)
                        if set_admin_label_for_conflicts(row_id, label):
                            flash('Label has been set successfully.', 'success')
                        else:
                            flash('Failed to set label.', 'danger')
                    except bson.errors.InvalidId:
                        flash('Invalid row ID.', 'danger')
                else:
                    flash('No row ID provided.', 'danger')
                conflict_row = get_first_conflict_row()  # Retrieve the next conflict row
            else:
                flash('Form validation failed.', 'danger')

        elif 'save_labels' in request.form:
            if admin_label_config_form.validate_on_submit():
                labels = admin_label_config_form.labels.data
                print('Received labels:', labels)
                if set_admin_label_config(labels):
                    flash('Labels have been updated successfully.', 'success')
                else:
                    flash('Failed to update labels.', 'danger')
            else:
                flash('Failed to update labels. Form is not validate_on_submit', 'danger')

    return render_template('access/admin/admin_db_management.html',
                           conflict_search_form=conflict_search_form,
                           conflict_row=conflict_row,
                           users=users,
                           extract_db_form=extract_db_form,
                           import_db_form=import_db_form,
                           admin_label_config_form=admin_label_config_form,
                           extracted=extracted,
                           collection_name=collection_name
                           )


@app.route('/extract_db', methods=['POST'])
@role_required('admin')
def extract_db():
    extract_db_form = ExtractDBForm()
    if extract_db_form.validate_on_submit():
        collection_name = extract_db_form.collection_name.data
        path = f'static/db/db_{collection_name}.json'
        extract_db_collection(path, collection_name)
        flash(f'The {collection_name} collection has been extracted successfully.', 'success')
        return redirect(url_for('admin_db_management', extracted=True, collection_name=collection_name))
    else:
        flash('Failed to extract database.', 'danger')
    return redirect(url_for('admin_db_management'))


@app.route('/download_file/<collection_name>')
@role_required('admin')
def download_file(collection_name):
    path = f'static/db/db_{collection_name}.json'  # Path to the saved file
    try:
        return send_file(path, as_attachment=True, download_name=f'extracted_{collection_name}.json')
    except FileNotFoundError:
        flash('The requested file was not found on the server.', 'danger')
        return redirect(url_for('admin_db_management'))


@app.route('/import_db', methods=['POST'])
@role_required('admin')
def import_db():
    import_db_form = ImportDBForm()
    if import_db_form.validate_on_submit():
        collection_name = import_db_form.collection_name.data
        file = import_db_form.file.data
        try:
            data = json.load(file)
            data = convert_oid(data)  # Convert ObjectId if necessary
            if rename_collection_if_exist(collection_name):
                flash(f'The collection exist and renamed to {collection_name}_old!', 'warning')
            import_db_collection(collection_name, data)
            flash(f'The {collection_name} collection has been imported successfully into the DB .', 'success')
        except Exception as e:
            flash(f'Failed to import data: {e}', 'danger')

        return redirect(url_for('admin_db_management'))
    else:
        flash('Failed to import database.', 'danger')
    return redirect(url_for('admin_db_management'))


@app.route('/user', methods=['GET', 'POST'])
@role_required('user')
@login_required
def user():
    add_label_form = AddLabelForm()
    add_label_form.set_label_choices()
    read_one_row_form = ReadOneRowDataForm()
    row = read_one_row_of_data(current_user.username)

    if row:
        read_one_row_form.username.data = current_user.username
        read_one_row_form.data.data = row['data']
        read_one_row_form.row_id.data = str(row['_id'])  # Pass the row ID to the form
        # Populate the AddLabelForm with the same data
        add_label_form.row_id.data = str(row['_id'])
        add_label_form.username.data = current_user.username
    else:
        read_one_row_form.data.data = "--None--"
        flash('All rows have been labeled by this account!', 'info')
    return render_template('access/user/user.html', read_one_row_form=read_one_row_form, add_label_form=add_label_form)


@app.route('/read_one_row_data', methods=['POST'])
@role_required('user')
@login_required
def read_one_row_data():
    read_one_row_form = ReadOneRowDataForm()
    if read_one_row_form.validate_on_submit():
        username = read_one_row_form.username.data
        row = read_one_row_of_data(username)
        if row:
            flash('Row has been retrieved successfully.', 'success')
            return redirect(url_for('user'))
    flash('Failed to extract from database.', 'danger')
    return redirect(url_for('user'))


@app.route('/add_label', methods=['POST'])
@role_required('user')
@login_required
def add_label():
    add_label_form = AddLabelForm()
    add_label_form.set_label_choices()
    if add_label_form.validate_on_submit():
        row_id = add_label_form.row_id.data
        username = add_label_form.username.data
        label = add_label_form.label.data
        if add_label_to_data(ObjectId(row_id), label, username):
            flash('Label has been added successfully.', 'success')
        else:
            flash('Failed to add label.', 'danger')
    return redirect(url_for('user'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=443, ssl_context=(ConfigApp.cert, ConfigApp.key))
