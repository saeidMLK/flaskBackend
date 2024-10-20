import json
import math
import os
from collections import defaultdict
import bson
from werkzeug.utils import secure_filename
import pandas as pd
from config import ConfigApp
from flask_cors import CORS
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from bson.objectid import ObjectId
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify, session
from forms import LoginForm, SignUpForm, RemoveUserForm, ExtractDBForm, AddLabelForm, ReadOneRowDataForm, \
    ReportTaskForm, ConflictSearchForm, SetDataConfigForm, ImportDBForm, AddAverageLabelForm, AddDataToCollectionForm, \
    AssignCollectionToUserForm, RemoveDataCollectionForm
from models import find_user, add_user, check_password, find_user_by_id, remove_user_by_name, get_all_users, \
    extract_db_collection, read_one_row_of_data, add_label_to_data, get_user_performance, get_first_conflict_row, \
    set_admin_label_for_conflicts, set_data_configs, import_db_collection, convert_oid, \
    rename_collection_if_exist, get_user_labels, get_db_collection_names, get_user_collection, \
    calculate_and_set_average_label, get_recent_labels, update_label, get_label_options, get_collection_users, \
    get_user_role, get_top_users, get_data_states, set_data_state, insert_data_into_collection, \
    assign_collection_to_user, get_supervisor_s_users, remove_data_collection
from extensions import sanitize_input, generate_captcha, clear_old_captchas  # , limiter
# Import the api.py to include API routes
import api
from extensions import csrf, login_manager  # Import CSRF and login manager from extensions.py


app = Flask(__name__)
app.config.from_object(ConfigApp)
CORS(app, resources={r"/*": {"origins": ConfigApp.CORS_ORIGINS}}, supports_credentials=True)
# csrf = CSRFProtect(app)  # to prevent CSRF attacks
csrf.init_app(app)  # Initialize CSRF protection with the app
# limiter.init_app(app)

# app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
# jwt = JWTManager(app)

# Initialize Flask-Login
# login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Import Blueprints and register them
from api import api_bp  # Import the blueprint from api.py
app.register_blueprint(api_bp)  # Register the blueprint

@login_manager.user_loader
def load_user(user_id):
    return find_user_by_id(user_id)


@app.route('/home')
@app.route('/')
def home():
    # return render_template('main/home.html')
    # ignore welcome page and go directly to login
    return redirect(url_for('login'))


# Global dictionary to track login attempts
login_attempts = {}
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    username = form.username.data  # Capture username for tracking

    # Initialize login attempts for the username if not already done
    if username not in login_attempts:
        login_attempts[username] = 0

    # Generate CAPTCHA only if login attempts >= 1
    captcha_text, captcha_path = None, None
    if login_attempts[username] > 0:
        captcha_text, captcha_path = generate_captcha()

    if request.method == 'POST':
        # # Update the captcha validation based on login attempts
        # form.validate_captcha = lambda field: form.validate_captcha(field, login_attempts[username])

        # Validate the form including the CAPTCHA if required
        if form.validate_on_submit():
            # Check if CAPTCHA is required (for failed attempts)
            if login_attempts[username] > 0:
                entered_captcha = form.captcha.data.lower() if form.captcha.data else None
                actual_captcha = request.form.get('captcha_text').lower() if request.form.get('captcha_text') else None

                if entered_captcha != actual_captcha:
                    flash('کلمات تصویر به درستی وارد نشده، دوباره تلاش کنید!', 'danger')
                    return render_template('registration/login.html', form=form, captcha_text=captcha_text, captcha_image_url=captcha_path)

            # Proceed with normal authentication
            sanitized_username = sanitize_input(form.username.data)
            user = find_user(sanitized_username)
            if user and check_password(user, form.password.data):
                login_user(user)
                login_attempts[username] = 0  # Reset login attempts on successful login
                role = user.role
                if role == 'admin':
                    flash(f'ورود موفق، دسترسی مدیر!', 'success')
                    return redirect(url_for('admin'))
                elif role == 'supervisor':
                    flash(f'ورود موفق، دسترسی سوپروایزر!', 'success')
                    return redirect(url_for('admin_db_management'))
                else:
                    flash(f'ورود موفق، دسترسی کاربر!', 'success')
                    return redirect(url_for('user'))
            else:
                # Increment login attempts on failed password/username match
                login_attempts[username] += 1
                flash('نام کاربری یا کلمه عبور اشتباه است.', 'danger')
        else:
            flash('Form validation failed. Please try again.', 'danger')

    # Render the login page with CAPTCHA if required
    return render_template('registration/login.html', form=form, captcha_text=captcha_text, captcha_image_url=captcha_path)


@app.route('/sign-up', methods=['GET', 'POST'])
# @limiter.limit("1 per minute")
def sign_up():
    form = SignUpForm()  # Create an instance of the sign-up form
    collections_choices = form.set_collections_choices()  # Ensure collections choices are set before form validation
    if form.validate_on_submit():
        # Process the form data (e.g., save user to database)
        sanitized_username = sanitize_input(form.username.data)
        # Get the selected collections from the hidden input
        selected_collections = request.form.get('collections', '')  # Comma-separated string
        collections_list = selected_collections.split(',') if selected_collections else []
        # print(collections_list)
        if add_user(sanitized_username, form.password.data, collections_list, form.role.data, current_user.username):
            flash('ایجاد کاربر جدید با موفقیت انجام شد.', 'success')
            return redirect(url_for('admin_user_management'))
        else:
            flash('ناموفق', 'danger')
        return redirect(url_for('sign_up'))
    # else:
    # flash('Form validation failed. Please try again.', 'danger')
    return render_template('registration/sign_up.html', form=form, collections_choices=collections_choices)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('شما با موفقیت خارج شدید.', 'success')
    return redirect(url_for('home'))


def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        @login_required
        def decorated_view(*args, **kwargs):
            if current_user.role not in roles:
                flash('شما به این صفحه دسترسی ندارید، لطفا وارد شوید.', 'danger')
                return redirect(url_for('home'))
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


@app.route('/admin', methods=['GET', 'POST'])
@role_required('admin')
def admin():
    # return render_template('access/admin/admin_base.html')
    # ignore welcome page for admin and go directly to db management
    return redirect(url_for('admin_db_management'))


@app.route('/admin_user_management', methods=['GET', 'POST'])
@role_required('admin', 'supervisor')
def admin_user_management():
    assign_collection_to_user_form = AssignCollectionToUserForm()
    remove_user_form = RemoveUserForm()
    # loading users to user management form as an initialisation.
    role = current_user.role
    if role == 'supervisor':
        collections = get_user_collection(current_user.username)
        assign_collection_to_user_form.data_collection.choices = [(name, name) for name in collections]
        users = get_supervisor_s_users(current_user.username)
    else:
        collections = get_db_collection_names(sys_collections_included=0)
        assign_collection_to_user_form.data_collection.choices = [(name, name) for name in collections]
        users = get_all_users()

    assign_collection_to_user_form.data_collection.choices = [(name, name) for name in collections]
    if users:
        remove_user_form.username.choices = [(user.username, f"{user.username} -- {user.role}") for user in users]
        assign_collection_to_user_form.username.choices = [(user.username, user.username) for user in users if user.role == 'user']
    else:
        flash('کاربری یافت نشد.', 'warning')
        remove_user_form = None

    if assign_collection_to_user_form.validate_on_submit():
        collection_name = assign_collection_to_user_form.data_collection.data
        username = assign_collection_to_user_form.username.data
        assign_collection_to_user(username, collection_name)
        flash('داده با موفقیت اختصاص یافت.', 'success')

    # Categorize users by their roles
    categorized_users = defaultdict(list)
    for user in users:
        categorized_users[user.role].append(user.username)

    return render_template('access/admin/admin_user_management.html',
                           users=users,
                           remove_user_form=remove_user_form,
                           assign_collection_to_user_form=assign_collection_to_user_form,
                           admin_users=categorized_users.get('admin', []),
                           supervisor_users=categorized_users.get('supervisor', []),
                           user_users=categorized_users.get('user', []))


@app.route('/remove_user', methods=['POST'])
@role_required('admin', 'supervisor')
def remove_user():
    users = get_all_users()
    remove_user_form = RemoveUserForm()
    if users:
        remove_user_form.username.choices = [(user.username, f"{user.username} -- {user.role}") for user in users]
    if remove_user_form.validate_on_submit():
        username = remove_user_form.username.data
        if remove_user_by_name(username):
            flash('کابر با موفقیت حذف شد.', 'success')
        else:
            flash('مدیر قابل حذف شدن نیست.', 'danger')
    else:
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('admin_user_management'))


@app.route('/admin_report', methods=['GET', 'POST'])
@role_required('admin', 'supervisor')
def admin_report():
    role = current_user.role
    report_task_form = ReportTaskForm()

    if role == 'supervisor':
        collections = get_user_collection(current_user.username)
        report_task_form.collection.choices = [(name, name) for name in collections]
        collection_0 = collections[0]
    else:
        collection_names_0 = get_db_collection_names(sys_collections_included=0)
        report_task_form.collection.choices = [(name, name) for name in collection_names_0]
        collection_0 = collection_names_0[0]

    collection = report_task_form.collection.data or collection_0

    users = get_collection_users(collection)
    if users:
        report_task_form.username.choices = [user.username for user in users]
    else:
        report_task_form.username.choices = ['--کاربری یافت نشد--']
    report_data = {}
    page = request.args.get('page', 1, type=int)
    per_page = 10
    # username = None
    if report_task_form.validate_on_submit():
        username = report_task_form.username.data
        if 'labels' in request.form:
            number_of_labels, consensus_degree, label_percentage = get_user_performance(username, collection)
            report_data = {
                'type': 'labels',
                'username': username,
                'number_of_labels': number_of_labels,
                'label_percentage': label_percentage,
                'consensus_degree': consensus_degree
            }
        if 'data' in request.form:
            rows, total_rows = get_user_labels(username, collection, page, per_page)
            total_pages = math.ceil(total_rows / per_page)
            report_data = {
                'type': 'data',
                'username': username,
                'total_pages': total_pages,
                'page': page,
                'per_page': per_page,
                'rows': rows
            }
        if 'users_report' in request.form:
            users_report_data = {}
            # print(users)
            for user in users:
                # print(type(user.username))
                number_of_labels, consensus_degree, label_percentage = get_user_performance(user.username, collection)
                users_report_data[user.username] = {'label_percentage': label_percentage,
                                                    'consensus_degree': consensus_degree}
            report_data = {
                'type': 'users_report',
                'username': 'همه افراد',
                'users_report_data': users_report_data
            }
    else:
        # Handle the case when navigating through pages without form submission
        username = request.args.get('username')
        report_task_form.username.data = username
        if username:
            rows, total_rows = get_user_labels(username, page, per_page)
            total_pages = math.ceil(total_rows / per_page)
            report_data = {
                'type': 'data',
                'username': username,
                'rows': rows,
                'total_pages': total_pages,
                'page': page,
                'per_page': per_page
            }
    top_users = get_top_users()
    return render_template('access/admin/admin_report.html', users=users, report_task_form=report_task_form,
                           report_data=report_data, collection=collection, top_users=top_users)


@app.route('/get_users_by_collection', methods=['POST'])
@role_required('admin')
def get_users_by_collection():
    collection = request.form.get('collection')
    print(f"Received Collection: {collection}")  # Debugging output

    users = get_collection_users(collection)
    user_list = [user.username for user in users] if users else ['--کاربری یافت نشد.--']

    print(f"User List: {user_list}")  # Debugging output

    return jsonify(users=user_list)


@app.route('/get_users/<collection_name>', methods=['GET'])
@role_required('admin')
def get_users(collection_name):
    users = get_collection_users(collection_name)
    user_choices = [user.username for user in users]
    return jsonify(user_choices)


@app.route('/admin_db_management', methods=['GET', 'POST'])
@role_required('admin', 'supervisor')
def admin_db_management():
    import_db_form = ImportDBForm()
    extract_db_form = ExtractDBForm()
    add_average_label_form = AddAverageLabelForm()
    conflict_search_form = ConflictSearchForm()
    set_data_config_form = SetDataConfigForm()
    add_data_to_collection_form = AddDataToCollectionForm()
    remove_data_collection_form = RemoveDataCollectionForm()
    # Fetch the latest collection names
    if current_user.role == 'supervisor':
        collections = get_user_collection(current_user.username)
        extract_db_form.collection_name.choices = [(name, name) for name in collections]
        data_states = get_data_states(current_user.username)
    else:
        collections = get_db_collection_names(sys_collections_included=0)
        collection_names_1 = get_db_collection_names(sys_collections_included=1)
        extract_db_form.collection_name.choices = [(name, name) for name in collection_names_1]
        data_states = get_data_states('admin')

    add_average_label_form.data_collection.choices = [(name, name) for name in collections]
    conflict_search_form.data_collection.choices = [(name, name) for name in collections]
    set_data_config_form.data_collection.choices = [(name, name) for name in collections]
    add_data_to_collection_form.data_collection.choices = [(name, name) for name in collections]
    remove_data_collection_form.data_collection.choices = [(name, name) for name in collections]
    # users = get_all_users()
    extracted = request.args.get('extracted', False)
    # For downloading the collection.
    if collections:
        selected_collection = request.args.get('collection_name', collections[0])
    else:
        selected_collection = []

    conflict_row = None
    threshold = 0.7  # Default value
    if request.method == 'POST':
        if 'search' in request.form:
            collection = conflict_search_form.data_collection.data
            conflict_search_form.hidden_collection.data = collection  # Store collection in hidden field
            conflict_search_form.set_label_choices(collection)  # Set label choices based on selected collection
            threshold = float(request.form.get('threshold', 0.5))
            conflict_row = get_first_conflict_row(collection, threshold)
        elif 'set_label' in request.form:
            collection = request.form.get('hidden_collection')  # Retrieve collection from hidden field
            conflict_search_form.data_collection.data = collection  # Repopulate form field
            conflict_search_form.set_label_choices(collection)  # Set label choices based on selected collection
            threshold = float(request.form.get('hidden_threshold', 0.5))  # Retrieve the threshold from the hidden field

            if conflict_search_form.validate_on_submit():
                label = conflict_search_form.label.data
                row_id = request.form.get('row_id')
                if row_id:
                    try:
                        row_id = ObjectId(row_id)
                        if set_admin_label_for_conflicts(collection, row_id, label):
                            flash('برچسب با موفقیت افزوده شد.', 'success')
                        else:
                            flash('Failed to set label.', 'danger')
                    except bson.errors.InvalidId:
                        flash('Invalid row ID.', 'danger')
                else:
                    flash('No row ID provided.', 'danger')
                conflict_row = get_first_conflict_row(collection,
                                                      threshold)  # Retrieve the next conflict row with the threshold
            else:
                flash('Form validation failed.', 'danger')

        elif 'save_labels' in request.form:
            if set_data_config_form.validate_on_submit():
                labels = set_data_config_form.labels.data
                data_collection = set_data_config_form.data_collection.data
                num_required_labels = set_data_config_form.num_required_labels.data
                if set_data_configs(data_collection, labels, num_required_labels):
                    set_data_state(data_collection)
                    flash('تنظیمات داده با موفقیت بروزرسانی شدند.', 'success')
                    return redirect(url_for('admin_db_management'))
                else:
                    flash('Failed to update data config.', 'danger')
            else:
                flash('Failed to update data config. Form is not validate_on_submit', 'danger')

        elif 'remove_collection' in request.form:
            if remove_data_collection_form.validate_on_submit():
                collection = remove_data_collection_form.data_collection.data
                # update_user_scores = remove_data_collection_form.update_user_scores.data
                if remove_data_collection(collection):
                    flash('حذف مجموعه داده با موفقیت انجام شد.', 'success')
                    return redirect(url_for('admin_db_management'))
                else:
                    flash('Failed to remove data collection.', 'danger')
            else:
                flash('Failed to remove data collection. Form is not validate_on_submit', 'danger')
    return render_template('access/admin/admin_db_management.html',
                           collection_name=selected_collection,
                           import_db_form=import_db_form,
                           extract_db_form=extract_db_form,
                           extracted=extracted,
                           add_data_to_collection_form=add_data_to_collection_form,
                           add_average_label_form=add_average_label_form,
                           conflict_search_form=conflict_search_form,
                           remove_data_collection_form=remove_data_collection_form,
                           set_data_config_form=set_data_config_form,
                           conflict_row=conflict_row,
                           # users=users,
                           threshold=threshold,  # Pass the threshold to the template
                           data_states=data_states)


@app.route('/add_average_label', methods=['POST'])
@role_required('admin', 'supervisor')
def add_average_label():
    add_average_label_form = AddAverageLabelForm()
    if add_average_label_form.validate_on_submit():
        collection_name = add_average_label_form.data_collection.data
        if calculate_and_set_average_label(collection_name):
            flash(f'برچسب تجمعی برای {collection_name} افزوده شد.', 'success')
        else:
            flash(f' برچسب تجمعی افزوده نشد! خطای تابع درج برچسب.', 'danger')
    else:
        flash(f'برچسب تجمعی افزوده نشد! خطای فرم ارسالی.', 'danger')
    return redirect(url_for('admin_db_management'))


@app.route('/extract_db', methods=['POST'])
@role_required('admin', 'supervisor')
def extract_db():
    extract_db_form = ExtractDBForm()
    if extract_db_form.validate_on_submit():
        collection_name = extract_db_form.collection_name.data
        path = f'static/db/db_{collection_name}.json'
        extract_db_collection(path, collection_name)
        flash(f' دسته بندی {collection_name}  با موفقیت استخراج شد.', 'success')
        return redirect(url_for('admin_db_management', extracted=True, collection_name=collection_name))
    else:
        flash('Failed to extract database.', 'danger')
    return redirect(url_for('admin_db_management'))


@app.route('/download_file/<collection_name>')
@role_required('admin', 'supervisor')
def download_file(collection_name):
    path = f'static/db/db_{collection_name}.json'  # Path to the saved file
    try:
        return send_file(path, as_attachment=True, download_name=f'extracted_{collection_name}.json')
    except FileNotFoundError:
        flash('The requested file was not found on the server.', 'danger')
        return redirect(url_for('admin_db_management'))


@app.route('/import_db', methods=['POST'])
@role_required( 'admin', 'supervisor')
def import_db():
    import_db_form = ImportDBForm()
    if import_db_form.validate_on_submit():
        file = import_db_form.file.data
        file_name_with_extension = secure_filename(file.filename)
        file_name, file_extension = os.path.splitext(file_name_with_extension)
        collection_title = import_db_form.title.data
        collection_title = secure_filename(collection_title)
        try:
            # Check if the collection already exists
            if collection_title in get_db_collection_names(sys_collections_included=1):
                flash(f'این عنوان داده از قبل وجود دارد.', 'warning')
                return redirect(url_for('admin_db_management'))

            # Handle JSON file
            if file_extension.lower() == '.json':
                data = json.load(file)
                data = convert_oid(data)  # Convert ObjectId if necessary
                import_db_collection(current_user.username, collection_title, data)
                flash(f'مجموعه داده {collection_title} با موفقیت به دیتابیس اضافه شد.', 'success')

            # Handle CSV file
            elif file_extension.lower() == '.csv':
                data = []
                print(1)
                df = pd.read_csv(file)
                data = df.to_dict(orient='records')
                print(2)
                import_db_collection(current_user.username, collection_title, data)
                flash(f'مجموعه داده {collection_title} با موفقیت به دیتابیس اضافه شد.', 'success')

            else:
                flash('فرمت فایل پشتیبانی نمی‌شود. فقط JSON و CSV مجاز هستند.', 'danger')
                return redirect(url_for('admin_db_management'))

        except Exception as e:
            flash(f'بارگذاری ناموفق: {e}', 'danger')
            return redirect(url_for('admin_db_management'))

    else:
        flash('بارگذاری ناموفق!', 'danger')

    return redirect(url_for('admin_db_management'))


@app.route('/add_data_to_collection', methods=['POST'])
@role_required('admin', 'supervisor')
def add_data_to_collection():
    add_data_to_collection_form = AddDataToCollectionForm()
    if add_data_to_collection_form.validate_on_submit():
        collection_name = add_data_to_collection_form.data_collection.data
        file = add_data_to_collection_form.file.data
        data = json.load(file)

        # Ensure the data is either a list or an object
        if not isinstance(data, (dict, list)):
            return jsonify({"error": "Uploaded file must contain a valid JSON object or an array of objects."}), 400
        # If the data is a single object, wrap it in a list to maintain consistency
        if isinstance(data, dict):
            data = [data]
        data = convert_oid(data)  # Convert ObjectId fields if necessary

        insert_data_into_collection(collection_name, data)

        flash(f'تعداد {len(data)} رکورد با موفقیت به مجموعه داده {collection_name} افزوده شد.', 'success')
    else:
        flash('بارگذاری ناموفق!', 'danger')

    return redirect(url_for('admin_db_management'))


@app.route('/user', methods=['GET', 'POST'])
@role_required('user')
@login_required
def user():
    collections = get_user_collection(current_user.username)
    add_label_form = AddLabelForm()
    read_one_row_form = ReadOneRowDataForm()

    if request.method == 'POST':
        # This handles the form submission from the collection buttons
        selected_collection = request.form.get('collection', collections[0])
    else:
        # This handles the redirect from the edit_label route or GET request
        selected_collection = request.args.get('selected_collection', collections[0])

    # Set the selected collection in the form
    read_one_row_form.collection.data = selected_collection

    add_label_form.set_label_choices(selected_collection)
    row = read_one_row_of_data(current_user.username, selected_collection)

    if row:
        read_one_row_form.username.data = current_user.username
        read_one_row_form.data.data = row['data']
        read_one_row_form.row_id.data = str(row['_id'])  # Pass the row ID to the form
        add_label_form.row_id.data = str(row['_id'])
        add_label_form.username.data = current_user.username
    else:
        read_one_row_form.data.data = "--None--"
        flash('همه داده ها توسط این کاربر برچسب گذاری شده است.', 'info')

    recent_labels = get_recent_labels(current_user.username, selected_collection)
    label_options = get_label_options(selected_collection)

    return render_template('access/user/user.html',
                           read_one_row_form=read_one_row_form,
                           add_label_form=add_label_form,
                           recent_labels=recent_labels,
                           label_options=label_options,
                           form=add_label_form,
                           user_collections=collections,
                           selected_collection=selected_collection)


@app.route('/edit_label', methods=['POST'])
@role_required('user')
@login_required
def edit_label():
    row_id = request.form['row_id']
    new_label_value = request.form['label_value']
    selected_collection = request.form.get('selected_collection')  # Retrieve the selected collection
    username = current_user.username

    if update_label(ObjectId(row_id), username, new_label_value, selected_collection):
        flash('برچسب با موفقیت ویرایش شد.', 'success')
    else:
        flash('ویرایش برچسب ناموفق بود.', 'danger')

    # Redirect with selected_collection as a URL parameter
    return redirect(url_for('user', selected_collection=selected_collection))


@app.route('/read_one_row_data', methods=['POST'])
@role_required('user')
@login_required
def read_one_row_data():
    read_one_row_form = ReadOneRowDataForm()
    if read_one_row_form.validate_on_submit():
        username = read_one_row_form.username.data
        row = read_one_row_of_data(username)
        if row:
            flash('داده با موفقیت بازیابی شد.', 'success')
            return redirect(url_for('user'))
    flash('استخراج از پایگاه داده ناموفق بود.', 'danger')
    return redirect(url_for('user'))


@app.route('/add_label', methods=['POST'])
@role_required('user')
@login_required
def add_label():
    selected_collection = request.form.get('selected_collection')  # Retrieve the selected collection
    add_label_form = AddLabelForm()
    # print(selected_collection)
    add_label_form.set_label_choices(selected_collection)
    if add_label_form.validate_on_submit():
        row_id = add_label_form.row_id.data
        username = add_label_form.username.data
        label = add_label_form.label.data
        if add_label_to_data(ObjectId(row_id), label, username, selected_collection):
            flash('برچسب با موفقیت اضافه شد.', 'success')
        else:
            flash('افزودن برچسب ناموفق بود.', 'danger')
    return redirect(url_for('user', selected_collection=selected_collection))


# @app.route('/supervisor_db_management', methods=['GET', 'POST'])
# @role_required('supervisor')
# @login_required
# def supervisor_db_management():
#     import_db_form = ImportDBForm()
#     extract_db_form = ExtractDBForm()
#     # admin_label_config_form = SetDataConfigForm()
#     add_average_label_form = AddAverageLabelForm()
#     conflict_search_form = ConflictSearchForm()
#     set_data_config_form = SetDataConfigForm()
#     add_data_to_collection_form = AddDataToCollectionForm()
#     # collection_names_0 = get_db_collection_names(sys_collections_included=0)
#     collections = get_user_collection(current_user.username)
#     extract_db_form.collection_name.choices = [(name, name) for name in collections]
#     add_average_label_form.data_collection.choices = [(name, name) for name in collections]
#     conflict_search_form.data_collection.choices = [(name, name) for name in collections]
#     set_data_config_form.data_collection.choices = [(name, name) for name in collections]
#     add_data_to_collection_form.data_collection.choices = [(name, name) for name in collections]
#     # extract_db_form.collection_name = collections
#     extracted = request.args.get('extracted', False)
#     if collections:
#         selected_collection = request.args.get('collection_name', collections[0])
#     else:
#         selected_collection = []
#     conflict_row = None
#     threshold = 0.7  # Default value
#     if request.method == 'POST':
#         if 'search' in request.form:
#             collection = conflict_search_form.data_collection.data
#             conflict_search_form.hidden_collection.data = collection  # Store collection in hidden field
#             conflict_search_form.set_label_choices(collection)  # Set label choices based on selected collection
#             threshold = float(request.form.get('threshold', 0.5))
#             conflict_row = get_first_conflict_row(collection, threshold)
#         elif 'set_label' in request.form:
#             collection = request.form.get('hidden_collection')  # Retrieve collection from hidden field
#             conflict_search_form.data_collection.data = collection  # Repopulate form field
#             conflict_search_form.set_label_choices(collection)  # Set label choices based on selected collection
#             threshold = float(request.form.get('hidden_threshold', 0.5))  # Retrieve the threshold from the hidden field
#
#             if conflict_search_form.validate_on_submit():
#                 label = conflict_search_form.label.data
#                 row_id = request.form.get('row_id')
#                 if row_id:
#                     try:
#                         row_id = ObjectId(row_id)
#                         if set_admin_label_for_conflicts(collection, row_id, label):
#                             flash('برچسب با موفقیت افزوده شد.', 'success')
#                         else:
#                             flash('Failed to set label.', 'danger')
#                     except bson.errors.InvalidId:
#                         flash('Invalid row ID.', 'danger')
#                 else:
#                     flash('No row ID provided.', 'danger')
#                 conflict_row = get_first_conflict_row(collection,
#                                                       threshold)  # Retrieve the next conflict row with the threshold
#             else:
#                 flash('Form validation failed.', 'danger')
#
#         elif 'save_labels' in request.form:
#             print(set_data_config_form.validate_on_submit())
#             if set_data_config_form.validate_on_submit():
#                 labels = set_data_config_form.labels.data
#                 data_collection = set_data_config_form.data_collection.data
#                 num_required_labels = set_data_config_form.num_required_labels.data
#                 if set_data_configs(data_collection, labels, num_required_labels):
#                     flash('تنظیمات داده با موفقیت بروزرسانی شدند.', 'success')
#                 else:
#                     flash('Failed to update data config.', 'danger')
#             else:
#                 flash('Failed to update data config. Form is not validate_on_submit', 'danger')
#     data_states = get_data_states(current_user.username)
#
#
#     return render_template('access/supervisor/supervisor_db_management.html',
#                            supervisor_collections=collections,
#                            selected_collection=selected_collection,
#                            import_db_form=import_db_form,
#                            extract_db_form=extract_db_form,
#                            extracted=extracted,
#                            add_data_to_collection_form=add_data_to_collection_form,
#                            # admin_label_config_form=admin_label_config_form,
#                            add_average_label_form=add_average_label_form,
#                            conflict_search_form=conflict_search_form,
#                            set_data_config_form=set_data_config_form,
#                            threshold=threshold,
#                            conflict_row=conflict_row,
#                            data_states=data_states)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4001)
# , ssl_context=(ConfigApp.cert, ConfigApp.key)
