import json
import math
import os

import bson
from config import ConfigApp
from flask_cors import CORS
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from bson.objectid import ObjectId
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from forms import LoginForm, SignUpForm, RemoveUserForm, ExtractDBForm, AddLabelForm, ReadOneRowDataForm, \
    ReportTaskForm, ConflictSearchForm, AdminLabelConfigForm, ImportDBForm, AddAverageLabelForm
from models import find_user, add_user, check_password, find_user_by_id, remove_user_by_name, get_all_users, \
    extract_db_collection, read_one_row_of_data, add_label_to_data, get_user_performance, get_first_conflict_row, \
    set_admin_label_for_conflicts, set_admin_label_config, import_db_collection, convert_oid, \
    rename_collection_if_exist, get_user_labels, get_db_collection_names, get_user_collection, \
    calculate_and_set_average_label, get_recent_labels, update_label, get_label_options
from extensions import sanitize_input, generate_captcha, clear_old_captchas  # , limiter

app = Flask(__name__)
app.config.from_object(ConfigApp)
CORS(app, resources={r"/*": {"origins": ConfigApp.CORS_ORIGINS}}, supports_credentials=True)
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
                        flash(f'ورود موفق، دسترسی مدیر!', 'success')
                        return redirect(url_for('admin'))
                    else:
                        flash(f'ورود موفق، دسترسی کاربر!', 'success')
                        return redirect(url_for('user'))
                else:
                    flash('نام کاربری یا کلمه عبور اشتباه است.', 'danger')
            else:
                flash('کلمات تصوبر به درستی وارد نشده، دوباره تلاش کنید!', 'danger')
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
        if add_user(sanitized_username, form.password.data,form.collections.data, form.role.data):
            flash('ایجاد کاربر جدید با موفقیت انجام شد.', 'success')
        else:
            flash('ناموفق', 'danger')
        return redirect(url_for('admin_user_management'))
    return render_template('registration/sign_up.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('شما با موفقیت خارج شدید.', 'success')
    return redirect(url_for('home'))


def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        @login_required
        def decorated_view(*args, **kwargs):
            if current_user.role != role:
                flash('شما به این صفحه دسترسی ندارید، لطفا وارد شوید.', 'danger')
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
        flash('کاربری یافت نشد.', 'warning')
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
            flash('کابر با موفقیت حذف شد.', 'success')
        else:
            flash('مدیر قابل حذف شدن نیست.', 'danger')
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
    page = request.args.get('page', 1, type=int)
    per_page = 10
    username = None

    if report_task_form.validate_on_submit():
        username = report_task_form.username.data
        if 'labels' in request.form:
            number_of_labels, consensus_degree = get_user_performance(username)
            report_data = {
                'type': 'labels',
                'username': username,
                'number_of_labels': number_of_labels,
                'consensus_degree': consensus_degree
            }
        if 'data' in request.form:
            rows, total_rows = get_user_labels(username, page, per_page)
            total_pages = math.ceil(total_rows / per_page)
            report_data = {
                'type': 'data',
                'username': username,
                'total_pages': total_pages,
                'page': page,
                'per_page': per_page,
                'rows': rows
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

    return render_template('access/admin/admin_report.html', users=users, report_task_form=report_task_form,
                           report_data=report_data)


@app.route('/admin_db_management', methods=['GET', 'POST'])
@role_required('admin')
def admin_db_management():
    # Fetch the latest collection names
    collection_names = get_db_collection_names()
    users = get_all_users()
    conflict_search_form = ConflictSearchForm()
    extract_db_form = ExtractDBForm()
    import_db_form = ImportDBForm()
    admin_label_config_form = AdminLabelConfigForm()
    add_average_label_form = AddAverageLabelForm()
    extracted = request.args.get('extracted', False)
    collection_name = request.args.get('collection_name', '')   # For downloading the collection.
    conflict_row = None
    threshold = 0.5  # Default value
    # Set choices for forms that need collection names
    conflict_search_form.data_collection.choices = [(name, name) for name in collection_names]
    extract_db_form.collection_name.choices = [(name, name) for name in collection_names]
    admin_label_config_form.data_collection.choices = [(name, name) for name in collection_names]
    add_average_label_form.data_collection.choices = [(name, name) for name in collection_names]

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
                conflict_row = get_first_conflict_row(collection, threshold)  # Retrieve the next conflict row with the threshold
            else:
                flash('Form validation failed.', 'danger')

        elif 'save_labels' in request.form:
            if admin_label_config_form.validate_on_submit():
                labels = admin_label_config_form.labels.data
                data_collection = admin_label_config_form.data_collection.data
                if set_admin_label_config(data_collection, labels):
                    flash('برچسب ها با موفقیت بروزرسانی شدند.', 'success')
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
                           add_average_label_form=add_average_label_form,
                           extracted=extracted,
                           collection_name=collection_name,
                           threshold=threshold  # Pass the threshold to the template
                           )


@app.route('/add_average_label', methods=['POST'])
@role_required('admin')
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
@role_required('admin')
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
        # collection_name = import_db_form.collection_name.data
        file = import_db_form.file.data
        file_name_with_extension = file.filename
        file_name = os.path.splitext(file_name_with_extension)[0]
        print(file_name)
        try:
            data = json.load(file)
            data = convert_oid(data)  # Convert ObjectId if necessary
            if file_name in get_db_collection_names():
                flash(f'این مجموعه داده از قبل وجود دارد.', 'warning')
            else:
                import_db_collection(file_name, data)
                flash(f'مجموعه داده {file_name} با موفقیت به دیتابیس اضافه شد.', 'success')
        except Exception as e:
            flash(f'بارگذاری ناموفق: {e}', 'danger')

        return redirect(url_for('admin_db_management'))
    else:
        flash('بارگذاری ناموفق!', 'danger')
    return redirect(url_for('admin_db_management'))


# @app.route('/user', methods=['GET', 'POST'])
# @role_required('user')
# @login_required
# def user():
#     collection = get_user_collection(current_user.username)
#     add_label_form = AddLabelForm()
#     add_label_form.set_label_choices(collection)
#     read_one_row_form = ReadOneRowDataForm()
#     row = read_one_row_of_data(current_user.username)
#     if row:
#         read_one_row_form.username.data = current_user.username
#         read_one_row_form.data.data = row['data']
#         read_one_row_form.row_id.data = str(row['_id'])  # Pass the row ID to the form
#         # Populate the AddLabelForm with the same data
#         add_label_form.row_id.data = str(row['_id'])
#         add_label_form.username.data = current_user.username
#     else:
#         read_one_row_form.data.data = "--None--"
#         flash('همه داده ها توسط این کاربر برچسب گذاری شده است.', 'info')
#     return render_template('access/user/user.html', read_one_row_form=read_one_row_form, add_label_form=add_label_form)


@app.route('/user', methods=['GET', 'POST'])
@role_required('user')
@login_required
def user():
    collection = get_user_collection(current_user.username)
    add_label_form = AddLabelForm()
    add_label_form.set_label_choices(collection)
    read_one_row_form = ReadOneRowDataForm()
    row = read_one_row_of_data(current_user.username)
    if row:
        read_one_row_form.username.data = current_user.username
        read_one_row_form.data.data = row['data']
        read_one_row_form.row_id.data = str(row['_id'])  # Pass the row ID to the form
        add_label_form.row_id.data = str(row['_id'])
        add_label_form.username.data = current_user.username
    else:
        read_one_row_form.data.data = "--None--"
        flash('همه داده ها توسط این کاربر برچسب گذاری شده است.', 'info')

    recent_labels = get_recent_labels(current_user.username)
    label_options = get_label_options(collection)

    return render_template('access/user/user.html', read_one_row_form=read_one_row_form, add_label_form=add_label_form,
                           recent_labels=recent_labels, label_options=label_options, form=add_label_form)


@app.route('/edit_label', methods=['POST'])
@role_required('user')
@login_required
def edit_label():
    row_id = request.form['row_id']
    new_label_value = request.form['label_value']
    username = current_user.username
    if update_label(ObjectId(row_id), username, new_label_value):
        flash('برچسب با موفقیت ویرایش شد.', 'success')
    else:
        flash('ویرایش برچسب ناموفق بود.', 'danger')
    return redirect(url_for('user'))


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
    collection = get_user_collection(current_user.username)
    add_label_form = AddLabelForm()
    add_label_form.set_label_choices(collection)
    if add_label_form.validate_on_submit():
        row_id = add_label_form.row_id.data
        username = add_label_form.username.data
        label = add_label_form.label.data
        if add_label_to_data(ObjectId(row_id), label, username):
            flash('برچسب با موفقیت اضافه شد.', 'success')
        else:
            flash('افزودن برچسب ناموفق بود.', 'danger')
    return redirect(url_for('user'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4001)
# , ssl_context=(ConfigApp.cert, ConfigApp.key)