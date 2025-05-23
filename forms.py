from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, HiddenField, RadioField
from wtforms.fields.numeric import IntegerField
from wtforms.fields.simple import BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, InputRequired, NumberRange, Optional, ValidationError
from wtforms.fields import SelectField
from flask import session  # Import session to access it in validation

from wtforms.widgets import ListWidget, CheckboxInput

import models
from config import ConfigDB
from models import get_db_collection_names


class LoginForm(FlaskForm):
    username = StringField('نام کاربری', validators=[DataRequired()])
    password = PasswordField('کلمه عبور', validators=[DataRequired()])
    captcha = StringField('کلمات تصویر را وارد کنید:', validators=[Optional()])
    submit = SubmitField('ورود')


class SignUpForm(FlaskForm):
    username = StringField('نام کاربری', validators=[DataRequired()])
    password = PasswordField('کلمه عبور', validators=[DataRequired()])
    confirm_password = PasswordField('تکرار کلمه عبور', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('نقش', choices=[('user', 'User'), ('supervisor', 'Supervisor'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('ایجاد کاربر')

    def set_collections_choices(self, user):
        choices = models.get_assigned_label_db_collection_names(user)
        return choices

    def set_role_choices(self, role):
        if role == 'admin':
            choices = [('user', 'User'), ('supervisor', 'Supervisor'), ('admin', 'Admin')]
            self.role.choices = choices
        else:
            choices = [('user', 'User')]
            self.role.choices = choices

class RemoveUserForm(FlaskForm):
    username = SelectField('نام کاربری', validators=[DataRequired()], coerce=str)
    submit = SubmitField('حذف')


class ExtractDBForm(FlaskForm):
    collection_name = SelectField('نام دسته بندی', choices=models.get_db_collection_names(1), validators=[DataRequired()])
    submit = SubmitField('استخراج پایگاه داده')

    def set_collections_choices(self, sys_collections_included):
        choices = models.get_db_collection_names(sys_collections_included=1)
        self.collection_name.choices = choices


class ImportDBForm(FlaskForm):
    title = StringField('عنوان مجموعه داده', validators=[DataRequired()])
    file = FileField('فایل JSON/CSV', validators=[DataRequired()])
    submit = SubmitField('افزودن مجموعه داده')


class ReadOneRowDataForm(FlaskForm):
    row_id = StringField('شماره سطر', validators=[DataRequired()], render_kw={'readonly': True})
    username = StringField('نام کاربری', validators=[DataRequired()], render_kw={'readonly': True})
    data = StringField('داده', validators=[DataRequired()], render_kw={'readonly': True})
    collection = StringField('مجموعه داده مد نظر را انتخاب کنید:', validators=[DataRequired()])


class AddLabelForm(FlaskForm):
    row_id = StringField('شماره سطر', validators=[DataRequired()], render_kw={'readonly': True})
    username = StringField('نام کاربری', validators=[DataRequired()], render_kw={'readonly': True})
    label = RadioField('برچسب مناسب را انتخاب کنید:', validators=[DataRequired()], choices=[])
    submit = SubmitField('افزودن برچسب')

    def set_label_choices(self, collection):
        choices = ConfigDB.get_data_labels(collection)
        self.label.choices = [choice for choice in choices]


class ReportTaskForm(FlaskForm):
    username = SelectField('نام کاربری', validators=[DataRequired()], coerce=str)
    collection = SelectField('مجموعه داده', validators=[DataRequired()])


class ConflictSearchForm(FlaskForm):
    data_collection = SelectField('مجموعه داده مورد نظر را انتخاب کنید:', choices=get_db_collection_names(), validators=[DataRequired()])
    search = SubmitField('یافتن یک داده متناقض')
    label = SelectField('انتخاب برچسب:', validators=[DataRequired()])
    row_id = StringField('شماره سطر')
    set_label = SubmitField('افزودن برچسب')
    remove_row = SubmitField('حذف داده')
    hidden_collection = HiddenField()

    # update choices when we instantiate AddLabelForm to get the updated labels for it.
    # we call this function (instance.function) after each instantiation
    def set_label_choices(self, collection):
        choices = ConfigDB.get_data_labels(collection)
        self.label.choices = choices


class LabelForm(FlaskForm):
    label = StringField('برچسب', validators=[DataRequired()])


class SetDataConfigForm(FlaskForm):
    data_collection = SelectField('مجموعه داده مورد نظر را انتخاب کنید:', choices=get_db_collection_names(), validators=[DataRequired()])
    labels = StringField('برچسب', validators=[DataRequired()], render_kw={"type": "hidden"})
    num_required_labels = IntegerField('تعداد برچسب‌ها مورد نیاز برای داده:', default=1, validators=[InputRequired(),
                                  NumberRange(min=1, message="تعداد برچسب‌های پیش فرض ۱ است.")])
    new_option = StringField('افزودن برچسب جدید: ')
    add_button = SubmitField('افزودن')
    remove_button = SubmitField('حذف')

    def get_unassinged_db_collection_names_for_user(self, user):
        choices = models.get_unassigned_label_db_collection_names(user)
        self.data_collection.choices = choices



class AddAverageLabelForm(FlaskForm):
    data_collection = SelectField('مجموعه داده مورد نظر را انتخاب کنید:', choices=get_db_collection_names(), validators=[DataRequired()])
    set_average_label = SubmitField('افزودن برچسب تجمعی')
    def set_data_collection_choices(self):
        choices = get_db_collection_names()
        self.data_collection.choices = choices


class AddDataToCollectionForm(FlaskForm):
    data_collection = SelectField('مجموعه داده مورد نظر را انتخاب کنید:', choices=get_db_collection_names(), validators=[DataRequired()])
    file = FileField('فایل CSV/JSON:', validators=[DataRequired()])
    submit = SubmitField('افزودن داده')


class AssignCollectionToUserForm(FlaskForm):
    data_collection = SelectField('مجموعه داده:', choices=get_db_collection_names(), validators=[DataRequired()])
    username = SelectField('کاربر', validators=[DataRequired()], coerce=str)
    submit = SubmitField('اختصاص', name='assign')

    def set_data_collection_choices(self, user):
        choices = models.get_assigned_label_db_collection_names(user)
        self.data_collection.choices = choices


class RevokeCollectionFromUserForm(FlaskForm):
    data_collection = SelectField('مجموعه داده:', choices=get_db_collection_names(), validators=[DataRequired()])
    username = SelectField('کاربر', choices=['--کاربری یافت نشد.--'], validators=[DataRequired()], coerce=str)
    submit = SubmitField('لغو تخصیص', name='revoke')

    def set_data_collection_choices(self, selected_user):
        if selected_user:
            choices = models.get_user_collection(selected_user)
        else:
            choices = ['--کاربری یافت نشد.--']
        # print(choices)
        self.data_collection.choices = choices

    # def set_username_choices(self, collection):
    #     users = models.get_collection_users(collection)
    #     choices = [user.username for user in users] if users else ['--کاربری یافت نشد.--']
    #     print(22222,choices)
    #     self.username.choices = choices

class RemoveDataCollectionForm(FlaskForm):
    data_collection = SelectField('مجموعه داده مورد نظر را انتخاب کنید:', choices=get_db_collection_names(), validators=[DataRequired()])
    # update_user_scores = BooleanField('بروزرسانی امتیازات کاربران')
    submit = SubmitField('حذف مجموعه داده')


class ChangePassword(FlaskForm):
    username = SelectField('نام کاربری', validators=[DataRequired()], coerce=str)
    new_password = PasswordField('کلمه عبور', validators=[DataRequired()])
    confirm_new_password = PasswordField('تکرار کلمه عبور', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('تغییر کلمه عبور', name='changepassword')
