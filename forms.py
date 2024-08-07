from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, HiddenField, FormField, FieldList
from wtforms.validators import DataRequired, Email, EqualTo, InputRequired
from wtforms.fields import SelectField

import models
from config import ConfigDB
from models import get_db_collection_names


class LoginForm(FlaskForm):
    username = StringField('نام کاربری', validators=[DataRequired()])
    password = PasswordField('کلمه عبور', validators=[DataRequired()])
    captcha = StringField('کلمات تصویر را وارد کنید:', validators=[DataRequired()])
    submit = SubmitField('ورود')


class SignUpForm(FlaskForm):
    username = StringField('نام کاربری', validators=[DataRequired()])
    collections = SelectField('داده مد نظر برای برچسب زدن', choices=models.get_db_collection_names(), validators=[DataRequired()])
    password = PasswordField('کلمه عبور', validators=[DataRequired()])
    confirm_password = PasswordField('تکرار کلمه عبور', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('نقش', choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('ایجاد کاربر')

    def set_collections_choices(self):
        choices = models.get_db_collection_names()
        self.collections.choices = choices

class RemoveUserForm(FlaskForm):
    username = SelectField('نام کاربری', validators=[DataRequired()], coerce=str)
    submit = SubmitField('حذف')


class ExtractDBForm(FlaskForm):
    collection_name = SelectField('نام دسته بندی', choices=models.get_db_collection_names(), validators=[DataRequired()])
    submit = SubmitField('استخراج پایگاه داده')

    def set_collections_choices(self):
        choices = models.get_db_collection_names()
        self.collection_name.choices = choices

class ImportDBForm(FlaskForm):
    # collection_name = SelectField('نام مجموعه', choices=models.get_db_collection_names(), validators=[DataRequired()])
    file = FileField('فایل JSON', validators=[DataRequired()])
    submit = SubmitField('افزودن مجموعه داده')


class ReadOneRowDataForm(FlaskForm):
    row_id = StringField('شماره سطر', validators=[DataRequired()], render_kw={'readonly': True})
    username = StringField('نام کاربری', validators=[DataRequired()], render_kw={'readonly': True})
    data = StringField('داده', validators=[DataRequired()], render_kw={'readonly': True})


class AddLabelForm(FlaskForm):
    row_id = StringField('شماره سطر', validators=[DataRequired()], render_kw={'readonly': True})
    username = StringField('نام کاربری', validators=[DataRequired()], render_kw={'readonly': True})
    label = SelectField('برچسب مناسب را انتخاب کنید:', validators=[DataRequired()])
    submit = SubmitField('افزودن برچسب')

    # update choices when we instantiate AddLabelForm to get the updated labels for it.
    # we call this function (instance.function) after each instantiation
    def set_label_choices(self, collectin):
        choices = ConfigDB.get_data_labels(collectin)
        self.label.choices = choices


class ReportTaskForm(FlaskForm):
    username = SelectField('نام کاربری', validators=[DataRequired()], coerce=str)


class ConflictSearchForm(FlaskForm):
    data_collection = SelectField('مجموعه داده مورد نظر را انتخاب کنید:', choices=get_db_collection_names(), validators=[DataRequired()])
    search = SubmitField('یافتن یک داده متناقض')
    label = SelectField('انتخاب برچسب:', validators=[DataRequired()])
    row_id = StringField('شماره سطر')
    set_label = SubmitField('افزودن برچسب')
    hidden_collection = HiddenField()

    # update choices when we instantiate AddLabelForm to get the updated labels for it.
    # we call this function (instance.function) after each instantiation
    def set_label_choices(self, collection):
        choices = ConfigDB.get_data_labels(collection)
        self.label.choices = choices


class LabelForm(FlaskForm):
    label = StringField('برچسب', validators=[DataRequired()])


class AdminLabelConfigForm(FlaskForm):
    data_collection = SelectField('مجموعه داده مورد نظر را انتخاب کنید:', choices=get_db_collection_names(), validators=[DataRequired()])
    labels = StringField('برچسب', validators=[DataRequired()], render_kw={"type": "hidden"})
    new_option = StringField('افزودن برچسب جدید: ')
    add_button = SubmitField('افزودن')


class AddAverageLabelForm(FlaskForm):
    data_collection = SelectField('مجموعه داده مورد نظر را انتخاب کنید:', choices=get_db_collection_names(), validators=[DataRequired()])
    set_average_label = SubmitField('افزودن برچسب تجمعی')
