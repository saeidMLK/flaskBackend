from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, HiddenField, FormField, FieldList
from wtforms.validators import DataRequired, Email, EqualTo, InputRequired
from wtforms.fields import SelectField

import models
from config import ConfigDB

class LoginForm(FlaskForm):
    username = StringField('نام کاربری', validators=[DataRequired()])
    password = PasswordField('کلمه عبور', validators=[DataRequired()])
    captcha = StringField('کلمات تصویر را وارد کنید:', validators=[DataRequired()])
    submit = SubmitField('ورود')


class SignUpForm(FlaskForm):
    username = StringField('نام کاربری', validators=[DataRequired()])
    category = SelectField('داده', choices=models.get_category_names(), validators=[DataRequired()])
    password = PasswordField('کلمه عبور', validators=[DataRequired()])
    confirm_password = PasswordField('تکرار کلمه عبور', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('نقش', choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('ایجاد کاربر')

    def set_category_choices(self):
        choices = models.get_category_names()
        self.category.choices = choices

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
    collection_name = SelectField('Collection Name', choices=models.get_db_collection_names(), validators=[DataRequired()])
    file = FileField('JSON File', validators=[DataRequired()])
    submit = SubmitField('Import Database')


class ReadOneRowDataForm(FlaskForm):
    row_id = StringField('Row ID', validators=[DataRequired()], render_kw={'readonly': True})
    username = StringField('Username', validators=[DataRequired()], render_kw={'readonly': True})
    data = StringField('Data', validators=[DataRequired()], render_kw={'readonly': True})


class AddLabelForm(FlaskForm):
    row_id = StringField('Row ID', validators=[DataRequired()], render_kw={'readonly': True})
    username = StringField('Username', validators=[DataRequired()], render_kw={'readonly': True})
    label = SelectField('Choose Label:', validators=[DataRequired()])
    submit = SubmitField('Add Label')

    # update choices when we instantiate AddLabelForm to get the updated labels for it.
    # we call this function (instance.function) after each instantiation
    def set_label_choices(self):
        choices = ConfigDB.get_data_labels()
        self.label.choices = choices


class ReportTaskForm(FlaskForm):
    username = SelectField('Username', validators=[DataRequired()], coerce=str)


class ConflictSearchForm(FlaskForm):
    search = SubmitField('Find a Conflicted Row')
    label = SelectField('Choose Label:', validators=[DataRequired()])
    row_id = StringField('Row ID')
    set_label = SubmitField('Set Label')

    # update choices when we instantiate AddLabelForm to get the updated labels for it.
    # we call this function (instance.function) after each instantiation
    def set_label_choices(self):
        choices = ConfigDB.get_data_labels()
        self.label.choices = choices


class LabelForm(FlaskForm):
    label = StringField('Label', validators=[DataRequired()])

class AdminLabelConfigForm(FlaskForm):
    labels = StringField('Labels', validators=[DataRequired()], render_kw={"type": "hidden"})
    # submit = SubmitField('Save Labels')
    new_option = StringField('Add a new label: ')
    add_button = SubmitField('Add')
