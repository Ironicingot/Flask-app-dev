from flask_wtf import FlaskForm, Form
from wtforms import StringField, PasswordField, SubmitField, HiddenField, FloatField, SelectField, FileField, validators
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Length, EqualTo, Email

# user register
class RegistrationForm(FlaskForm):
    username = StringField(validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=16)])
    confirm_password = PasswordField(validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField(label='Sign Up', validators=[DataRequired()])

# user login
class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField(label='Sign In', validators=[DataRequired()])

# user request reset password
class ResetRequestForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    submit = SubmitField(label='Send token', validators=[DataRequired()])

# user reset password
class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=16)])
    confirm_password = PasswordField(validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField(label='Change Password', validators=[DataRequired()])

# UPLOAD PRODUCT
class UploadUpdateForm(FlaskForm):
    picture = FileField(label="Update Picture", validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField(label='Update Picture')

class ShoppingCart(Form):
    data1 = HiddenField()
    data2 = HiddenField()
    submit_button1 = SubmitField("Submit")
    submit_button2 = SubmitField("Submit")

# UPDATE PRODUCT
class UploadProductForm(Form):
    category = SelectField('Category', [validators.DataRequired()], id='product', choices=[('', 'Click to select'), ('Kids', 'Kids'), ('Men', 'Men'), ('Women', 'Women'), ('New In', 'New In')], default='')
    name = StringField('Product Name', [validators.Length(min=1, max=150), validators.DataRequired(), validators.Regexp(r'^[A-Za-z\s-]+$', message="Product name must be letters only")], id='product')
    price = FloatField('Price', [validators.DataRequired(), validators.NumberRange(min=0)], id='product')
    size = SelectField('Size', id='size', choices=[('', 'Click to select'), ('S', 'S'), ('M', 'M'), ('L', 'L'), ('XL', 'XL')], default='')
    image = FileField('Image', id='image')

class CreateProductForm(Form):
    category = SelectField('Category', [validators.DataRequired()], id='product', choices=[('', 'Click to select'), ('Kids', 'Kids'), ('Men', 'Men'), ('Women', 'Women'), ('New In', 'New In')], default='')
    name = StringField('Product Name', [validators.Length(min=1, max=150), validators.DataRequired(), validators.Regexp(r'^[A-Za-z\s-]+$', message="Product name must be letters only")], id='product')
    price = FloatField('Price', [validators.DataRequired(), validators.NumberRange(min=0)], id='product')
    size = SelectField('Size', id='size', choices=[('', 'Click to select'), ('S', 'S'), ('M', 'M'), ('L', 'L'), ('XL', 'XL')], default='')
    image = FileField('Image', id='image')