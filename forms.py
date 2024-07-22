from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import DataRequired, EqualTo, Email, Length

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm password', validators=[DataRequired(), EqualTo('password')])
    account_type = RadioField('Account Type', choices=[('personal', 'Personal'), ('family', 'Family')],
                              validators=[DataRequired()])
    submit_bn = SubmitField('Register')

class FamilyRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=35)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit_bn = SubmitField('Add Family Member')

class AnimalSelectionForm(FlaskForm):
    animal = RadioField('Choose Animal ID', choices=[
        ('giraffe', 'Giraffe'),
        ('peacock', 'Peacock'),
        ('chicken', 'Chicken'),
        ('monkey', 'Monkey'),
        ('dog', 'Dog'),
        ('tiger', 'Tiger')
    ], validators=[DataRequired()])
    submit = SubmitField('Confirm Animal ID')

class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit_bn = SubmitField('Log in')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password',validators=[DataRequired()])
    resetPassword = PasswordField('Password',validators=[DataRequired()])
    confirmResetPassword = PasswordField('Confirm password',validators=[DataRequired(),EqualTo('password')])
    submit_bn = SubmitField('ConfirmPassword')