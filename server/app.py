from flask import Flask, render_template, request, url_for, redirect
from flask_wtf import FlaskForm
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from playhouse.shortcuts import model_to_dict

app=Flask(__name__)
bcrypt = Bcrypt(app)

# to not get confused, this is importing 'Data' from the folder 'database', which has 'table'.py in it
from table import UserInfo, db

app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
  return UserInfo.get(int(user_id))

class RegisterForm(FlaskForm):
  username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
  password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

  submit = SubmitField("Register")

  def validate_username(self, username):
    if UserInfo.select().where(UserInfo.username == username.data):
      raise ValidationError("That username already exists. Please choose a different one.")      
    
class LoginForm(FlaskForm):
  username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
  password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

  submit = SubmitField("Login")

@app.route('/')
def home():
  return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
  form = LoginForm()

  if form.validate_on_submit():
    try:
      user = UserInfo.get(UserInfo.username == form.username.data)
    except:
      return redirect(url_for('login'))

    print(user)

    if user:
      if bcrypt.check_password_hash(user.password, form.password.data):
        login_user(user)
        return redirect(url_for('dashboard'))

  return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
  return render_template('dashboard.html')

@app.route('/logout', methods=['GET','POST'])
def logout():
  logout_user()
  return redirect(url_for("login"))



@app.route('/register', methods=['GET', 'POST'])
def register():
  form = RegisterForm()
  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    UserInfo.insert(username=form.username.data, password=hashed_password).execute()
    return redirect(url_for('login'))
  return render_template('register.html', form=form)

if __name__ == '__main__':
  app.run(debug=True)