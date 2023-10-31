from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField, SelectField, DateTimeField
from wtforms.validators import DataRequired
import werkzeug.security
import datetime

# App config and plugins
app = Flask(__name__)
app.config['SECRET_KEY'] = 'DS5F6DSF6D47F4DF4D35SFdjfjk8S4DCF5SF458SD4CFWE@'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todolist.db'
db = SQLAlchemy(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)


# Databases
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(300))
    todos = db.relationship('Todo', backref='User')


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_title = db.Column(db.String(50), nullable=False)
    task_notes = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    priority = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# Forms
class Register(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class Login(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class AddTask(FlaskForm):
    task_title = StringField("Task Title", validators=[DataRequired()])
    task_notes = TextAreaField("Task Description", validators=[DataRequired()])
    start_date = DateTimeField("Start Date", validators=[DataRequired()], format="%d%b%Y %H:%M", default=datetime.datetime.utcnow())
    end_date = DateTimeField("End Date", validators=[DataRequired()], format="%d%b%Y %H:%M", default=datetime.datetime.utcnow())
    priority = SelectField("Priority", validators=[DataRequired()], choices=["Low", "Medium", "High"])
    status = SelectField("Status", validators=[DataRequired()], choices=["To do", "Doing", "Done"])
    submit = SubmitField("Submit", validators=[DataRequired()])


# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))


# App routes
@app.route("/")
def home():
    db.create_all()
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route("/dashboard/<int:user_id>")
@login_required
def dashboard(user_id):
    return render_template("dashboard.html", user_id=user_id, user=User.query.get(user_id),
                           logged_in=current_user.is_authenticated,
                           todos=db.session.query(Todo).filter_by(user_id=user_id).all())


@app.route("/delete//<int:todo_id>")
@login_required
def delete(todo_id):
    todo = db.session.query(Todo).filter_by(id=todo_id).first()
    user = db.session.query(User).filter_by(id=todo.user_id).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for("dashboard", user_id=user.id))


@app.route("/edit/<int:todo_id>", methods=["POST", "GET"])
@login_required
def edit(todo_id):
    todo = db.session.query(Todo).filter_by(id=todo_id).first()
    user = db.session.query(User).filter_by(id=todo.user_id).first()
    user_id = user.id
    form = AddTask(task_title=todo.task_title,
                   task_notes=todo.task_notes,
                   start_date=todo.start_date,
                   end_date=todo.end_date,
                   priority=todo.priority,
                   status=todo.status,
                   )
    if form.validate_on_submit():
        todo.task_title = form.task_title.data
        todo.task_notes = form.task_notes.data
        todo.start_date = form.start_date.data
        todo.end_date = form.end_date.data
        todo.priority = form.priority.data
        todo.status = form.status.data
        db.session.commit()
        return redirect(url_for("dashboard", user_id=user.id))

    return render_template("edit.html", user=User.query.get(user_id), user_id=user_id, form=form, todo=todo )


@app.route("/login", methods=["POST", "GET"])
def login():
    form = Login()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = db.session.query(User).filter_by(email=email).first()
        if user:
            if werkzeug.security.check_password_hash(pwhash=user.password, password=password):
                login_user(user)
                return redirect(url_for('dashboard', user_id=user.id))
            else:
                flash("incorrect Password")
        else:
            flash("No account registered with this email, please register to proceed")

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/register", methods=["POST", "GET"])
def register():
    form = Register()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = werkzeug.security.generate_password_hash(password=password, method="pbkdf2:sha256",
                                                                   salt_length=8)
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            flash("This email is already registered, please login")
            return redirect(url_for('login'))
        else:
            load_user(new_user.id)
            return redirect(url_for("login"))

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/add/<int:user_id>", methods=["POST", "GET"])
# @login_required
def add(user_id):
    form = AddTask()
    if form.validate_on_submit():
        task_title = form.task_title.data
        task_notes = form.task_notes.data
        start_date = form.start_date.data
        end_date = form.end_date.data
        # start_time = form.start_time.data
        # end_time = form.end_time.data
        priority = form.priority.data
        status = form.status.data
        new_task = Todo(task_title=task_title, task_notes=task_notes, start_date=start_date, end_date=end_date,
                        priority=priority, status=status, user_id=user_id)
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for("dashboard", user_id=user_id))

    return render_template("add.html", form=form, user=User.query.get(user_id), user_id=user_id)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
