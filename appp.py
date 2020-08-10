from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'martdevelopers_ContactTracingApp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)


# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# ContactTracing
@app.route('/contact_tracings')
def contact_tracings():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get Filled Questionaires
    result = cur.execute("SELECT * FROM questionaires")

    contact_tracing = cur.fetchall()

    if result > 0:
        return render_template('responses.html', contact_tracings=contact_tracing)
    else:
        msg = 'No Responses Captured'
        return render_template('responses.html', msg=msg)
    # Close connection
    cur.close()


# Single contact tracing Response
@app.route('/contact_tracings/<string:id>/')
def contact_tracing(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get Question
    result = cur.execute("SELECT * FROM questionaires WHERE id = %s", [id])

    contact_tracing = cur.fetchone()

    return render_template('response.html', contact_tracing=contact_tracing)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()


        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))


        mysql.connection.commit()


        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))

    return wrap


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get questionaires
    # Show recently tracing inforation of logged in user
    result = cur.execute("SELECT * FROM questionaires WHERE name = %s", [session['username']])
    Responses = cur.fetchall()
    if result > 0:
        return render_template('dashboard.html', Responses=Responses)
    else:
        msg = 'No Contact Tracing Responses Found'
        return render_template('dashboard.html', msg=msg)
    # Close connection
    cur.close()


# Questionaire form
class ArticleForm(Form):
    name = StringField('Full Name', [validators.Length(min=1, max=200)])
    age = StringField('Age', [validators.length(min=1, max=200)])
    phone = StringField('Phone Number', [validators.length(min=2, max=13)])
    family_members = TextAreaField('How Many Are You In Your Family Including You', [validators.length(min=1)])
    symptoms = TextAreaField('What Are Your Symptoms', [validators.length(min=10)])
    symptops_started = TextAreaField('When Did You Start Having These Symptoms', [validators.Length(min=1)])
    closeness = TextAreaField('Have You Been Close To Someone With Such Symptoms', [validators.length(min=1)])
    other_medical_issues = TextAreaField('Do You Have Any Chronic Medical Condition - Name Them',
                                         [validators.length(min=4)])
    any_recent_travel = TextAreaField('Have you recently traveled', [validators.length(min=1)])
    same_symptoms = TextAreaField('Is Anyone In Your Family Experiencing Any Of The Symptoms As You',
                                  [validators.length(min=2)])


# Add Questionare
@app.route('/take_survey', methods=['GET', 'POST'])
@is_logged_in
def add_question():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        age = form.age.data
        phone = form.phone.data
        symptoms = form.symptoms.data
        symptops_started = form.symptops_started.data
        closeness = form.closeness.data
        other_medical_issues = form.other_medical_issues.data
        family_members = form.family_members.data
        any_recent_travel = form.any_recent_travel.data
        same_symptoms = form.same_symptoms.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute(
            "INSERT INTO questionaires(name, age, phone, symptoms, symptops_started, closeness, other_medical_issues, family_members, any_recent_travel, same_symptoms) VALUES(%s, %s, %s,%s, %s, %s, %s, %s, %s, %s)",
            (session['username'], age, phone, symptoms, symptops_started, closeness, other_medical_issues,
             family_members, any_recent_travel, same_symptoms))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Response Submitted', 'success')

        return redirect(url_for('dashboard'))

    return render_template('take_survey.html', form=form)


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
