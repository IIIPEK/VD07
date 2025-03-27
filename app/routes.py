from flask_login import login_user, logout_user, login_required, current_user
from flask import render_template, redirect, url_for, request, flash
from app import models,forms
from app.models import User
from app.forms import RegistrationForm, LoginForm, UpdateAccountForm
from app import db, app, bcrypt


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Неправильный логин или пароль', 'danger')
    return render_template('login.html', form=form)

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    form = UpdateAccountForm(obj=current_user)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        return redirect(url_for('account'))
    return render_template('edit.html', form=form)
