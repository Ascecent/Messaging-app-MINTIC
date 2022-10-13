import functools
import random

import bcrypt
import flask
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from app.db import get_db
from . import utils

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if g.user:
        return redirect(url_for('inbox.show'))

    if request.method == 'GET':
        return render_template('auth/register.html')

    register_template = 'auth/register.html'
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    db = get_db()

    if not username or not password or not email:
        flash('All the fields are required.')
        return render_template(register_template)

    if not utils.is_username_valid(username):
        flash("Username should be alphanumeric plus '.','_','-'")
        return render_template(register_template)

    if not utils.is_email_valid(email):
        flash('Email address is invalid.')
        return render_template('auth/register.html')

    if not utils.is_password_valid(password):
        flash(utils.password_feedback)
        return render_template('auth/register.html')

    if db.execute('SELECT id FROM user WHERE username = ?', [username]).fetchone() is not None:
        flash('Username {} is already taken.'.format(username))
        return render_template(register_template)

    if db.execute('SELECT id FROM user WHERE email = ?', [email]).fetchone() is not None:
        flash('Email {} is already being used.'.format(email))
        return render_template(register_template)

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    validator = hex(random.getrandbits(256))[2:]

    db.execute('INSERT INTO user (username, password, email) VALUES (?,?,?)', [username, hashed_password, email])
    user = db.execute('SELECT id FROM user WHERE email = ?', [email]).fetchone()
    db.execute('INSERT INTO activation_link(id_user, validator, state) VALUES(?,?,?)',
               [user['id'], validator, utils.U_UNCONFIRMED])
    db.commit()

    credentials = db.execute('SELECT user,password FROM credentials WHERE name=?', (utils.EMAIL_APP,)).fetchone()
    content = 'Hello there, to activate your account, please click on this link ' + flask.url_for(
        'auth.activate', _external=True) + '?auth=' + validator

    print(content)
    utils.send_email(credentials, email, 'Activate your account', content)

    flash('Please check in your registered email to activate your account')
    return redirect(url_for('auth.login'))


@bp.route('/activate', methods=['GET'])
def activate():
    if g.user:
        return redirect(url_for('inbox.show'))

    validator = request.args['auth']
    db = get_db()
    attempt = db.execute(
        'SELECT id, id_user FROM activation_link WHERE validator = ? AND state = ? AND CURRENT_TIMESTAMP < valid_until ORDER BY id DESC',
        (validator, utils.U_UNCONFIRMED)
    ).fetchone()

    message = None
    if attempt is not None:
        db.execute('UPDATE activation_link SET state = ? WHERE id = ?', [utils.U_CONFIRMED, attempt['id']])
        db.execute('UPDATE user SET state = ? WHERE id = ?', [utils.F_ACTIVE, attempt['id_user']])
        db.commit()
        message = 'The account has been successfully validated.'
    else:
        message = 'The validation link is invalid, try asking for a new validation link.'

    flash(message)
    return redirect(url_for('auth.login'))


@bp.route('/change', methods=('GET', 'POST'))
def change():
    if g.user:
        return redirect(url_for('inbox.show'))

    change_template = 'auth/change.html'
    if request.method == 'GET':
        return render_template(change_template)

    password = request.form['password']
    password1 = request.form['password1']
    auth_id = request.form['authid']

    if auth_id is None:
        flash('The password change is invalid, generate another forgot link and try again.')
        return render_template('auth/login.html')

    db = get_db()
    attempt = db.execute(
        'SELECT id_user FROM forgot_link WHERE validator = ? AND state = ? AND  CURRENT_TIMESTAMP < valid_until ORDER BY id DESC',
        [auth_id, utils.F_ACTIVE]).fetchone()
    db.execute('UPDATE forgot_link SET state = ? WHERE id_user = ?', [utils.F_INACTIVE, attempt['id_user']])
    db.commit()

    if not password1 or not password:
        flash('All the fields are required')
        return render_template(change_template)

    if password != password:
        flash('Both values should be the same')
        return render_template(change_template)

    if not utils.is_password_valid(password):
        flash(utils.password_feedback)
        return render_template(change_template)

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    db.execute('UPDATE user SET password = ? WHERE id = ?', [hashed_password, attempt['id_user']])
    db.commit()

    flash('The password has been updated')
    return render_template('auth/login.html')


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    if g.user:
        return redirect(url_for('inbox.show'))

    if request.method == 'GET':
        return render_template('auth/forgot.html')

    email = request.form['email']
    forgot_template = 'auth/forgot.html'

    if not email or not utils.is_email_valid(email):
        flash('Invalid email address')
        return render_template(forgot_template)

    db = get_db()
    user = db.execute('SELECT id FROM user WHERE email = ?', [email]).fetchone()

    if user is None:
        flash('Email is not registered')
        return render_template(forgot_template)

    validator = hex(random.getrandbits(256))[2:]
    db.execute('UPDATE forgot_link SET state = ? WHERE id_user = ?', [utils.F_INACTIVE, user['id']])
    db.execute('INSERT INTO forgot_link(id_user, validator) VALUES(?,?)', [user['id'], validator])
    db.commit()

    credentials = db.execute('SELECT user,password FROM credentials WHERE name = ?', [utils.EMAIL_APP]).fetchone()
    content = 'Hello there, to change your password, please click on this link ' + flask.url_for(
        'auth.change', _external=True) + '?auth=' + validator

    print(content)
    utils.send_email(credentials, receiver=email, subject='New Password', message=content)
    flash('Please check in your registered email')
    return render_template('auth/login.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    login_template = 'auth/login.html'

    if g.user:
        return redirect(url_for('inbox.show'))

    if request.method == 'GET':
        return render_template(login_template)

    username = request.form['username']
    password = request.form['password']

    if not username or not password:
        flash('All the fields are required')
        return render_template(login_template)

    db = get_db()
    user = db.execute('SELECT id, username, password FROM user WHERE username = ?', (username,)).fetchone()
    error = None

    if user is None or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        error = 'Incorrect username or password'

    if error is None:
        session.clear()
        session['user_id'] = user['id']
        return redirect(url_for('inbox.show'))

    flash(error)
    return render_template(login_template)


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', [user_id]).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)

    return wrapped_view
