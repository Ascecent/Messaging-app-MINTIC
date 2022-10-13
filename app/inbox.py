from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')


@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)


@bp.route('/show')
@login_required
def show():
    db = get_db()
    messages = db.execute('SELECT * FROM message').fetchall()
    return render_template('inbox/show.html', messages=messages)


@bp.route('/send', methods=('GET', 'POST'))
@login_required
def send():
    if request.method == 'GET':
        return render_template('inbox/send.html')

    from_id = g.user['id']
    to_username = request.form['to']
    subject = request.form['subject']
    body = request.form['body']

    db = get_db()

    if not to_username or not subject or not body:
        flash('All the fields are required.')
        return render_template('inbox/send.html')

    user_to = db.execute('SELECT id FROM user WHERE username = ?', [to_username]).fetchone()
    creator = db.execute('SELECT username FROM user WHERE id = ?', [from_id]).fetchone()

    if user_to is None:
        flash('Recipient does not exist')
        return render_template('inbox/send.html')

    db = get_db()
    db.execute(
        'INSERT INTO message(creator, id_user_from, id_user_to, subject, body) VALUES(?,?,?,?,?)',
        [creator['username'], from_id, user_to['id'], subject, body]
    )
    db.commit()

    return redirect(url_for('inbox.show'))
