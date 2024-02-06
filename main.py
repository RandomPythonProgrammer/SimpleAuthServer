import os
import time

import pyotp
import qrcode
import flask
import sqlite3


class DataBase:

    def __init__(self):
        curr_dir = os.path.abspath(os.path.dirname(__file__))
        self.connection = sqlite3.connect(os.path.join(curr_dir, 'database.db'), check_same_thread=False)
        self.cursor = self.connection.cursor()

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS IP (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                time INTEGER
            );
            """
        )
        self.connection.commit()


os.makedirs('secrets', exist_ok=True)
totp_path = os.path.join('secrets', 'totp.txt')
if not os.path.exists(totp_path):
    with open(totp_path, 'w') as file:
        file.write(pyotp.random_base32())


with open(totp_path, 'r') as file:
    totp = pyotp.totp.TOTP(file.readline().strip())
    code_path = os.path.join('secrets', 'code.png')
    if not os.path.exists(code_path):
        url = totp.provisioning_uri(name='BASED_MINECRAFT_USERS', issuer_name='server')
        image = qrcode.make(url)
        image.save(code_path)

app = flask.Flask(__name__)


@app.route('/')
def index():
    if is_auth(flask.request.remote_addr):
        return flask.render_template('success.html')
    return flask.render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    if not is_auth(flask.request.remote_addr):
        if flask.request.form['token'] == totp.now():
            db = DataBase()
            db.cursor.execute(
                """
                INSERT INTO IP (ip, time)
                VALUES(?, ?)
                """,
                (flask.request.remote_addr, int(time.time()))
            )
            db.connection.commit()
            return flask.make_response("", 200)
        else:
            return flask.make_response("", 401)


def is_auth(ip):
    db = DataBase()
    db.cursor.execute(
        """
        SELECT 1 FROM IP
        WHERE ip = ?;
        """,
        (ip,)
    )
    return db.cursor.fetchone() is not None


app.run(host='0.0.0.0', port=8080)
