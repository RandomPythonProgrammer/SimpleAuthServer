import atexit
import os
import time
import subprocess

import pyotp
import qrcode
import flask
import sqlite3

# Set these
# Also make a new unpriviliged user that can run sudo without password
# Sudoers rule example `simpleauth ALL=(root) NOPASSWD: /usr/bin/iptables`
# That runs this script
minecraft_server_ip = '10.0.0.165'
this_server_ip = '10.0.0.12'


def whitelist_port(ip, port, protocol):
    p1 = subprocess.Popen(["sudo", "/usr/bin/iptables", "-t", "nat", "-A", "PREROUTING", "--src", ip, "-p", protocol, "--dport", f"{port}", "-j", "DNAT", "--to-destination", f"{minecraft_server_ip}:{port}"], stdout=subprocess.PIPE)
    output1, err1 = p1.communicate()
    #print(f"Out1: {output1}\nErr1: {err1}\nCmd: {p1.args}\n")
    p2 = subprocess.Popen(["sudo", "/usr/bin/iptables", "-t", "nat", "-A", "POSTROUTING", "-p", protocol, "-d", minecraft_server_ip, "--dport", f"{port}", "-j", "SNAT", "--to-source", f"{this_server_ip}:{port}"], stdout=subprocess.PIPE)
    output2, err2 = p2.communicate()
    #print(f"Out2: {output2}\nErr2: {err2}\nCmd: {p2.args}\n")

def whitelist_ip(ip):
    # Java
    whitelist_port(ip, 25565, 'tcp')
    # Bedrock
    whitelist_port(ip, 19132, 'tcp')
    whitelist_port(ip, 19133, 'udp')


class DataBase:

    def __init__(self):
        curr_dir = os.path.abspath(os.path.dirname(__file__))
        self.connection = sqlite3.connect(os.path.join(curr_dir, 'database.db'), check_same_thread=False)
        self.cursor = self.connection.cursor()

        if not os.path.exists('init.lock'):
            with open('init.lock', 'w'):
                pass
            self.cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS IP (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    time INTEGER
                );
                """
            )
        # TODO: list through existing ips and whitelist them
            self.connection.commit()
            for ip, in self.cursor.execute("SELECT ip FROM IP"):
                print(f"Whitelisting: {ip}\n")
                whitelist_ip(ip)

            def remove_lock():
                os.remove('init.lock')

            atexit.register(remove_lock)
        


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
            whitelist_ip(flask.request.remote_addr)
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

if __name__ == '__main__':
    app.run()
