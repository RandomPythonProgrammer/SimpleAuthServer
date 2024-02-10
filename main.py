import os
import time

import pyotp
import qrcode
import flask
import sqlite3
import iptc

server_ip = '127.0.0.1'

def whitelist_port(ip, port, protocol):
    prerouting = iptc.Chain(iptc.Table(iptc.Table.NAT), "PREROUTING")
    rule1 = iptc.Rule()
    rule1.protocol = protocol
    rule1.src = ip
    match1 = iptc.Match(rule1, protocol)
    match1.dport = port
    rule1.add_match(match1)
    target1 = iptc.Target(rule1, "DNAT")
    target1.to_destination = f"{server_ip}:{port}"
    rule1.target = target1
    prerouting.insert_rule(rule1)
    postrouting = iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING")
    rule2 = iptc.Rule()
    rule2.protocol = protocol
    rule2.dst = ip
    match2 = iptc.Match(rule2, protocol)
    match2.dport = port
    rule2.add_match(match2)
    target2 = iptc.Target(rule2, "SNAT")
    target2.to_source = f"{server_ip}:{port}"
    rule2.target = target2
    postrouting.insert_rule(rule2)

def whitelist_ip(ip):
    # TODO: minecraft server ports

    # Test
    whitelist_port(ip, 8000, 'tcp')
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
