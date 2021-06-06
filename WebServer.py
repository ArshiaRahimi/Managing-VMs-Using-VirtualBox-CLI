from flask import Flask, request, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from typing import Callable
import uuid
import jwt
import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import Controller
app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"

class MySQLAlchemy(SQLAlchemy):
    Column: Callable
    String: Callable
    Integer: Callable
    Boolean: Callable

db = MySQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


def need_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'token' in request.headers:
            token = request.headers['token']
        if not token:
            return jsonify({'message': 'token is missing'}) ,401
        try:
            data = jwt.decode(token, key=app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/user', methods = ['POST'])
@need_token
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message': 'you are not the admin'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id = str(uuid.uuid4()), name=data['name'], password = hashed_password, admin = False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'new user created!'})


@app.route('/user', methods = ['GET'])
def get_all_users():
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users':output})


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not veirify', 401, {'WWW-Authenticate':'Basic realm="login required'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('could not veirify', 401, {'WWW-Authenticate':'Basic realm="login required'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id':user.public_id, 'exp' : datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, key=app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return make_response('could not veirify', 401, {'WWW-Authenticate':'Basic realm="login required'})


@app.route('/run', methods = ['POST'])
@need_token
def jsonHandler(currentUser):
    data = request.get_json()

    if data["command"] == "status" and len(data) == 2:
        if currentUser.name == 'user1' and data["vmName"] != "VM1":
            return jsonify({"message":"you don't have the permission"})
        result = Controller.vmStatus(data["vmName"])
        return jsonify({"command":"status", "vmName": data["vmName"], "status": result})

    if data["command"] =="status" and len(data)==1:
        if currentUser.name == 'user1':
            return jsonify({"message":"you don't have the permission"})
        result = Controller.vmsStatus()
        return jsonify({"command":"status", "details": result})

    if data["command"] == "on":
        if currentUser.name == 'user1' and data["vmName"] != "VM1":
            return jsonify({"message":"you don't have the permission"})
        result = Controller.vm_start(data["vmName"])
        if result == "Vm is already running":
            return jsonify({"command": "on", "vmName": data["vmName"], "status":"already on"})
        else:
            return jsonify({"command": "on", "vmName": data["vmName"], "status":"Powering on"})

    if data["command"] == "off":
        if currentUser.name == 'user1' and data["vmName"] != "VM1":
            return jsonify({"message":"you don't have the permission"})
        result = Controller.vm_poweroff(data["vmName"])
        if result == "Vm is already off":
            return jsonify({"command": "off", "vmName": data["vmName"], "status": "already off"})
        else:
            return jsonify({"command": "off", "vmName": data["vmName"], "status": "Powering off"})

    if data["command"] == "setting":
        if currentUser.name == 'user1' and data["vmName"] != "VM1":
            return jsonify({"message":"you don't have the permission"})
        result = Controller.changeCpuRam(data["vmName"], data["ram"], data["cpu"])
        if result == "cpu and ram changed":
            return jsonify({"command": "setting", "vmName": data["vmName"], "cpu": data["cpu"], "ram": data["ram"], "status": "OK"})
        else:
            return jsonify({"command": "setting", "vmName": data["vmName"], "cpu": data["cpu"], "ram": data["ram"], "status": "Vm does not exist"})

    if data["command"] == "clone":
        if currentUser.name == 'user1' and data["sourceVmName"] != "VM1":
            return jsonify({"message":"you don't have the permission"})
        result = Controller.cloneVM(data["sourceVmName"], data["destVmName"])
        if result == "cloned":
            return jsonify({"command":"clone", "sourceVmName":data["sourceVmName"], "destVmName": data["destVmName"], "status":"ok"})
        else:
            return jsonify({"command": "clone", "sourceVmName": data["sourceVmName"], "destVmName": data["destVmName"],"status": result})

    if data["command"] == "delete":
        if currentUser.name == 'user1' and data["vmName"] != "VM1":
            return jsonify({"message":"you don't have the permission"})
        result = Controller.deleteVM(data["vmName"])
        if result == "deleted":
            return jsonify({"command": "delete", "vmName": data["vmName"], "status": "OK"})
        else:
            return jsonify({"command": "delete", "vmName": data["vmName"], "status": result})

    if data["command"] == "execute":
        if currentUser.name == 'user1' and data["vmName"] != "VM1":
            return jsonify({"message":"you don't have the permission"})
        result = Controller.executeCommand(data["vmName"], data["input"])
        if result == 'vm does not exist':
            return jsonify({"command": "execute", "vmName": data["vmName"], "input": data["input"], "status":result})
        elif result == 'start the vm first':
            return jsonify({"command": "execute", "vmName": data["vmName"], "input": data["input"], "status":result})
        else :
            return jsonify({"command": "execute", "vmName": data["vmName"], "input": data["input"], "status": "ok", "response": result})

    if data["command"] == "upload":
        if currentUser.name != 'admin':
            return jsonify({"message":"you don't have the permission"})
        result = Controller.uploadToVm(data["vmName"], data["hostFile"], data["vmDest"])
        if result == 'vm does not exist':
            return jsonify({"command": "upload", "vmName": data["vmName"], "status":result})
        elif result == 'start the vm first':
            return jsonify({"command": "upload", "vmName": data["vmName"], "status":result})
        else:
            return jsonify({"command": "upload", "vmName": data["vmName"], "hoseFile": data["hostFile"], "vmDest":data["vmDest"], "status":"ok"})

    if data["command"] == "transfer":
        if currentUser.name == 'user1' and data["originVM"] != "VM1":
            return jsonify({"message":"you don't have the permission"})
        result = Controller.transfer(data["originVM"], data["originPath"], data["destVM"], data["destPath"])

        return jsonify({"command": "transfer", "originPath": data["originPath"], "destVM":data["destVM"], "destPath": data["destPath"], "status":result})







if __name__ == '__main__':
    app.run(debug=True)

