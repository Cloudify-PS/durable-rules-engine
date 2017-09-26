import os
import json
from . import engine
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from werkzeug.http import parse_authorization_header
from common import _start_functions, _rulesets
from flask import Flask, jsonify, request, abort
from flasgger import Swagger

host = None

UPLOAD_FOLDER = 'rules/'
auth = HTTPBasicAuth()
users = {
    "admin": "admin"
}

app = Flask(__name__)
Swagger(app)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def _allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ['py']


def _authorize(request):
    if request.headers.get('Authorization'):
        credentials = parse_authorization_header(
            request.headers.get('Authorization'))
        if not credentials or not \
                (credentials.type == 'basic'
                 and credentials.password == users[credentials.username]):
            abort(403)
        return credentials
    else:
        abort(403)


def _encode_promise(obj):
    if isinstance(obj, engine.Promise) or hasattr(obj, '__call__'):
        return 'function'
    raise TypeError(repr(obj) + " is not JSON serializable")


@app.route('/rulesets', methods=['GET'])
def list_rulesets():
    """
    List rulesets
    ---
    tags:
      - Rules engine
    responses:
      200:
        description: A list of registered rulesets
        schema:
          properties:
            registered_rulesets:
              type: array
              description: list of registeres rulesets
              default: ["test_ruleset"]
    """
    result = host.list_rulesets()
    return jsonify(result)


@app.route('/rulesets/events', methods=['POST'])
def all_events_request():
    """
    Post event to all rulesets
    ---
    tags:
      - Rules engine
    parameters:
      - name: body
        in: body
        required: True
        description: JSON message.
    responses:
      200:
        description: OK response
    """
    result = []
    message = json.loads(request.stream.read().decode('utf-8'))
    for ruleset_name in host.list_rulesets():
        result.append(host.post(ruleset_name, message))
    return jsonify(result)


def _update_rulesets(request):
    if 'file' in request.files:
        file = request.files['file']
    if file and _allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
    execfile(UPLOAD_FOLDER + filename)
    global host
    host._execute = False
    db = host._databases
    create_host(db)


@app.route('/<ruleset_name>/definition', methods=['POST'])
def ruleset_definition_create(ruleset_name):
    """
    Upload new ruleset
    ---
    tags:
      - Rules engine
    parameters:
      - in: header
        name: Authorization
        schema:
          type: string
        description: "Basic base64encoded username:password"
        required: True
      - in: ruleset_name
        name: ruleset_name
      - name: body
        in: body
        required: True
        description: JSON message.
    responses:
      200:
        description: OK response
      403:
        description: Forbidden
        example: You don't have the permission to access the requested resource. It is either read-protected or not readable by the server
    """
    # curl -X POST http://127.0.0.1:5000/test/definition -F "file=@testimport.py"
    _authorize(request)
    if ruleset_name in host.list_rulesets():
        return "Ruleset {} already exists".format(ruleset_name)
    _update_rulesets(request)
    return jsonify({"Rulests registered": host.list_rulesets()})


@app.route('/<ruleset_name>/definition', methods=['PATCH'])
def ruleset_definition_update(ruleset_name):
    """
    Override existing ruleset
    ---
    tags:
      - Rules engine
    parameters:
      - in: header
        name: Authorization
        schema:
          type: string
        description: "Basic base64encoded username:password"
        required: True
      - in: ruleset_name
        name: ruleset_name
      - name: body
        in: body
        required: True
        description: JSON message
    responses:
      200:
        description: OK response
      403:
        description: Forbidden
        example: You don't have the permission to access the requested resource. It is either read-protected or not readable by the server
    """
    # curl -X POST http://127.0.0.1:5000/test/definition -F "file=@testimport.py"
    _authorize(request)
    if ruleset_name not in host.list_rulesets():
        return "Ruleset {} does not exist".format(ruleset_name)
    _update_rulesets(request)
    return jsonify({"Rulests registered": host.list_rulesets()})


@app.route('/<ruleset_name>/definition', methods=['GET'])
def ruleset_definition_request(ruleset_name):
    """
    Get ruleset definition
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
    responses:
      200:
        description: OK response
        example: {}
    """
    result = host.get_ruleset(ruleset_name)
    if result:
        return json.dumps(result.get_definition()) #jsonify(result.get_definition())
    else:
        abort(404)


@app.route('/<ruleset_name>/definition', methods=['DELETE'])
def ruleset_definition_delete(ruleset_name):
    """
    Delete ruleset
    ---
    tags:
      - Rules engine
    parameters:
      - in: header
        name: Authorization
        schema:
          type: string
        description: "Basic base64encoded username:password"
        required: True
      - in: ruleset_name
        name: ruleset_name
    responses:
      200:
        description: OK response
        example: 0
      403:
        description: Forbidden
        example: You don't have the permission to access the requested resource. It is either read-protected or not readable by the server
    """
    _authorize(request)
    host.delete_ruleset(ruleset_name)
    result = {"Rulests registered": host.list_rulesets()}
    return jsonify(result)


@app.route('/<user_name>/password', methods=['POST'])
def change_password(user_name):
    """
    Change password
    ---
    tags:
      - Rules engine
    parameters:
      - in: header
        name: Authorization
        schema:
          type: string
        description: "Basic base64encoded username:password"
        required: True
      - in: user_name
        name: user_name
    responses:
      200:
        description: OK response
        example: ""
      403:
        description: Forbidden
        example: You don't have the permission to access the requested resource. It is either read-protected or not readable by the server
    """
    response = _authorize(request)
    if response.username != user_name:
        abort(403)
    payload = json.loads(request.stream.read().decode('utf-8'))
    users[user_name] = payload['password']
    return ""


@app.route('/<ruleset_name>/state', methods=['GET'])
def get_state_request(ruleset_name):
    """
    Get ruleset state
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
    responses:
      200:
        description: OK response
        example: {"state"}
    """
    result = host.get_state(ruleset_name, None)
    return jsonify(result)


@app.route('/<ruleset_name>/state', methods=['POST'])
def patch_state_request(ruleset_name):
    """
    Change ruleset state
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
    responses:
      200:
        description: OK response
        example: {"state"}
   """
    message = json.loads(request.stream.read().decode('utf-8'))
    result = host.patch_state(ruleset_name, message)
    return jsonify(result)


@app.route('/<ruleset_name>/state/<sid>', methods=['POST'])
def set_state_sid_request(ruleset_name, sid):
    """
    Set ruleset state sid
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
      - in: sid
        name: sid
    responses:
      200:
        description: OK response
        example: {"state"}
   """
    message = json.loads(request.stream.read().decode('utf-8'))
    message['sid'] = sid
    result = host.patch_state(ruleset_name, message)
    return jsonify(result)


@app.route('/<ruleset_name>/state/<sid>', methods=['GET'])
def get_state_sid_request(ruleset_name, sid):
    """
    Get ruleset state sid
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
      - in: sid
        name: sid
    responses:
      200:
        description: OK response
        example: {"state"}
   """
    result = host.get_state(ruleset_name, sid)
    return jsonify(result)


@app.route('/<ruleset_name>/events', methods=['POST'])
def post_events(ruleset_name):
    """
    Post events to the ruleset
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
      - name: body
        in: body
        required: True
        description: JSON message
    responses:
      200:
        description: OK response
        example: {"state"}
   """
    message = json.loads(request.stream.read().decode('utf-8'))
    result = host.post(ruleset_name, message)
    return jsonify(result)


@app.route('/<ruleset_name>/events/<sid>', methods=['POST'])
def post_sid_events(ruleset_name, sid):
    """
    Post sid events to the ruleset
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
      - in: sid
        name: sid
      - name: body
        in: body
        required: True
        description: JSON message
    responses:
      200:
        description: OK response
        example: {"state"}
   """
    message = json.loads(request.stream.read().decode('utf-8'))
    message['sid'] = sid
    result = host.post(ruleset_name, message)
    return jsonify(result)


@app.route('/<ruleset_name>/facts', methods=['POST'])
def default_facts_request(ruleset_name):
    """
    Post factss to the ruleset
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
      - name: body
        in: body
        required: True
        description: JSON message
    responses:
      200:
        description: OK response
        example: {"state"}
   """
    message = json.loads(request.stream.read().decode('utf-8'))
    result = host.assert_fact(ruleset_name, message)
    return jsonify(result)


@app.route('/<ruleset_name>/facts/<sid>', methods=['POST'])
def facts_request(ruleset_name, sid):
    """
    Post sid facts to the ruleset
    ---
    tags:
      - Rules engine
    parameters:
      - in: ruleset_name
        name: ruleset_name
      - in: sid
        name: sid
      - name: body
        in: body
        required: True
        description: JSON message
    responses:
      200:
        description: OK response
        example: {"state"}
   """
    message = json.loads(request.stream.read().decode('utf-8'))
    message['sid'] = sid
    result = host.assert_fact(ruleset_name, message)
    return jsonify(result)


def create_host(databases=None, state_cache_size=1024):
    ruleset_definitions = {}
    for rset in _rulesets:
        ruleset_name, ruleset_definition = rset.define()
        ruleset_definitions[ruleset_name] = ruleset_definition

    global host
    host = engine.Host(ruleset_definitions, databases, state_cache_size)
    for start in _start_functions:
        start(host)

    host.run()
    return host


def app_run(host, port):
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(host=host, port=port)
