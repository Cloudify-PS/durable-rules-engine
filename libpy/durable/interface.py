import os
import json
from . import engine
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException
from flask_httpauth import HTTPBasicAuth
from werkzeug.serving import run_simple
from werkzeug.serving import make_ssl_devcert
from werkzeug.utils import secure_filename
from werkzeug.http import parse_authorization_header
from common import _start_functions, _rulesets

UPLOAD_FOLDER = 'rules/'
auth = HTTPBasicAuth()
users = {
    "admin": "admin"
}


class Application(object):

    def __init__(self, host, host_name, port, routing_rules = None, run = None):
        self._host = host
        self._host_name = host_name
        self._port = port
        self._run = run
        if not routing_rules:
            routing_rules = []

        routing_rules.append(Rule('/rulesets', endpoint=self._list_rulesets))
        routing_rules.append(Rule('/rulesets/events', endpoint=self._all_events_request))
        routing_rules.append(Rule('/<ruleset_name>/definition', endpoint=self._ruleset_definition_request))
        routing_rules.append(Rule('/<ruleset_name>/state', endpoint=self._default_state_request))
        routing_rules.append(Rule('/<ruleset_name>/state/<sid>', endpoint=self._state_request))
        routing_rules.append(Rule('/<ruleset_name>/events', endpoint=self._default_events_request))
        routing_rules.append(Rule('/<ruleset_name>/events/<sid>', endpoint=self._events_request))
        routing_rules.append(Rule('/<ruleset_name>/facts', endpoint=self._default_facts_request))
        routing_rules.append(Rule('/<ruleset_name>/facts/<sid>', endpoint=self._facts_request))
        routing_rules.append(Rule('/<user_name>/password', endpoint=self._reset_password))
        self._url_map = Map(routing_rules)

    def _allowed_file(self, filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ['py']

    def _authorize(self, request, environ, start_response):
        print "Authorize"
        if request.headers.get('Authorization'):
            credentials = parse_authorization_header(
                request.headers.get('Authorization'))
            if not credentials or not \
                    (credentials.type == 'basic'
                     and credentials.password == users[credentials.username]):
                return Response('Not Authorized', status=403)
            return credentials
        else:
            return Response('Not Authorized', status=403)

    def _ruleset_definition_request(self, environ, start_response, ruleset_name):
        def encode_promise(obj):
            if isinstance(obj, engine.Promise) or hasattr(obj, '__call__'):
                return 'function'
            raise TypeError(repr(obj) + " is not JSON serializable")

        request = Request(environ)
        if request.method == 'GET':
            result = self._host.get_ruleset(ruleset_name)
            return Response(json.dumps(result.get_definition(), default=encode_promise))(environ, start_response)
        elif request.method == 'POST':
            # curl -X POST http://127.0.0.1:5000/test/definition -F "file=@testimport.py"
            response = self._authorize(request, environ, start_response)
            if isinstance(response, Response):
                return response(environ, start_response)
            file = request.files['file']
            if file and self._allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(UPLOAD_FOLDER, filename))
            execfile(UPLOAD_FOLDER + filename)
            self._host._execute = False
            self._host = create_host()
            result = { "Rulests registered": self._host.list_rulesets()}
        elif request.method == 'DELETE':
            response = self._authorize(request, environ, start_response)
            if isinstance(response, Response):
                return response(environ, start_response)
            self._host.delete_ruleset(ruleset_name)
            result = {"Rulests registered": self._host.list_rulesets()}
        return Response(json.dumps(result))(environ, start_response)

    def _list_rulesets(self, environ, start_response):
        result = self._host.list_rulesets()
        return Response(json.dumps(result))(environ, start_response)

    def _reset_password(self, environ, start_response, user_name):
        request = Request(environ)
        response = self._authorize(request, environ, start_response)
        if isinstance(response, Response):
            return response(environ, start_response)
        if response.username != user_name:
            return Response('Not Authorized', status=403)(environ, start_response)
        payload = json.loads(request.stream.read().decode('utf-8'))
        users[user_name] = payload['password']
        return Response()(environ, start_response)

    def _state_request(self, environ, start_response, ruleset_name, sid):
        request = Request(environ)
        result = None
        if request.method == 'GET':
            result = self._host.get_state(ruleset_name, sid)
            return Response(json.dumps(result))(environ, start_response)
        elif request.method == 'POST':
            message = json.loads(request.stream.read().decode('utf-8'))
            message['sid'] = sid
            result = self._host.patch_state(ruleset_name, message)
            return Response(json.dumps({'outcome': result}))(environ, start_response)

    def _default_state_request(self, environ, start_response, ruleset_name):
        request = Request(environ)
        result = None
        if request.method == 'GET':
            result = self._host.get_state(ruleset_name, None)
            return Response(json.dumps(result))(environ, start_response)
        elif request.method == 'POST':
            message = json.loads(request.stream.read().decode('utf-8'))
            result = self._host.patch_state(ruleset_name, message)
            return Response(json.dumps({'outcome': result}))(environ, start_response)
        
    def _events_request(self, environ, start_response, ruleset_name, sid):
        request = Request(environ)
        result = None
        if request.method == 'POST':
            message = json.loads(request.stream.read().decode('utf-8'))
            message['sid'] = sid
            result = self._host.post(ruleset_name, message)
            return Response(json.dumps({'outcome': result}))(environ, start_response)

    def _default_events_request(self, environ, start_response, ruleset_name):
        request = Request(environ)
        result = None
        if request.method == 'POST':
            message = json.loads(request.stream.read().decode('utf-8'))
            result = self._host.post(ruleset_name, message)
            return Response(json.dumps({'outcome': result}))(environ, start_response)

    def _all_events_request(self, environ, start_response):
        request = Request(environ)
        result = None
        if request.method == 'POST':
            message = json.loads(request.stream.read().decode('utf-8'))
            for ruleset_name in self._host.list_rulesets():
                result = self._host.post(ruleset_name, message)
            return Response(json.dumps({'outcome': result}))(environ, start_response)

    def _facts_request(self, environ, start_response, ruleset_name, sid):
        request = Request(environ)
        result = None
        if request.method == 'POST':
            message = json.loads(request.stream.read().decode('utf-8'))
            message['sid'] = sid
            result = self._host.assert_fact(ruleset_name, message)
            return Response(json.dumps({'outcome': result}))(environ, start_response)

    def _default_facts_request(self, environ, start_response, ruleset_name):
        request = Request(environ)
        result = None
        if request.method == 'POST':
            message = json.loads(request.stream.read().decode('utf-8'))
            result = self._host.assert_fact(ruleset_name, message)
            return Response(json.dumps({'outcome': result}))(environ, start_response)

    def _not_found(self, environ, start_response):
        return Exception('File not found')

    def __call__(self, environ, start_response):
        request = Request(environ)
        adapter = self._url_map.bind_to_environ(environ)
        try:
            endpoint, values = adapter.match()
            return endpoint(environ, start_response, **values)
        except HTTPException as e:
            return e

    def run(self):
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
        if self._run:
            self._run(self._host, self)
        elif self._port != 443:
            run_simple(self._host_name, self._port, self, threaded = True)
        else:
            make_ssl_devcert('key', host = self._host_name)
            run_simple(self._host_name, self._port, self, threaded = True, ssl_context = ('key.crt', 'key.key'))


def create_host(databases=None, state_cache_size=1024):
    ruleset_definitions = {}
    for rset in _rulesets:
        ruleset_name, ruleset_definition = rset.define()
        ruleset_definitions[ruleset_name] = ruleset_definition

    main_host = engine.Host(ruleset_definitions, databases, state_cache_size)
    for start in _start_functions:
        start(main_host)

    main_host.run()
    return main_host