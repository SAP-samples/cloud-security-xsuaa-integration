#!/usr/bin/env python3
import abc
import subprocess
import urllib.request
from urllib.parse import urlencode
from urllib.error import HTTPError
from base64 import b64encode
import json
import unittest
import logging
import os
import time
import re
from getpass import getpass

# Usage information
# To run this script you must be logged into CF via 'cf login' Also make sure
# to change settings in vars.yml to your needs.  This script deploys sample
# apps and fires post request against their endpoints.  For some samples it
# needs to create a password token for which you need to provide your password
# (same as you would use for 'cf login').  You can do this by either supplying
# it via the system environment variable 'CFPASSWORD' or by typing when the
# script prompts for the password.  The same goes for the username with the
# variable 'CFUSER'.

# Dependencies
# The script depends on python3 and the cloud foundry command line tool 'cf'.

# Running the script
# If the script is made executable, it can be started with cd
# It can also be started like so: python3 ./deploy_and_test.py
# By default it will run all unit tests.
# It is also possible to run specific test classes:
# python3 -m unittest deploy_and_test.TestJavaSecurity.test_hello_java_security
# This would only the run the test called 'test_hello_java_security'
# inside the test class 'TestJavaSecurity' inside the deploy_and_test.py file.

logging.basicConfig(level=logging.INFO)


class Credentials:
    def __init__(self):
        self.username = self.__get_env_variable('CFUSER', lambda: input("Username: "))
        self.password = self.__get_env_variable('CFPASSWORD', lambda: getpass())

    def __get_env_variable(self, env_variable_name, prompt_function):
        value = os.getenv(env_variable_name)
        if (value is None):
            value = prompt_function()
        return value


credentials = Credentials()


# Abstract base class for sample app tests classes 
class SampleTest(abc.ABC, unittest.TestCase):

    @abc.abstractmethod
    def get_app(self):
        """Should return the sample app that should be tested """
        self.skipTest('Dont run abstract base class')
        return CFApp(None, None)

    def setUp(self):
        vars_file = open('./vars.yml')
        self.vars_parser = VarsParser(vars_file.read())
        vars_file.close()
        self.cf_apps = CFApps()
        self.__deployed_app = None
        self.__api_access = None
        self.credentials = credentials

        self.get_app().deploy()
        time.sleep(2)  # waiting for deployed apps to be available

    def tearDown(self):
        self.get_app().delete()
        if self.__api_access is not None:
            self.__api_access.delete()

    def add_user_to_role(self, role):
        logging.info('Assigning role collection {} for user {}'.format(role, self.credentials.username))
        user = self.__get_api_access().get_user_by_username(self.credentials.username)
        user_id = user.get('id')
        resp = self.__get_api_access().add_user_to_group(user_id, role)
        if (not resp.is_ok):
            logging.error("Could not set role " + role)
            exit()

    def perform_get_request(self, path, username=None, password=None):
        if (username is not None and password is not None):
            authorization_value = b64encode(bytes(username + ':' + password + self.__get_2factor_auth_code(), 'utf-8')).decode("ascii")
            return self.__perform_get_request(path=path, additional_headers={'Authorization': 'Basic ' + authorization_value})
        return self.__perform_get_request(path=path)

    def perform_get_request_with_token(self, path, additional_headers={}):
        access_token = self.get_token().get('access_token')
        if (access_token is None):
            logging.error("Cannot continue without access token")
            exit()
        return self.__perform_get_request(path=path, access_token=access_token, additional_headers=additional_headers)

    def get_deployed_app(self):
        if (self.__deployed_app is None):
            deployed_app = self.cf_apps.app_by_name(self.get_app().name)
            if (deployed_app is None):
                logging.error('Could not find app: ' + self.get_app().name)
                exit()
            self.__deployed_app = deployed_app
        return self.__deployed_app

    def get_token(self):
        deployed_app = self.get_deployed_app()
        return HttpUtil().get_token(
            xsuaa_service_url=deployed_app.xsuaa_service_url,
            clientid=deployed_app.clientid,
            clientsecret=deployed_app.clientsecret,
            grant_type='password',
            username=self.credentials.username,
            password=self.credentials.password + self.__get_2factor_auth_code())

    def __get_api_access(self):
        if (self.__api_access is None):
            deployed_app = self.get_deployed_app()
            self.__api_access = ApiAccessService(
                xsuaa_service_url=deployed_app.xsuaa_service_url,
                xsuaa_api_url=deployed_app.xsuaa_api_url)
        return self.__api_access

    def __perform_get_request(self, path, access_token=None, additional_headers={}):
        url = 'https://{}-{}.{}{}'.format(
            self.get_app().name,
            self.vars_parser.user_id,
            self.vars_parser.landscape_apps_domain,
            path)
        logging.info('GET request to {} {}'.format(url, 'using access token' if access_token else ''))
        resp = HttpUtil().get_request(url, access_token=access_token, additional_headers=additional_headers)
        logging.info('Response: ' + str(resp))
        return resp

    def __get_2factor_auth_code(self):
        auth_code = ""
        if (os.getenv('ENABLE_2_FACTOR') is not None):
            auth_code = input("2-Factor Authenticator Code: ") or ""
        return auth_code

class TestTokenClient(SampleTest):

    def get_app(self):
        return CFApp(name='java-tokenclient-usage', xsuaa_service_name='xsuaa-token-client')

    def test_hello_token_client(self):
        response = self.perform_get_request('/hello-token-client')
        self.assertEqual(response.status, 200, 'Expected HTTP status 200')
        body = response.body
        self.assertIsNotNone(body)
        self.assertRegex(body, "Access-Token: ")
        self.assertRegex(body, "Access-Token-Payload: ")
        self.assertRegex(body, "Expired-At: ")


class TestJavaSecurity(SampleTest):

    def get_app(self):
        return CFApp(name='java-security-usage', xsuaa_service_name='xsuaa-java-security')

    def test_hello_java_security(self):
        resp = self.perform_get_request('/hello-java-security')
        self.assertEqual(resp.status, 401, 'Expected HTTP status 401')

        resp = self.perform_get_request_with_token('/hello-java-security')
        self.assertEqual(resp.status, 403, 'Expected HTTP status 403')

        self.add_user_to_role('JAVA_SECURITY_SAMPLE_Viewer')
        resp = self.perform_get_request_with_token('/hello-java-security')
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')
        xsappname = self.get_deployed_app().get_credentials_property('xsappname')
        expected_scope = xsappname + '.Read'
        self.assertIsNotNone(resp.body)
        self.assertRegex(resp.body, self.credentials.username, "Did not find username '{}' in response body".format(self.credentials.username))
        self.assertRegex(resp.body, expected_scope, "Expected to find scope '{}' in response body: ".format(expected_scope))


class TestSpringSecurity(SampleTest):

    def get_app(self):
        return CFApp(name='spring-security-xsuaa-usage', xsuaa_service_name='xsuaa-authentication',
                     app_router_name='approuter-spring-security-xsuaa-usage')

    def test_sayHello(self):
        resp = self.perform_get_request('/v1/sayHello')
        self.assertEqual(resp.status, 401, 'Expected HTTP status 401')

        resp = self.perform_get_request_with_token('/v1/sayHello')
        self.assertEqual(resp.status, 403, 'Expected HTTP status 403')

        self.add_user_to_role('Viewer')
        resp = self.perform_get_request_with_token('/v1/sayHello')
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')
        xsappname = self.get_deployed_app().get_credentials_property('xsappname')
        self.assertRegex(resp.body, xsappname, 'Expected to find xsappname in response')

    def test_tokenFlows(self):
        self.add_user_to_role('Viewer')
        resp = self.perform_get_request_with_token('/v2/sayHello')
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')

        resp = self.perform_get_request_with_token('/v3/requestClientCredentialsToken')
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')

        resp = self.perform_get_request_with_token('/v3/requestUserToken')
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')
       
        token = self.get_token()
        pathWithRefreshToken = '/v3/requestRefreshToken/' + token.get('refresh_token')
        resp = self.perform_get_request_with_token(pathWithRefreshToken)
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')


class TestJavaBuildpackApiUsage(SampleTest):

    def get_app(self):
        return CFApp(name='sap-java-buildpack-api-usage',
                     xsuaa_service_name='xsuaa-buildpack',
                     app_router_name='approuter-sap-java-buildpack-api-usage')

    def test_hello_token_servlet(self):
        resp = self.perform_get_request('/hello-token')
        self.assertEqual(resp.status, 401, 'Expected HTTP status 401')

        resp = self.perform_get_request_with_token('/hello-token')
        self.assertEqual(resp.status, 403, 'Expected HTTP status 403')

        self.add_user_to_role('Buildpack_API_Viewer')
        resp = self.perform_get_request_with_token('/hello-token')
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')
        self.assertRegex(resp.body, self.credentials.username, 'Expected to find username in response')


class SpringSecurityBasicAuthTest(SampleTest):

    def get_app(self):
        return CFApp(name='spring-security-basic-auth', xsuaa_service_name='xsuaa-basic')

    def test_hello_token(self):
        resp = self.perform_get_request('/hello-token')
        self.assertEqual(resp.status, 401, 'Expected HTTP status 401')

        resp = self.perform_get_request('/hello-token', username=self.credentials.username, password=self.credentials.password)
        self.assertEqual(resp.status, 403, 'Expected HTTP status 403')

    def test_hello_token_status_ok(self):
        # second test needed because tokens are cached in application
        self.add_user_to_role('BASIC_AUTH_API_Viewer')
        resp = self.perform_get_request('/hello-token', username=self.credentials.username, password=self.credentials.password)
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')
        self.assertRegex(resp.body, self.credentials.username, 'Expected to find username in response')


class SpringWebfluxSecurityXsuaaUsage(SampleTest):

    def get_app(self):
        return CFApp(name='spring-webflux-security-xsuaa-usage',
                     xsuaa_service_name='xsuaa-webflux',
                     app_router_name='approuter-spring-webflux-security-xsuaa-usage')

    def test_say_hello(self):
        resp = self.perform_get_request('/v1/sayHello')
        self.assertEqual(resp.status, 401, 'Expected HTTP status 401')

        resp = self.perform_get_request_with_token('/v1/sayHello')
        self.assertEqual(resp.status, 403, 'Expected HTTP status 403')

        self.add_user_to_role('Webflux_API_Viewer')
        resp = self.perform_get_request_with_token('/v1/sayHello')
        self.assertEqual(resp.status, 200, 'Expected HTTP status 200')
        self.assertRegex(resp.body, self.credentials.username, 'Expected to find username in response')


class HttpUtil:

    class HttpResponse:
        def __init__(self, response, error=None):
            if (error):
                self.body = error.reason
                self.status = error.code
                self.is_ok = False
            else:
                self.body = response.read().decode()
                self.status = response.status
                self.is_ok = True
            logging.debug(self)

        @classmethod
        def error(cls, error):
            return cls(response=None, error=error)

        def __str__(self):
            if (len(self.body) > 150):
                body = self.body[:150] + '... (truncated)'
            else:
                body = self.body
            return 'HTTP status: {}, body: {}'.format(self.status, body)

    def get_request(self, url, access_token=None, additional_headers={}):
        logging.debug('Performing GET request to ' + url)
        req = urllib.request.Request(url, method='GET')
        self.__add_headers(req, access_token, additional_headers)
        return self.__execute(req)

    def post_request(self, url, data=None, access_token=None, additional_headers={}):
        logging.debug('Performing POST request to ' + url)
        req = urllib.request.Request(url, data=data, method='POST')
        self.__add_headers(req, access_token, additional_headers)
        return self.__execute(req)

    def get_token(self, xsuaa_service_url, clientid, clientsecret, grant_type, username=None, password=None):
        post_req_body = urlencode({'client_id': clientid,
                                   'client_secret': clientsecret,
                                   'grant_type': grant_type,
                                   'response_type': 'token',
                                   'username': username,
                                   'password': password}).encode()
        url = xsuaa_service_url + '/oauth/token'
        resp = HttpUtil().post_request(url, data=post_req_body)
        if (resp.is_ok):
            return json.loads(resp.body)
        else:
            logging.error('Could not retrieve access token')
            return None

    def __add_headers(self, req, access_token, additional_headers):
        if (access_token):
            self.__add_header(req, 'Authorization', 'Bearer ' + access_token)
        for header_key in additional_headers:
            self.__add_header(req, header_key, additional_headers[header_key])

    def __add_header(self, req, header_name, header_value):
        logging.debug('adding HTTP header {} -> {}'.format(header_name, header_value))
        req.add_header(header_name, header_value)

    def __execute(self, req):
        try:
            res = urllib.request.urlopen(req)
            return HttpUtil.HttpResponse(response=res)
        except HTTPError as error:
            return HttpUtil.HttpResponse.error(error=error)


class ApiAccessService:

    def __init__(self, xsuaa_service_url, xsuaa_api_url, name='api-access-service'):
        self.name = name
        self.service_key_name = self.name + '-sk'
        self.xsuaa_api_url = xsuaa_api_url
        self.xsuaa_service_url = xsuaa_service_url
        self.http_util = HttpUtil()
        subprocess.run(['cf', 'create-service', 'xsuaa', 'apiaccess', name])
        subprocess.run(['cf', 'create-service-key', name,
                        self.service_key_name])
        service_key_output = subprocess.run(
            ['cf', 'service-key', name, self.service_key_name], capture_output=True)
        lines = service_key_output.stdout.decode().split('\n')
        self.data = json.loads(''.join(lines[1:]))
        logging.debug('Created ' + str(self))

    def delete(self):
        subprocess.run(['cf', 'delete-service-key', '-f',
                        self.name, self.service_key_name])
        subprocess.run(['cf', 'delete-service', '-f', self.name])

    def get_user_by_username(self, username):
        query_parameters = urlencode(
            {'filter': 'userName eq "{}"'.format(username)})
        url = '{}/Users?{}'.format(self.xsuaa_api_url, query_parameters)
        res = self.http_util.get_request(
            url, access_token=self.__get_access_token())
        if (not res.is_ok):
            self.__panic_user_not_found(username)
        users = json.loads(res.body).get('resources')
        if (users is None or len(users) < 1):
            self.__panic_user_not_found(username)
        return users[0]

    def add_user_to_group(self, user_id, group_name):
        post_req_body = json.dumps(
            {'value': user_id, 'origin': 'ldap', 'type': 'USER'}).encode()
        url = '{}/Groups/{}/members'.format(self.xsuaa_api_url, group_name)
        return self.http_util.post_request(url, data=post_req_body,
                                           access_token=self.__get_access_token(),
                                           additional_headers={'Content-Type': 'application/json'})

    def __panic_user_not_found(self, username):
        logging.error('Could not find user {}'.format(username))
        exit()

    def __get_access_token(self):
        token = self.http_util.get_token(
            xsuaa_service_url=self.xsuaa_service_url,
            clientid=self.data.get('clientid'),
            clientsecret=self.data.get('clientsecret'),
            grant_type='client_credentials')
        return token.get('access_token')

    def __str__(self):
        formatted_data = json.dumps(self.data, indent=2)
        return 'Name: {}, Service-Key-Name: {}, Data: {}'.format(
            self.name, self.service_key_name, formatted_data)


class CFApps:
    def __init__(self):
        token = subprocess.run(['cf', 'oauth-token'], capture_output=True)
        target = subprocess.run(['cf', 'target'], capture_output=True)
        self.bearer_token = token.stdout.strip().decode()
        [self.cf_api_endpoint, self.user_id, space_name] = self.__parse_target_output(target.stdout.decode())
        space = subprocess.run(['cf', 'space', space_name, '--guid'], capture_output=True)
        self.space_guid = space.stdout.decode().strip()

    def app_by_name(self, app_name):
        url = '{}/apps?space_guids={}&names={}'.format(self.cf_api_endpoint, self.space_guid, app_name)
        paginated_apps = self.__get_with_token(url)
        app = self.__get_first_paginated_resource(paginated_apps)
        if (app is None):
            logging.error('App {} not found'.format(app_name))
            exit()
        vcap_services = self.__vcap_services_by_guid(app.get('guid'))
        return DeployedApp(vcap_services)

    def __get_first_paginated_resource(self, paginated_resources):
        pagination = paginated_resources.get('pagination')
        if (pagination and pagination.get('total_results') > 0):
            if (pagination.get('total_results') > 1):
                logging.warn(
                    'More than one resource found, taking the first one!')
            return paginated_resources.get('resources')[0]

    def __get_with_token(self, url):
        res = HttpUtil().get_request(url, additional_headers={
            'Authorization': self.bearer_token})
        return json.loads(res.body)

    def __vcap_services_by_guid(self, guid):
        env = self.__get_with_token(
            self.cf_api_endpoint + '/apps/{}/env'.format(guid))
        return env.get('system_env_json').get('VCAP_SERVICES')

    def __parse_target_output(self, target_output):
        api_endpoint_match = re.search(r'api endpoint:(.*)', target_output)
        user_id_match = re.search(r'user:(.*)', target_output)
        space_match = re.search(r'space:(.*)', target_output)
        api_endpoint = api_endpoint_match.group(1)
        user_id = user_id_match.group(1)
        space_name = space_match.group(1)
        return [api_endpoint.strip() + '/v3', user_id.strip(), space_name.strip()]


class VarsParser:

    """
        This class parses the content of the vars.yml file in the samples directory, e.g:
    >>> vars = VarsParser('# change to another value, e.g. your User ID\\nID: X0000000\\n# Choose cfapps.eu10.hana.ondemand.com for the EU10 landscape, cfapps.us10.hana.ondemand.com for US10\\nLANDSCAPE_APPS_DOMAIN: cfapps.sap.hana.ondemand.com\\n#LANDSCAPE_APPS_DOMAIN: api.cf.eu10.hana.ondemand.com\\n')
    >>> vars.user_id
    'X0000000'
    >>> vars.landscape_apps_domain
    'cfapps.sap.hana.ondemand.com'

    """

    def __init__(self, vars_file_content):
        self.vars_file_content = self.__strip_comments(vars_file_content)

    @property
    def user_id(self):
        id_match = re.search(r'ID:(.*)', self.vars_file_content)
        return id_match.group(1).strip()

    @property
    def landscape_apps_domain(self):
        landscape_match = re.search(r'LANDSCAPE_APPS_DOMAIN:(.*)',
                                    self.vars_file_content)
        return landscape_match.group(1).strip()

    def __strip_comments(self, content):
        result = ''
        for line in content.split('\n'):
            commented_line = re.search(r'\w*#', line)
            if (commented_line is None):
                result += line + '\n'
        return result


class DeployedApp:
    """
        This class parses VCAP_SERVICES (as dictionary) and supplies its content, e.g.:
    >>> vcap_services = {'xsuaa': [{'label': 'xsuaa', 'provider': None, 'plan': 'application', 'name': 'xsuaa-java-security', 'tags': ['xsuaa'], 'instance_name': 'xsuaa-java-security', 'binding_name': None, 'credentials': {'tenantmode': 'dedicated', 'sburl': 'https://internal-xsuaa.authentication.sap.hana.ondemand.com', 'clientid': 'sb-java-security-usage!t1785', 'xsappname': 'java-security-usage!t1785', 'clientsecret': 'b1GhPeHArXQCimhsCiwOMzT8wOU=', 'url': 'https://saschatest01.authentication.sap.hana.ondemand.com', 'uaadomain': 'authentication.sap.hana.ondemand.com', 'verificationkey': '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/jN5v1mp/TVn9nTQoYVIUfCsUDHa3Upr5tDZC7mzlTrN2PnwruzyS7w1Jd+StqwW4/vn87ua2YlZzU8Ob0jR4lbOPCKaHIi0kyNtJXQvQ7LZPG8epQLbx0IIP/WLVVVtB8bL5OWuHma3pUnibbmATtbOh5LksQ2zLMngEjUF52JQyzTpjoQkahp0BNe/drlAqO253keiY63FL6belKjJGmSqdnotSXxB2ym+HQ0ShaNvTFLEvi2+ObkyjGWgFpQaoCcGq0KX0y0mPzOvdFsNT+rBFdkHiK+Jl638Sbim1z9fItFbH9hiVwY37R9rLtH1YKi3PuATMjf/DJ7mUluDQIDAQAB-----END PUBLIC KEY-----', 'apiurl': 'https://api.authentication.sap.hana.ondemand.com', 'identityzone': 'saschatest01', 'identityzoneid': '54d48a27-0ff4-42b8-b39e-a2b6df64d78a', 'tenantid': '54d48a27-0ff4-42b8-b39e-a2b6df64d78a'}, 'syslog_drain_url': None, 'volume_mounts': []}]}
    >>> app = DeployedApp(vcap_services)
    >>> app.get_credentials_property('clientsecret')
    'b1GhPeHArXQCimhsCiwOMzT8wOU='
    >>> app.clientsecret
    'b1GhPeHArXQCimhsCiwOMzT8wOU='

    """

    def __init__(self, vcap_services):
        self.vcap_services = vcap_services
        self.xsuaa_properties = self.vcap_services.get('xsuaa')[0]

    @property
    def xsuaa_api_url(self):
        return self.get_credentials_property('apiurl')

    @property
    def xsuaa_service_url(self):
        return self.get_credentials_property('url')

    @property
    def clientid(self):
        return self.get_credentials_property('clientid')

    @property
    def clientsecret(self):
        return self.get_credentials_property('clientsecret')

    def get_credentials_property(self, property_name):
        return self.xsuaa_properties.get('credentials').get(property_name)

    def __str__(self):
        return json.dumps(self.vcap_services, indent=2)


class CFApp:
    def __init__(self, name, xsuaa_service_name, app_router_name=None):
        if (name is None or xsuaa_service_name is None):
            raise(Exception('Name and xsua service name must be provided'))
        self.name = name
        self.xsuaa_service_name = xsuaa_service_name
        self.app_router_name = app_router_name

    @property
    def working_dir(self):
        return './' + self.name

    def deploy(self):
        subprocess.run(['cf', 'create-service', 'xsuaa', 'application', self.xsuaa_service_name, '-c', 'xs-security.json'], cwd=self.working_dir)
        subprocess.run(['mvn', 'clean', 'verify'], cwd=self.working_dir)
        subprocess.run(['cf', 'push', '--vars-file', '../vars.yml'], cwd=self.working_dir)

    def delete(self):
        subprocess.run(['cf', 'delete', '-f', '-r', self.name])
        if (self.app_router_name is not None):
            subprocess.run(['cf', 'delete', '-f', '-r', self.app_router_name])
        subprocess.run(
            ['cf', 'delete-service', '-f', self.xsuaa_service_name])

    def __str__(self):
        return 'Name: {}, Xsuaa-Service-Name: {}, App-Router-Name: {}'.format(
            self.name, self.xsuaa_service_name, self.app_router_name)


def is_logged_off():
    target = subprocess.run(['cf', 'target'], capture_output=True)
    return not target or target.stdout.decode().startswith('FAILED')


if __name__ == '__main__':
    if (is_logged_off()):
        print('To run this script you must be logged into CF via "cf login"')
        print('Also make sure to change settings in vars.yml')
    else:
        import doctest
        doctest.testmod()
        unittest.main()
