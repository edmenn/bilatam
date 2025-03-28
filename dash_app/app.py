import dash
from dash import html
from flask import Flask, redirect, session, request, url_for
from authlib.integrations.flask_client import OAuth
import os

server = Flask(__name__)
server.secret_key = os.environ.get("SECRET_KEY", "secret")
app = dash.Dash(__name__, server=server, routes_pathname_prefix='/')

oauth = OAuth(server)
keycloak = oauth.register(
    name='keycloak',
    client_id='dashboard',
    client_secret='TU_CLIENT_SECRET',
    access_token_url='http://keycloak:8080/realms/miempresa/protocol/openid-connect/token',
    authorize_url='http://keycloak:8080/realms/miempresa/protocol/openid-connect/auth',
    userinfo_endpoint='http://keycloak:8080/realms/miempresa/protocol/openid-connect/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)

@server.route('/login')
def login():
    return keycloak.authorize_redirect(redirect_uri=url_for('auth', _external=True))

@server.route('/auth')
def auth():
    token = keycloak.authorize_access_token()
    session['user'] = keycloak.parse_id_token(token)
    return redirect('/')

@server.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.server.before_request
def require_login():
    allowed_routes = ['login', 'auth', 'static']
    if request.endpoint not in allowed_routes and 'user' not in session:
        return redirect('/login')

app.layout = html.Div([
    html.H1("Dashboard Seguro con Keycloak"),
    html.P(id='welcome'),
    html.A("Cerrar sesión", href="/logout")
])

@app.callback(
    dash.Output('welcome', 'children'),
    dash.Input('welcome', 'id')
)
def update_user(_):
    if 'user' in session:
        return f"Bienvenido, {session['user'].get('preferred_username', 'usuario')}!"
    return "Cargando..."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8050, debug=True)
