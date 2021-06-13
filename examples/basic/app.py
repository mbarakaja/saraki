import os
from saraki import Saraki
from saraki import require_auth
from saraki.model import database

app = Saraki(__name__, db=None)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
database.init_app(app)


@app.route('/')
def index():
    return 'Home'


@app.route('/locked')
@require_auth()
def locked():
    return 'locked'


@app.route('/<sub:username>-info')
@require_auth()
def user_info(username):
    return f'This information is just for {username}'


@app.route('/orgs/<aud:orgname>-info')
@require_auth()
def org_info(orgname):
    return f'This information is just for {orgname}'


if __name__ == '__main__':
    with app.app_context():
        database.create_all()
    app.run(host='0.0.0.0', port='5000')
