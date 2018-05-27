import os
from saraki import Saraki
from saraki import require_auth
from saraki.model import database

app = Saraki(__name__, db=None)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('TEST_DATABASE_URI')
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


with app.app_context():
    database.create_all()


if __name__ == '__main__':
    app.run()
