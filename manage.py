# manage.py
import os

from flask_script import Manager, Server, Command, Option
from flask_migrate import Migrate, MigrateCommand

from project.server import app, db, models


migrate = Migrate(app, db)
manager = Manager(app)

class GunicornServer(Command):

    description = 'Run the app within Gunicorn'

    def __init__(self, host='0.0.0.0', port=8000, workers=4):
        self.port = port
        self.host = host
        self.workers = workers

    def get_options(self):
        return (
            Option('-H', '--host',
                   dest='host',
                   default=self.host),

            Option('-p', '--port',
                   dest='port',
                   type=int,
                   default=self.port),

            Option('-w', '--workers',
                   dest='workers',
                   type=int,
                   default=self.workers),
        )

    def __call__(self, app, host, port, workers):

        from gunicorn import version_info

        if version_info < (0, 9, 0):
            from gunicorn.arbiter import Arbiter
            from gunicorn.config import Config
            arbiter = Arbiter(Config({'bind': "%s:%d" % (host, int(port)),'workers': workers}), app)
            arbiter.run()
        else:
            from gunicorn.app.base import Application

            class FlaskApplication(Application):
                def init(self, parser, opts, args):
                    return {
                        'bind': '{0}:{1}'.format(host, port),
                        'workers': workers 
                    }

                def load(self):
                    return app

            FlaskApplication().run()


manager.add_command("runserver", GunicornServer(host='0.0.0.0', port=8000))
# manager.add_command("runserver", Server(host='0.0.0.0', port='8000'))
# migrations
manager.add_command('db', MigrateCommand)


@manager.command
def create_db():
    """Creates the db tables."""
    db.create_all()


@manager.command
def drop_db():
    """Drops the db tables."""
    db.drop_all()


if __name__ == '__main__':
    db.create_all()
    manager.run()
