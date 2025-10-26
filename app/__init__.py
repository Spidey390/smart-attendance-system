from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'main.login'
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)
    login_manager.init_app(app)
    from app.routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    with app.app_context():
        db.create_all()
    return app