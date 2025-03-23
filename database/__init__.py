from database.models import db

def init_app(app):
    """
    Initialize the database with the Flask app
    
    Args:
        app: Flask application instance
    """
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///valnara.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    with app.app_context():
        db.create_all()