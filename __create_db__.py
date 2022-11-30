from another_api_with_db import app, db



with app.app_context():
    db.create_all()
