# backend/config.py

import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'd2a1b9c8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'escola.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BABEL_DEFAULT_LOCALE = 'pt_BR'

    # --- CONFIGURAÇÕES DE E-MAIL (Versão Final e Correta) ---
    # Estas variáveis serão lidas do seu ficheiro .env
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    # --- FIM DAS ALTERAÇÕES ---

    @staticmethod
    def init_app(app):
        if not app.config.get("SECRET_KEY") and not app.testing:
            raise ValueError("No SECRET_KEY set for Flask application. Set the SECRET_KEY environment variable.")