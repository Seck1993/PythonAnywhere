# backend/services/email_service.py

from flask import current_app, render_template
from threading import Thread
import os
import logging
import requests  # Usaremos a biblioteca requests diretamente

log = logging.getLogger(__name__)

def send_async_email_pa_api(app, to_email, subject, body):
    """Função que envia o e-mail diretamente via API do PythonAnywhere."""
    with app.app_context():
        try:
            api_token = os.environ.get('PYTHONANYWHERE_API_TOKEN')
            username = 'esfasBM'  # O seu nome de utilizador no PythonAnywhere
            
            if not api_token:
                log.error("ERRO CRÍTICO: PYTHONANYWHERE_API_TOKEN não encontrado nas variáveis de ambiente.")
                return

            # A API do PythonAnywhere para enviar e-mail
            api_url = f"https://www.pythonanywhere.com/api/v0/user/{username}/send-email/"
            
            response = requests.post(
                api_url,
                headers={'Authorization': f'Token {api_token}'},
                data={
                    'to': to_email,
                    'subject': subject,
                    'body': body
                }
            )

            if response.status_code == 200:
                log.info(f"E-mail enviado com sucesso via API do PythonAnywhere para: {to_email}")
            else:
                log.error(f"FALHA AO ENVIAR E-MAIL via API. Status: {response.status_code}, Resposta: {response.text}")

        except Exception as e:
            log.error(f"FALHA CRÍTICA AO ENVIAR E-MAIL com API do PythonAnywhere para {to_email}")
            log.error(f"Erro: {e}", exc_info=True)

class EmailService:
    @staticmethod
    def send_password_reset_email(user, token):
        """
        Prepara e dispara o envio do e-mail de redefinição de senha.
        """
        log.info(f"Preparando e-mail (PythonAnywhere API) para o utilizador: {user.email}")
        app = current_app._get_current_object()
        
        html_content = render_template(
            'email/redefinir_senha.html',
            user=user,
            token=token
        )

        subject = 'Redefinição de Senha - Sistema EsFAS'
        
        thr = Thread(target=send_async_email_pa_api, args=[app, user.email, subject, html_content])
        thr.start()
        return thr