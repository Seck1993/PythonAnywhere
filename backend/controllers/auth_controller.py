# backend/controllers/auth_controller.py
from flask import Blueprint, flash, redirect, render_template, request, url_for, current_app
from flask_login import login_user, logout_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy import select
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
import logging

from ..models.database import db
from ..models.user import User
from ..models.user_school import UserSchool
from ..models.instrutor import Instrutor
from ..models.aluno import Aluno
from ..models.disciplina import Disciplina
from ..models.historico_disciplina import HistoricoDisciplina
from utils.validators import validate_email, validate_password_strength
from ..services.password_reset_service import PasswordResetService
from ..services.email_service import EmailService

auth_bp = Blueprint('auth', __name__)
log = logging.getLogger(__name__)

class ForgotPasswordForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    submit = SubmitField('Enviar E-mail de Recuperação')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nova Senha', validators=[DataRequired(), EqualTo('password2', message='As senhas não correspondem.')])
    password2 = PasswordField('Confirmar Nova Senha', validators=[DataRequired()])
    submit = SubmitField('Redefinir Senha')

class LoginForm(FlaskForm):
    username = StringField('Matrícula / Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

# ... (outras rotas como /register, /login, /logout permanecem iguais) ...
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        matricula = request.form.get('matricula')
        nome_completo = request.form.get('nome_completo')
        nome_de_guerra = request.form.get('nome_de_guerra')
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        role = request.form.get('role')
        opm = request.form.get('opm')
        # --- NOVO CAMPO ---
        posto_graduacao = request.form.get('posto_graduacao')

        if not role:
            flash('Por favor, selecione sua função (Aluno ou Instrutor).', 'danger')
            return render_template('register.html', form_data=request.form)
            
        if not posto_graduacao:
            flash('O campo Posto/Graduação é obrigatório.', 'danger')
            return render_template('register.html', form_data=request.form)

        if role == 'aluno' and not opm:
            flash('O campo OPM é obrigatório para alunos.', 'danger')
            return render_template('register.html', form_data=request.form)

        if not validate_email(email):
            flash('Formato de e-mail inválido.', 'danger')
            return render_template('register.html', form_data=request.form)

        is_strong, message = validate_password_strength(password)
        if not is_strong:
            flash(message, 'danger')
            return render_template('register.html', form_data=request.form)

        user = db.session.execute(
            db.select(User).filter_by(matricula=matricula, role=role)
        ).scalar_one_or_none()

        if not user:
            flash('Matrícula não encontrada para a função selecionada. Contate a administração.', 'danger')
            return render_template('register.html', form_data=request.form)

        if user.is_active:
            flash('Esta conta já foi ativada. Tente fazer o login.', 'info')
            return redirect(url_for('auth.login'))

        if password != password2:
            flash('As senhas não coincidem.', 'danger')
            return render_template('register.html', form_data=request.form)

        email_exists = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if email_exists and email_exists.id != user.id:
            flash('Este e-mail já está em uso por outra conta.', 'danger')
            return render_template('register.html', form_data=request.form)

        user.nome_completo = nome_completo
        user.nome_de_guerra = nome_de_guerra
        user.posto_graduacao = posto_graduacao
        user.email = email
        user.username = matricula
        user.set_password(password)
        user.is_active = True
        
        if role == 'instrutor' and not user.instrutor_profile:
            new_instrutor_profile = Instrutor(user_id=user.id)
            db.session.add(new_instrutor_profile)
        elif role == 'aluno' and not user.aluno_profile:
            new_aluno_profile = Aluno(user_id=user.id, opm=opm)
            db.session.add(new_aluno_profile)
            db.session.flush()

            user_school_link = db.session.scalar(select(UserSchool).where(UserSchool.user_id == user.id))
            if user_school_link:
                school_id = user_school_link.school_id
                disciplinas_da_escola = db.session.scalars(select(Disciplina).where(Disciplina.school_id == school_id)).all()
                for disciplina in disciplinas_da_escola:
                    nova_matricula = HistoricoDisciplina(aluno_id=new_aluno_profile.id, disciplina_id=disciplina.id)
                    db.session.add(nova_matricula)
        
        db.session.commit()

        flash('Sua conta foi ativada com sucesso! Agora você pode fazer o login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form_data={})


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        login_identifier = form.username.data
        password = form.password.data

        user = db.session.execute(db.select(User).filter_by(matricula=login_identifier)).scalar_one_or_none()

        if not user:
            user = db.session.execute(db.select(User).filter_by(username=login_identifier)).scalar_one_or_none()

        if user and user.is_active and user.check_password(password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        elif user and not user.is_active:
            flash('Sua conta precisa ser ativada. Use a página de registro para ativá-la.', 'warning')
        else:
            flash('Matrícula/Usuário ou senha inválidos.', 'danger')

    return render_template('login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você foi desconectado com sucesso.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/recuperar-senha', methods=['GET', 'POST'])
def recuperar_senha():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        # --- VERIFICAÇÃO EXPLÍCITA ---
        mail_password = current_app.config.get('MAIL_PASSWORD')
        if not mail_password:
            log.error("ERRO CRÍTICO: A variável de ambiente MAIL_PASSWORD não foi carregada na aplicação web. Verifique o ficheiro WSGI.")
            flash("Erro de configuração do servidor de e-mail. Contacte o administrador.", "danger")
            return redirect(url_for('auth.login'))
        # --- FIM DA VERIFICAÇÃO ---
        
        user = db.session.scalar(select(User).filter_by(email=form.email.data))
        if user:
            token = PasswordResetService.generate_token_for_user(user.id)
            EmailService.send_password_reset_email(user, token)
            flash('Um e-mail com instruções para redefinir sua senha foi enviado.', 'info')
            return redirect(url_for('auth.login'))
        else:
            flash('Nenhum usuário encontrado com este endereço de e-mail.', 'warning')
            
    return render_template('recuperar_senha.html', form=form)

@auth_bp.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    user = PasswordResetService.verify_reset_token(token)
    if not user:
        flash('O link de redefinição de senha é inválido ou expirou.', 'danger')
        return redirect(url_for('auth.recuperar_senha'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        is_strong, message = validate_password_strength(form.password.data)
        if not is_strong:
            flash(message, 'danger')
            return render_template('redefinir_senha.html', form=form, token=token)
            
        user.set_password(form.password.data)
        user.must_change_password = False
        db.session.commit()
        PasswordResetService.invalidate_token(token)
        flash('Sua senha foi atualizada com sucesso!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('redefinir_senha.html', form=form, token=token)