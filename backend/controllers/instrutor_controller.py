# backend/controllers/instrutor_controller.py

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
from sqlalchemy import select
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, BooleanField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Optional, Email, EqualTo
from ..models.database import db
from ..services.instrutor_service import InstrutorService
from ..services.user_service import UserService # Importar UserService
from ..models.user import User
# --- DECORADOR CORRIGIDO IMPORTADO AQUI ---
from utils.decorators import admin_or_programmer_required, school_admin_or_programmer_required, can_view_management_pages_required

instrutor_bp = Blueprint('instrutor', __name__, url_prefix='/instrutor')

# Lista de opções padrão para Posto/Graduação
posto_graduacao_choices = [
    ('Soldado PM', 'Soldado PM'),
    ('2º Sargento PM', '2º Sargento PM'),
    ('1º Sargento PM', '1º Sargento PM'),
    ('1º Tenente PM', '1º Tenente PM'),
    ('Capitão PM', 'Capitão PM'),
    ('Major PM', 'Major PM'),
    ('Tenente-Coronel PM', 'Tenente-Coronel PM'),
    ('Coronel PM', 'Coronel PM'),
    ('Outro', 'Outro')
]

class InstrutorForm(FlaskForm):
    nome_completo = StringField('Nome Completo', validators=[DataRequired()])
    nome_de_guerra = StringField('Nome de Guerra', validators=[DataRequired()])
    matricula = StringField('Matrícula', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[
        DataRequired(),
        EqualTo('password2', message='As senhas devem corresponder.')
    ])
    password2 = PasswordField('Confirmar Senha', validators=[DataRequired()])
    posto_graduacao_select = SelectField('Posto/Graduação', choices=posto_graduacao_choices, validators=[DataRequired()])
    posto_graduacao_outro = StringField('Outro (especifique)', validators=[Optional()])
    telefone = StringField('Telefone', validators=[Optional()])
    is_rr = BooleanField('RR')
    submit = SubmitField('Salvar')

class EditInstrutorForm(FlaskForm):
    nome_completo = StringField('Nome Completo', validators=[DataRequired()])
    nome_de_guerra = StringField('Nome de Guerra', validators=[DataRequired()])
    matricula = StringField('Matrícula', render_kw={'readonly': True})
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    posto_graduacao_select = SelectField('Posto/Graduação', choices=posto_graduacao_choices, validators=[DataRequired()])
    posto_graduacao_outro = StringField('Outro (especifique)', validators=[Optional()])
    telefone = StringField('Telefone', validators=[Optional()])
    is_rr = BooleanField('Efetivo da Reserva Remunerada (RR)')
    submit = SubmitField('Salvar Alterações')

class DeleteForm(FlaskForm):
    pass

@instrutor_bp.route('/')
@login_required
@can_view_management_pages_required
def listar_instrutores():
    instrutores = InstrutorService.get_all_instrutores()
    return render_template('listar_instrutores.html', instrutores=instrutores, csrf_token=lambda: '')

@instrutor_bp.route('/cadastrar', methods=['GET', 'POST'])
@login_required
@school_admin_or_programmer_required
def cadastrar_instrutor():
    form = InstrutorForm()
    if form.validate_on_submit():
        school_id = UserService.get_current_school_id()
        if not school_id:
            flash('Não foi possível identificar a escola para associar o instrutor.', 'danger')
            return redirect(url_for('instrutor.listar_instrutores'))
            
        success, message = InstrutorService.create_full_instrutor(form.data, school_id)
        if success:
            flash(message, 'success')
            return redirect(url_for('instrutor.listar_instrutores'))
        else:
            flash(message, 'danger')
    return render_template('cadastro_instrutor.html', form=form)

@instrutor_bp.route('/editar/<int:instrutor_id>', methods=['GET', 'POST'])
@login_required
@school_admin_or_programmer_required
def editar_instrutor(instrutor_id):
    instrutor = InstrutorService.get_instrutor_by_id(instrutor_id)
    if not instrutor or not instrutor.user:
        flash('Instrutor não encontrado.', 'danger')
        return redirect(url_for('instrutor.listar_instrutores'))
    
    form = EditInstrutorForm(obj=instrutor)
    
    if request.method == 'GET':
        # Preenche os dados do usuário associado
        form.nome_completo.data = instrutor.user.nome_completo
        form.nome_de_guerra.data = instrutor.user.nome_de_guerra
        form.matricula.data = instrutor.user.matricula
        form.email.data = instrutor.user.email
        
        # Lógica para o campo 'posto_graduacao'
        posto = instrutor.user.posto_graduacao
        if posto in [choice[0] for choice in form.posto_graduacao_select.choices]:
            form.posto_graduacao_select.data = posto
        elif posto:
            form.posto_graduacao_select.data = 'Outro'
            form.posto_graduacao_outro.data = posto

    if form.validate_on_submit():
        success, message = InstrutorService.update_instrutor(instrutor_id, form.data)
        if success:
            flash(message, 'success')
            return redirect(url_for('instrutor.listar_instrutores'))
        else:
            flash(message, 'danger')
    
    return render_template('editar_instrutor.html', form=form, instrutor=instrutor)

@instrutor_bp.route('/excluir/<int:instrutor_id>', methods=['POST'])
@login_required
@school_admin_or_programmer_required
def excluir_instrutor(instrutor_id):
    success, message = InstrutorService.delete_instrutor(instrutor_id)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect(url_for('instrutor.listar_instrutores'))