from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from datetime import timedelta


app = Flask(__name__)
app.secret_key = 'chave-secreta'
app.permanent_session_lifetime = timedelta(days=7)  # manter logado por 7 dias

import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Cria a pasta se não existir
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def extensao_permitida(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meubanco.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ========================
# MODELOS
# ========================

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)

class Recurso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(200))
    status = db.Column(db.String(20))

class Reserva(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    recurso_id = db.Column(db.Integer, db.ForeignKey('recurso.id'), nullable=False)
    data = db.Column(db.Date, nullable=False)

    usuario = db.relationship('Usuario', backref='reservas')
    recurso = db.relationship('Recurso', backref='reservas')


# ========================
# ROTAS PRINCIPAIS
# ========================

@app.route('/')
def home():
    if 'usuario_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))


@app.route('/login-page')
def login_page():
    sucesso = session.pop('sucesso', None)
    return render_template('login.html', erro=None, sucesso=sucesso)

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    senha = request.form['senha']
    usuario = Usuario.query.filter_by(email=email).first()
    if usuario and check_password_hash(usuario.senha_hash, senha):
        session.permanent = True
        session['usuario_id'] = usuario.id
        session['usuario_nome'] = usuario.nome
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', erro="Email ou senha inválidos.", sucesso=None)

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        confirmar_senha = request.form.get('confirmar_senha')

        if senha != confirmar_senha:
            return render_template('cadastro.html', erro="As senhas não conferem.")

        if Usuario.query.filter_by(email=email).first():
            return render_template('cadastro.html', erro="Já existe uma conta com este email.")

        senha_criptografada = generate_password_hash(senha)
        novo_usuario = Usuario(nome=nome, email=email, senha_hash=senha_criptografada)
        db.session.add(novo_usuario)
        db.session.commit()

        session['sucesso'] = "Conta criada com sucesso. Faça o login."
        return redirect(url_for('login_page'))

    return render_template('cadastro.html', erro=None)

@app.route('/dashboard')
def dashboard():
    if 'usuario_id' not in session:
        return redirect(url_for('login_page'))

    total_usuarios = Usuario.query.count()
    total_recursos = Recurso.query.count()
    total_reservas = Reserva.query.count()
    return render_template('dashboard.html',
                            nome=session['usuario_nome'],
                            total_usuarios=total_usuarios,
                            total_recursos=total_recursos,
                            total_reservas=total_reservas)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ========================
# GERENCIAMENTO DE USUÁRIOS
# ========================

@app.route('/usuarios-page')
def usuarios_page():
    if 'usuario_id' not in session:
        return redirect(url_for('login_page'))
    usuarios = Usuario.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/usuarios', methods=['GET'])
def obter_usuarios():
    usuarios = Usuario.query.all()
    return jsonify([{'id': u.id, 'nome': u.nome, 'email': u.email} for u in usuarios])



@app.route('/usuarios', methods=['POST'])
def adicionar_usuario():
    dados = request.get_json()
    nome = dados.get('nome')
    email = dados.get('email')
    senha_hash = generate_password_hash(dados.get('senha_hash'))

    if Usuario.query.filter_by(email=email).first():
        return jsonify({'erro': 'Já existe um usuário com este email'}), 400

    novo = Usuario(nome=nome, email=email, senha_hash=senha_hash)
    db.session.add(novo)
    db.session.commit()
    return jsonify({'mensagem': 'Usuário adicionado com sucesso'})


@app.route('/usuarios/<int:id>', methods=['PUT'])
def editar_usuario(id):
    dados = request.get_json()
    usuario = Usuario.query.get(id)
    if not usuario:
        return jsonify({'erro': 'Usuário não encontrado'}), 404
    usuario.nome = dados.get('nome')
    usuario.email = dados.get('email')
    db.session.commit()
    return jsonify({'mensagem': 'Usuário atualizado'})

@app.route('/usuarios/<int:id>', methods=['DELETE'])
def deletar_usuario(id):
    usuario = Usuario.query.get(id)
    if not usuario:
        return jsonify({'erro': 'Usuário não encontrado'}), 404
    db.session.delete(usuario)
    db.session.commit()
    return jsonify({'mensagem': 'Usuário deletado'})


# ========================
# GERENCIAMENTO DE RECURSOS
# ========================

@app.route('/recursos-page')
def recursos_page():
    if 'usuario_id' not in session:
        return redirect(url_for('login_page'))
    recursos = Recurso.query.all()
    return render_template('recursos.html', recursos=recursos)

@app.route('/recursos', methods=['GET'])
def obter_recursos():
    recursos = Recurso.query.all()
    return jsonify([
        {'id': r.id, 'nome': r.nome, 'descricao': r.descricao}
        for r in recursos
    ])

@app.route('/recursos', methods=['POST'])
def adicionar_recurso():
    dados = request.get_json()
    nome = dados.get('nome')
    descricao = dados.get('descricao')
    novo = Recurso(nome=nome, descricao=descricao)
    db.session.add(novo)
    db.session.commit()
    return jsonify({'mensagem': 'Recurso adicionado com sucesso'})

@app.route('/recursos/<int:id>', methods=['PUT'])
def editar_recurso(id):
    dados = request.get_json()
    recurso = Recurso.query.get(id)
    if not recurso:
        return jsonify({'erro': 'Recurso não encontrado'}), 404
    recurso.nome = dados.get('nome')
    recurso.descricao = dados.get('descricao')
    db.session.commit()
    return jsonify({'mensagem': 'Recurso atualizado'})

@app.route('/recursos/<int:id>', methods=['DELETE'])
def deletar_recurso(id):
    recurso = Recurso.query.get(id)
    if not recurso:
        return jsonify({'erro': 'Recurso não encontrado'}), 404
    db.session.delete(recurso)
    db.session.commit()
    return jsonify({'mensagem': 'Recurso excluído'})


# ========================
# GERENCIAMENTO DE RESERVAS
# ========================

@app.route('/reservas', methods=['GET', 'POST'])
def gerenciar_reservas():
    if 'usuario_id' not in session:
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        usuario_id = request.form['usuario_id']
        recurso_id = request.form['recurso_id']
        data = request.form['data']

        nova_reserva = Reserva(
            usuario_id=usuario_id,
            recurso_id=recurso_id,
            data=datetime.strptime(data, '%Y-%m-%d').date()
        )
        db.session.add(nova_reserva)
        db.session.commit()
        return redirect('/reservas')

    usuarios = Usuario.query.all()
    recursos = Recurso.query.all()
    reservas = Reserva.query.all()
    return render_template('reservas.html', usuarios=usuarios, recursos=recursos, reservas=reservas)

@app.route('/reservas/<int:id>/excluir', methods=['POST'])
def excluir_reserva(id):
    if 'usuario_id' not in session:
        return redirect(url_for('login_page'))

    reserva = Reserva.query.get_or_404(id)
    db.session.delete(reserva)
    db.session.commit()
    return redirect('/reservas')

@app.route('/reservas-page')
def reservas_page():
    if 'usuario_id' not in session:
        return redirect(url_for('login_page'))
    reservas = Reserva.query.all()
    usuarios = Usuario.query.all()
    recursos = Recurso.query.all()
    return render_template('reservas.html', reservas=reservas, usuarios=usuarios, recursos=recursos)


# ========================
# EXECUÇÃO
# ========================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
