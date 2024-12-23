from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask.logging import create_logger
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from models import db, User, Role, BMIRecord

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bmi_records.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '123123'
db.init_app(app)
log = create_logger(app)


# Проверка блокировки перед каждым запросом
@app.before_request
def check_user_block_status():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and user.is_banned:
            # Если заблокирован администратор или супер-администратор
            if user.role.name in ['admin', 'super-admin']:
                session.clear()  # Очищаем сессию
                log.info(f"Заблокированный администратор {user.username} пытался выполнить запрос.")
                return redirect(url_for('login'))  # Перенаправление без JSON-ответа

            # Если заблокирован обычный пользователь
            log.info(f"Заблокированный пользователь {user.username} пытался выполнить запрос.")
            # Здесь оставляем все как есть


# Декоратор для проверки ролей
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Пожалуйста, войдите в систему.", "danger")
                return redirect(url_for('login'))
            user = db.session.get(User, session['user_id'])
            if user.role.name not in roles:
                flash("У вас недостаточно прав для выполнения этого действия.", "danger")
                return redirect(request.referrer or url_for('index'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Хелпер для получения текущего пользователя
def get_current_user():
    if 'user_id' not in session:
        return None
    return db.session.get(User, session['user_id'])


# Маршруты
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует!', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        user_role = Role.query.filter_by(name='user').first()
        new_user = User(username=username, password=hashed_password, role=user_role)
        db.session.add(new_user)
        db.session.commit()
        flash('Регистрация успешна! Теперь войдите в систему.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if user.is_banned:
                log.info(f"Попытка входа заблокированного пользователя {username}.")
                flash("Ваш аккаунт заблокирован. Обратитесь к администратору.", "danger")
                return redirect(url_for('login'))

            # Сохраняем данные в сессию
            session['user_id'] = user.id
            session['username'] = user.username  # Добавлено

            flash(f"Добро пожаловать, {user.username}!", "success")

            if user.role.name in ['admin', 'super-admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            flash("Неверное имя пользователя или пароль.", "danger")

    return render_template('login.html')





@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


@app.route('/admin')
@role_required(['admin', 'super-admin'])
def admin_panel():
    users = User.query.options(db.joinedload(User.role)).all()
    return render_template('admin.html', users=users)


@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@role_required(['admin', 'super-admin'])
def ban_user(user_id):
    target_user = db.session.get(User, user_id)
    current_user = get_current_user()

    if current_user.role.name == 'admin' and target_user.role.name != 'user':
        flash("Администратор может банить только пользователей.", "danger")
        return redirect(url_for('admin_panel'))

    target_user.is_banned = True
    db.session.commit()

    # Если заблокированный пользователь залогинен
    if 'user_id' in session and session['user_id'] == target_user.id:
        session.clear()  # Очистка сессии

    log.info(f"Пользователь {current_user.username} забанил {target_user.username}.")
    flash(f"Пользователь {target_user.username} забанен.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/admin/unban/<int:user_id>', methods=['POST'])
@role_required(['admin', 'super-admin'])
def unban_user(user_id):
    target_user = db.session.get(User, user_id)
    target_user.is_banned = False
    db.session.commit()
    log.info(f"Пользователь {target_user.username} разбанен.")
    flash(f"Пользователь {target_user.username} разбанен.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/admin/change_role/<int:user_id>', methods=['POST'])
@role_required(['super-admin'])
def change_role(user_id):
    target_user = db.session.get(User, user_id)
    new_role = request.form['role']
    role = Role.query.filter_by(name=new_role).first()
    if not role:
        flash("Указана неверная роль.", "danger")
        return redirect(url_for('admin_panel'))

    target_user.role_id = role.id
    db.session.commit()
    flash(f"Роль пользователя {target_user.username} изменена на {new_role}.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>')
@role_required(['admin', 'super-admin'])
def view_user_data(user_id):
    target_user = db.session.get(User, user_id)
    records = BMIRecord.query.filter_by(user_id=user_id).all()
    return render_template('view_user.html', user=target_user, records=records)


@app.route('/admin/delete_record/<int:record_id>', methods=['POST'])
@role_required(['admin', 'super-admin'])
def admin_delete_bmi_record(record_id):
    record = db.session.get(BMIRecord, record_id)
    if not record:
        flash("Запись не найдена.", "danger")
        return redirect(url_for('admin_panel'))
    db.session.delete(record)
    db.session.commit()
    flash("Запись успешно удалена.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/', methods=['GET'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    records = BMIRecord.query.filter_by(user_id=user_id).all()
    return render_template('index.html', records=records)


@app.route('/calculate_bmi', methods=['POST'])
def calculate_bmi():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = session['user_id']
    user = db.session.get(User, user_id)

    if user and user.is_banned:  # Проверка, заблокирован ли пользователь
        session.clear()  # Очистка сессии
        return jsonify({'error': 'Ваша учетная запись была заблокирована. Пожалуйста, свяжитесь с администратором.'}), 403

    data = request.get_json()
    weight = float(data.get('weight'))
    height_cm = float(data.get('height'))
    height_m = height_cm / 100
    bmi = round(weight / (height_m ** 2), 2)
    bmi_category = get_bmi_category(bmi)

    new_record = BMIRecord(user_id=user_id, weight=weight, height=height_m, bmi=bmi)
    db.session.add(new_record)
    db.session.commit()

    return jsonify({
        'id': new_record.id,
        'weight': weight,
        'height': round(height_m, 2),
        'bmi': bmi,
        'category': bmi_category,
        'date': new_record.created_at.strftime('%Y-%m-%d')
    })


@app.route('/delete_record/<int:id>', methods=['DELETE'])
def delete_record(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = session['user_id']
    user = db.session.get(User, user_id)

    if user and user.is_banned:  # Проверка, заблокирован ли пользователь
        session.clear()  # Очистка сессии
        return jsonify({'error': 'Your account has been banned. Please contact an administrator.'}), 403

    record = db.session.get(BMIRecord, id)
    if record.user_id != user_id:
        return jsonify({'error': 'Forbidden'}), 403

    db.session.delete(record)
    db.session.commit()
    return jsonify({'success': True})


def get_bmi_category(bmi):
    if bmi <= 16:
        return "Выраженный дефицит массы тела"
    elif 16 < bmi <= 18.5:
        return "Недостаточная масса тела"
    elif 18.5 < bmi <= 25:
        return "Норма"
    elif 25 < bmi <= 30:
        return "Избыточная масса тела"
    elif 30 < bmi <= 35:
        return "Ожирение первой степени"
    elif 35 < bmi <= 40:
        return "Ожирение второй степени"
    else:
        return "Ожирение третьей степени"


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
