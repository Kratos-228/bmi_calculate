from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from models import db, User, BMIRecord, Role
from datetime import datetime
from functools import wraps


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bmi_records.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '123123'  # Для работы сессий
db.init_app(app)


def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Пожалуйста, войдите в систему.", "danger")
                return redirect(url_for('login'))
            user = User.query.get(session['user_id'])

            # Проверяем, не забанен ли пользователь
            if user.is_banned:
                session.pop('user_id', None)  # Удаляем данные из сессии
                flash("Ваш аккаунт заблокирован. Обратитесь к администратору.", "danger")
                return redirect(url_for('login'))

            if user.role.name not in roles:
                flash("У вас нет доступа к этой странице.", "danger")
                return redirect(url_for('index'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует!', 'danger')
            return redirect(url_for('register'))
        user_role = Role.query.filter_by(name='user').first()  # Устанавливаем роль "user"
        new_user = User(username=username, password=password)  # Сохраняем обычный пароль
        new_user.role = user_role
        db.session.add(new_user)
        db.session.commit()
        flash('Регистрация успешна! Теперь войдите в систему.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')





@app.route('/admin')
@role_required(['admin', 'super-admin'])
def admin_panel():
    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@role_required(['admin', 'super-admin'])
def ban_user(user_id):
    target_user = User.query.get_or_404(user_id)
    current_user = User.query.get(session['user_id'])

    # Проверяем права бана
    if current_user.role.name == 'admin' and target_user.role.name != 'user':
        flash("Администратор может банить только пользователей.", "danger")
        return redirect(url_for('admin_panel'))

    target_user.is_banned = True
    db.session.commit()
    flash(f"Пользователь {target_user.username} забанен.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/admin/unban/<int:user_id>', methods=['POST'])
@role_required(['admin', 'super-admin'])
def unban_user(user_id):
    target_user = User.query.get_or_404(user_id)
    target_user.is_banned = False
    db.session.commit()
    flash(f"Пользователь {target_user.username} разбанен.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/admin/change_role/<int:user_id>', methods=['POST'])
@role_required(['super-admin'])
def change_role(user_id):
    target_user = User.query.get_or_404(user_id)
    new_role = request.form['role']
    role = Role.query.filter_by(name=new_role).first()
    if not role:
        flash("Указана неверная роль.", "danger")
        return redirect(url_for('admin_panel'))

    target_user.role_id = role.id
    db.session.commit()
    flash(f"Роль пользователя {target_user.username} изменена на {new_role}.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_record/<int:record_id>', methods=['POST'])
@role_required(['admin', 'super-admin'])
def admin_delete_bmi_record(record_id):
    record = BMIRecord.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    flash('Запись успешно удалена.', 'success')
    return redirect(request.referrer or url_for('admin_panel'))



@app.route('/admin/user/<int:user_id>')
@role_required(['admin', 'super-admin'])
def view_user_data(user_id):
    target_user = User.query.get_or_404(user_id)
    records = BMIRecord.query.filter_by(user_id=user_id).all()
    return render_template('view_user.html', user=target_user, records=records)



# Логин
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:  # Сравниваем обычные пароли
            if user.is_banned:
                flash("Ваш аккаунт заблокирован. Обратитесь к администратору.", "danger")
                return redirect(url_for('login'))

            session['user_id'] = user.id
            flash(f"Добро пожаловать, {user.username}!", "success")

            # Перенаправление в зависимости от роли
            if user.role.name in ['admin', 'super-admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            flash("Неверное имя пользователя или пароль.", "danger")

    return render_template('login.html')





# Выход
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))

# Главная страница
@app.route('/', methods=['GET'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    records = BMIRecord.query.filter_by(user_id=user_id).all()
    return render_template('index.html', records=records)

# Добавление записи через AJAX
@app.route('/calculate_bmi', methods=['POST'])
def calculate_bmi():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = session['user_id']
    data = request.get_json()
    weight = float(data.get('weight'))
    height_cm = float(data.get('height'))
    height_m = height_cm / 100
    bmi = round(weight / (height_m ** 2), 2)

    # Интерпретация ИМТ
    bmi_category = get_bmi_category(bmi)

    # Добавляем запись в БД
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

# Удаление записи через AJAX
@app.route('/delete_record/<int:id>', methods=['DELETE'])
def delete_record(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    record = BMIRecord.query.get_or_404(id)
    if record.user_id != session['user_id']:
        return jsonify({'error': 'Forbidden'}), 403

    db.session.delete(record)
    db.session.commit()

    return jsonify({'success': True})

# Функция для интерпретации ИМТ
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
        return "Ожирение 1 степени"
    elif 35 < bmi <= 40:
        return "Ожирение 2 степени"
    else:
        return "Ожирение 3 степени"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not Role.query.first():
            roles = ['user', 'admin', 'super-admin']
            for role_name in roles:
                role = Role(name=role_name)
                db.session.add(role)
            db.session.commit()
    app.run(debug=True)

