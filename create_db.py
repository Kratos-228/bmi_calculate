from app import app, db  # Импортируем приложение и объект db

# Создаем контекст приложения для работы с базой данных
with app.app_context():
    db.create_all()  # Создаем все таблицы
