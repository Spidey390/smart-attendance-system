from functools import wraps
from flask import redirect, url_for
from flask_login import current_user
import pandas as pd
from app import db
from app.models import User, Student, Staff, Course
from werkzeug.security import generate_password_hash
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function
def check_first_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.first_login:
            return redirect(url_for('main.change_password'))
        return f(*args, **kwargs)
    return decorated_function
def process_excel(file_path, user_role, default_password):
    try:
        df = pd.read_excel(file_path)
        if not {'username', 'name'}.issubset(df.columns):
            return (False, "Excel must have 'username' and 'name' columns.")
        for index, row in df.iterrows():
            username = row['username']
            name = row['name']
            if User.query.filter_by(username=username).first() is None:
                new_user = User(username=username, role=user_role)
                new_user.set_password(default_password)
                db.session.add(new_user)
                db.session.flush()
                if user_role == 'student':
                    new_profile = Student(name=name, user_id=new_user.id)
                elif user_role == 'staff':
                    new_profile = Staff(name=name, user_id=new_user.id)
                db.session.add(new_profile)
        db.session.commit()
        return (True, f"{user_role.capitalize()}s added successfully!")
    except Exception as e:
        db.session.rollback()
        return (False, f"An error occurred: {str(e)}")
def process_course_excel(file_path):
    try:
        df = pd.read_excel(file_path)
        if not {'course_code', 'course_name'}.issubset(df.columns):
            return (False, "Excel must have 'course_code' and 'course_name' columns.")
        for index, row in df.iterrows():
            code = row['course_code']
            name = row['course_name']
            if Course.query.filter_by(course_code=code).first() is None:
                new_course = Course(course_code=code, course_name=name)
                db.session.add(new_course)
        db.session.commit()
        return (True, "Courses added successfully!")
    except Exception as e:
        db.session.rollback()
        return (False, f"An error occurred: {str(e)}")
