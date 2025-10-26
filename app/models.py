from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(50), nullable=False)
    first_login = db.Column(db.Boolean, default=True)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(20), unique=True, nullable=False)
    course_name = db.Column(db.String(100), nullable=False)
enrollments = db.Table('enrollments',
    db.Column('student_id', db.Integer, db.ForeignKey('student.id'), primary_key=True),
    db.Column('course_offering_id', db.Integer, db.ForeignKey('course_offering.id'), primary_key=True)
)
class CourseOffering(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'))
    max_seats = db.Column(db.Integer, default=50)
    filled_seats = db.Column(db.Integer, default=0)
    course = db.relationship('Course', backref='offerings')
    staff = db.relationship('Staff', backref='offerings')
    enrolled_students = db.relationship('Student', secondary=enrollments,
                                      backref=db.backref('enrolled_courses', lazy='dynamic'), lazy='dynamic')
class AttendanceSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_offering_id = db.Column(db.Integer, db.ForeignKey('course_offering.id'))
    session_code = db.Column(db.String(8), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
class AttendanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('attendance_session.id'))
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'))

