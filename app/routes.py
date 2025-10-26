from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Student, Staff, Course, CourseOffering, AttendanceSession, AttendanceRecord, enrollments
from app.utils import admin_required, check_first_login, process_excel
from werkzeug.security import check_password_hash
import random
import string
from datetime import datetime, timedelta
import io
import pandas as pd
main = Blueprint('main', __name__)
@main.route('/')
def index():
    return redirect(url_for('main.login'))
@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            if user.first_login:
                return redirect(url_for('main.change_password'))
            if user.role == 'admin':
                return redirect(url_for('main.admin_dashboard'))
            elif user.role == 'staff':
                return redirect(url_for('main.staff_dashboard'))
            else:
                return redirect(url_for('main.student_dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')
@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))
@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        current_user.set_password(new_password)
        current_user.first_login = False
        db.session.commit()
        flash('Password updated successfully!')
        if current_user.role == 'admin':
            return redirect(url_for('main.admin_dashboard'))
        elif current_user.role == 'staff':
            return redirect(url_for('main.staff_dashboard'))
        else:
            return redirect(url_for('main.student_dashboard'))
    return render_template('change_password.html')
@main.route('/admin/dashboard')
@login_required
@admin_required
@check_first_login
def admin_dashboard():
    return render_template('admin/dashboard.html')
@main.route('/admin/add_users', methods=['POST'])
@login_required
@admin_required
def add_users_from_excel():
    file = request.files['excel_file']
    role = request.form.get('role')
    file.save('upload.xlsx')
    process_excel('upload.xlsx', role, 'default1J23')
    flash(f'{role.capitalize()}s added successfully!')
    return redirect(url_for('main.admin_dashboard'))
@main.route('/staff/dashboard')
@login_required
@check_first_login
def staff_dashboard():
    staff_profile = Staff.query.filter_by(user_id=current_user.id).first()
    staff_offerings = CourseOffering.query.filter_by(staff_id=staff_profile.id).all()
    return render_template('staff/dashboard.html', staff_offerings=staff_offerings)
@main.route('/staff/start-session/<int:offering_id>')
@login_required
@check_first_login
def start_attendance_session(offering_id):
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    expiry_time = datetime.utcnow() + timedelta(minutes=5)
    new_session = AttendanceSession(course_offering_id=offering_id, session_code=code, expires_at=expiry_time)
    db.session.add(new_session)
    db.session.commit()
    return render_template('staff/attendance_session.html', code=code, expiry=expiry_time)
@main.route('/student/dashboard')
@login_required
@check_first_login
def student_dashboard():
    student = Student.query.filter_by(user_id=current_user.id).first()
    enrolled_courses = CourseOffering.query.join(enrollments).filter(enrollments.c.student_id == student.id).all()
    return render_template('student/dashboard.html', enrolled_courses=enrolled_courses)
@main.route('/student/enroll', methods=['POST'])
@login_required
@check_first_login
def enroll_course():
    offering_id = request.form.get('offering_id')
    offering = CourseOffering.query.get(offering_id)
    student = Student.query.filter_by(user_id=current_user.id).first()
    if offering and offering.filled_seats < offering.max_seats:
        offering.filled_seats += 1
        student.enrolled_courses.append(offering)
        db.session.commit()
        flash('Enrolled successfully!')
    else:
        flash('Course is full or does not exist.')
    return redirect(url_for('main.student_dashboard'))
@main.route('/student/mark-attendance', methods=['POST'])
@login_required
@check_first_login
def mark_attendance():
    code = request.form.get('attendance_code')
    session = AttendanceSession.query.filter_by(session_code=code).first()
    student = Student.query.filter_by(user_id=current_user.id).first()
    if not session or session.expires_at < datetime.utcnow():
        flash('Invalid or expired code.', 'danger')
        return redirect(url_for('main.mark_attendance_page'))
    enrolled = db.session.query(enrollments).filter_by(student_id=student.id, course_offering_id=session.course_offering_id).first()
    if not enrolled:
        flash('You are not enrolled in this course.', 'warning')
        return redirect(url_for('main.mark_attendance_page'))
    already_marked = AttendanceRecord.query.filter_by(session_id=session.id, student_id=student.id).first()
    if already_marked:
        flash('Attendance already marked for this session.', 'info')
        return redirect(url_for('main.student_dashboard'))
    record = AttendanceRecord(session_id=session.id, student_id=student.id)
    db.session.add(record)
    db.session.commit()
    flash('Attendance marked successfully!', 'success')
    return redirect(url_for('main.student_dashboard'))
@main.route('/staff/report/<int:offering_id>')
@login_required
@check_first_login
def staff_report(offering_id):
    offering = CourseOffering.query.get_or_404(offering_id)
    sessions = AttendanceSession.query.filter_by(course_offering_id=offering.id).order_by(AttendanceSession.expires_at).all()
    enrolled_students = Student.query.join(enrollments).filter(enrollments.c.course_offering_id == offering_id).all()
    session_ids = [s.id for s in sessions]
    all_records = AttendanceRecord.query.filter(AttendanceRecord.session_id.in_(session_ids)).all()
    present_set = {(record.student_id, record.session_id) for record in all_records}
    report_data = []
    for student in enrolled_students:
        attended_count = 0
        attendance_status = []
        for session in sessions:
            if (student.id, session.id) in present_set:
                attendance_status.append('Present')
                attended_count += 1
            else:
                attendance_status.append('Absent')
        total_sessions = len(sessions)
        percentage = (attended_count / total_sessions * 100) if total_sessions > 0 else 0
        report_data.append({
            'student_name': student.name,
            'status': attendance_status,
            'attended': attended_count,
            'total': total_sessions,
            'percentage': round(percentage, 2)
        })
    return render_template('staff/report.html', offering=offering, sessions=sessions, report_data=report_data)
@main.route('/download_report/<int:offering_id>')
@login_required
def download_report(offering_id):
    offering = CourseOffering.query.get_or_404(offering_id)
    sessions = AttendanceSession.query.filter_by(course_offering_id=offering.id).order_by(AttendanceSession.expires_at).all()
    enrolled_students = Student.query.join(enrollments).filter(enrollments.c.course_offering_id == offering_id).all()
    session_ids = [s.id for s in sessions]
    all_records = AttendanceRecord.query.filter(AttendanceRecord.session_id.in_(session_ids)).all()
    present_set = {(record.student_id, record.session_id) for record in all_records}
    data_for_df = []
    for student in enrolled_students:
        user = User.query.get(student.user_id)
        row = {'Student Name': student.name, 'Username': user.username}
        attended_count = 0
        for session in sessions:
            session_date = session.expires_at.strftime('%Y-%m-%d %H:%M')
            if (student.id, session.id) in present_set:
                row[session_date] = 'Present'
                attended_count += 1
            else:
                row[session_date] = 'Absent'
        total_sessions = len(sessions)
        row['Attended'] = attended_count
        row['Total Sessions'] = total_sessions
        row['Percentage'] = (attended_count / total_sessions * 100) if total_sessions > 0 else 0
        data_for_df.append(row)
    df = pd.DataFrame(data_for_df)
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    df.to_excel(writer, index=False, sheet_name='Attendance')
    writer.close()
    output.seek(0)
    filename = f"{offering.course.course_code}_attendance_report.xlsx"
    return make_response(output.read(), {
        'Content-Disposition': f'attachment; filename={filename}',
        'Content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    })
@main.route('/admin/reports')
@login_required
@admin_required
@check_first_login
def admin_reports():
    all_offerings = CourseOffering.query.all()
    return render_template('admin/reports.html', offerings=all_offerings)
@main.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        role = request.form.get('role')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('main.add_user'))
        new_user = User(username=username, role=role)
        new_user.set_password('default123')
        db.session.add(new_user)
        db.session.flush()
        if role == 'student':
            profile = Student(name=name, user_id=new_user.id)
        else:
            profile = Staff(name=name, user_id=new_user.id)
        db.session.add(profile)
        db.session.commit()
        flash(f'{role.capitalize()} "{name}" added successfully!', 'success')
        return redirect(url_for('main.admin_dashboard'))
    return render_template('admin/add_user.html')
@main.route('/admin/add-course', methods=['GET', 'POST'])
@login_required
@admin_required
def add_course():
    if request.method == 'POST':
        code = request.form.get('course_code')
        name = request.form.get('course_name')
        if Course.query.filter_by(course_code=code).first():
            flash('A course with this code already exists.', 'danger')
        else:
            new_course = Course(course_code=code, course_name=name)
            db.session.add(new_course)
            db.session.commit()
            flash(f'Course "{name}" added successfully!', 'success')
        return redirect(url_for('main.admin_dashboard'))
    return render_template('admin/add_course.html')
@main.route('/admin/assign-course', methods=['GET', 'POST'])
@login_required
@admin_required
def assign_course():
    if request.method == 'POST':
        staff_id = request.form.get('staff_id')
        course_id = request.form.get('course_id')
        max_seats = request.form.get('max_seats', 50)
        existing = CourseOffering.query.filter_by(staff_id=staff_id, course_id=course_id).first()
        if existing:
            flash('This staff member is already assigned to this course.', 'warning')
        else:
            new_offering = CourseOffering(staff_id=staff_id, course_id=course_id, max_seats=max_seats)
            db.session.add(new_offering)
            db.session.commit()
            flash('Course assigned to staff successfully!', 'success')
        return redirect(url_for('main.assign_course'))
    all_staff = Staff.query.all()
    all_courses = Course.query.all()
    return render_template('admin/assign_course.html', all_staff=all_staff, all_courses=all_courses)
@main.route('/student/attendance/<int:offering_id>')
@login_required
@check_first_login
def student_attendance(offering_id):
    student = Student.query.filter_by(user_id=current_user.id).first()
    offering = CourseOffering.query.get_or_404(offering_id)
    sessions = AttendanceSession.query.filter_by(course_offering_id=offering.id).order_by(AttendanceSession.expires_at).all()
    session_ids = [s.id for s in sessions]
    records = AttendanceRecord.query.filter(
        AttendanceRecord.session_id.in_(session_ids),
        AttendanceRecord.student_id == student.id
    ).all()
    present_session_ids = {r.session_id for r in records}
    report_details = []
    for session in sessions:
        status = 'Present' if session.id in present_session_ids else 'Absent'
        report_details.append({'date': session.expires_at, 'status': status})
    attended_count = len(present_session_ids)
    total_sessions = len(sessions)
    percentage = (attended_count / total_sessions * 100) if total_sessions > 0 else 0
    report_summary = {
        'attended': attended_count,
        'total': total_sessions,
        'percentage': round(percentage, 2),
        'details': report_details
    }
    return render_template('student/attendance.html', offering=offering, report=report_summary)
@main.route('/student/enroll-page')
@login_required
@check_first_login
def enroll_page():
    student = Student.query.filter_by(user_id=current_user.id).first()
    enrolled_course_ids = [offering.id for offering in CourseOffering.query.join(enrollments).filter(enrollments.c.student_id == student.id).all()]
    available_offerings = CourseOffering.query.filter(CourseOffering.id.notin_(enrolled_course_ids)).all()
    return render_template('student/enroll.html', available_offerings=available_offerings)
@main.route('/student/mark-attendance-page')
@login_required
@check_first_login
def mark_attendance_page():
    return render_template('student/mark_attendance.html')

