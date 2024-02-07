from flask import Blueprint,render_template,request,flash,redirect,url_for
from flask_login import login_user,login_required,logout_user,current_user
from .models import User
from werkzeug.security import generate_password_hash,check_password_hash
from . import db

auth = Blueprint('auth',__name__)


@auth.route('/login',methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            if check_password_hash(user.password,password):
                flash('Logged In successfully!', category='success')
                login_user(user,remember=True)
                return redirect(url_for('views.index'))
            else:
                flash('Incorrect password, try again.', category='error')
                
        else:
            flash('Email does not exist.',category='error')
            
    return render_template('login.html',user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('index.html',user=current_user)
    
    
@auth.route('/register',methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        fullname = request.form.get('fullname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            flash('Email already existts.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.',category='error')
        elif len(fullname) < 2:
            flash('Email must be greater than 1 characters.',category='error')
        elif password2 != password1:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 8:
            flash('Passwords must be at least 8 characters.', category='error')
        else:
            new_user = User(email=email,full_name=fullname,password=generate_password_hash(password1,method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user,remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.index'))
        
    return render_template('register.html', user=current_user)