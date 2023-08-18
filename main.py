#Befor starting write this command in terminal
#set FLASK_APP=main.py
#flask run
import tensorflow as tf
  
from flask import Flask, flash, render_template, request,redirect, session,url_for,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt 
import os 
import pickle
import h5py
import numpy as np
from PIL import Image
import pdfkit
from io import BytesIO
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config["SECRET_KEY"]='65b0b774279de460f1cc5c92'
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///ums.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"]='filesystem'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db=SQLAlchemy(app) 

bcrypt=Bcrypt(app)   
Session(app)
# Create User Class
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    fname=db.Column(db.String(255), nullable=False)
    lname=db.Column(db.String(255), nullable=False)
    email=db.Column(db.String(255), nullable=False)
    username=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)
    status=db.Column(db.Integer,default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.id}","{self.fname}","{self.lname}","{self.email}","{self.username}","{self.status}")'

#Create Patient class
class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    mri_image = db.Column(db.String(100))
    anomaly_score = db.Column(db.Float)
    def __repr__(self):
        return f'User("{self.id}","{self.name}","{self.age}","{self.gender}","{self.mri_image}","{self.anomaly_score}")'


# create Admin Class
class Admin(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.username}","{self.id}")'

 

# create table
with app.app_context():
    db.create_all()

# insert admin data one time only one time insert this data
# latter will check the condition
#admin=Admin(username='BTSystem',password=bcrypt.generate_password_hash('BTSystem',10))
#db.session.add(admin)
#db.session.commit()

# main index 
@app.route('/')
def index():
    return render_template('index.html',title="")


# admin loign
@app.route('/admin/',methods=["POST","GET"])
def adminIndex():
    # chect the request is post or not
    if request.method == 'POST':
        # get the value of field
        username = request.form.get('username')
        password = request.form.get('password')
        # check the value is not empty
        if username=="" and password=="":
            flash('Please fill all the field','danger')
            return redirect('/admin/')
        else:
            # login admin by username 
            admins=Admin().query.filter_by(username=username).first()
            if admins and bcrypt.check_password_hash(admins.password,password):
                session['admin_id']=admins.id
                session['admin_name']=admins.username
                flash('Login Successfully','success')
                return redirect('/admin/dashboard')
            else:
                flash('Invalid Email and Password','danger')
                return redirect('/admin/')
    else:
        return render_template('admin/index.html',title="Admin Login")

# admin Dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser=User.query.count()
    totalApprove=User.query.filter_by(status=1).count()
    NotTotalApprove=User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html',title="Admin Dashboard",totalUser=totalUser,totalApprove=totalApprove,NotTotalApprove=NotTotalApprove)

# admin get all user 
@app.route('/admin/get-all-user', methods=["POST","GET"])
def adminGetAllUser():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if request.method== "POST":
        search=request.form.get('search')
        users=User.query.filter(User.username.like('%'+search+'%')).all()
        return render_template('admin/all-user.html',title='Approve User',users=users)
    else:
        users=User.query.all()
        return render_template('admin/all-user.html',title='Approve User',users=users)

@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')
    User().query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    #flash('Approve Successfully','success')
    return redirect('/admin/get-all-user')

#delete user
@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete=User.query.get_or_404(id)
    db.session.delete(user_to_delete)
    db.session.commit()
    #flash('User Deleted Successfully','success')
    return redirect('/admin/get-all-user')
    
# change admin password
@app.route('/admin/change-admin-password',methods=["POST","GET"])
def adminChangePassword():
    admin=Admin.query.get(1)
    if request.method == 'POST':
        username=request.form.get('username')
        password=request.form.get('password')
        if username == "" or password=="":
            flash('Please fill the field','danger')
            return redirect('/admin/change-admin-password')
        else:
            Admin().query.filter_by(username=username).update(dict(password=bcrypt.generate_password_hash(password,10)))
            db.session.commit()
            flash('Admin Password update successfully','success')
            return redirect('/admin/change-admin-password')
    else:
        return render_template('admin/admin-change-password.html',title='Admin Change Password',admin=admin)

# admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if session.get('admin_id'):
        session['admin_id']=None
        session['admin_name']=None
        return redirect('/')
# -------------------------user area----------------------------


# User login
@app.route('/user/',methods=["POST","GET"])
def userIndex():
    if  session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method=="POST":
        # get the name of the field
        email=request.form.get('email')
        password=request.form.get('password')
        # check user exist in this email or not
        users=User().query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password,password):
            # check the admin approve your account are not
            is_approve=User.query.filter_by(id=users.id).first()
            # first return the is_approve:
            if is_approve.status == 0:
                flash('Your Account is not approved by Admin','danger')
                return redirect('/user/')
            else:
                session['user_id']=users.id
                session['username']=users.username
                flash('Login Successfully','success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Email and Password','danger')
            return redirect('/user/')
    else:
        return render_template('user/index.html',title="User Login")

# User Register
@app.route('/user/signup',methods=['POST','GET'])
def userSignup():
    if  session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method=='POST':
        # get all input field name
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        username=request.form.get('username')
        password=request.form.get('password')
        # check all the field is filled are not
        if fname =="" or lname=="" or email=="" or password=="" or username=="":
            flash('Please fill all the field','danger')
            return redirect('/user/signup')
        else:
            is_email=User().query.filter_by(email=email).first()
            if is_email:
                flash('Email already Exist','danger')
                return redirect('/user/signup')
            else:
                hash_password=bcrypt.generate_password_hash(password,10)
                user=User(fname=fname,lname=lname,email=email,password=hash_password,username=username)
                db.session.add(user)
                db.session.commit()
                flash('Account Create Successfully Admin Will approve your account in 10 to 30 mint ','success')
                return redirect('/user/')
    else:
        return render_template('user/signup.html',title="User Signup")


# user dashboard
@app.route('/user/dashboard')
def userDashboard():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User().query.filter_by(id=id).first()
    return render_template('user/dashboard.html',title="User Dashboard",users=users)

# user logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        return redirect('/user/')

@app.route('/user/change-password',methods=["POST","GET"])
def userChangePassword():
    if not session.get('user_id'):
        return redirect('/user/')
    if request.method == 'POST':
        email=request.form.get('email')
        password=request.form.get('password')
        if email == "" or password == "":
            flash('Please fill the field','danger')
            return redirect('/user/change-password')
        else:
            users=User.query.filter_by(email=email).first()
            if users:
               hash_password=bcrypt.generate_password_hash(password,10)
               User.query.filter_by(email=email).update(dict(password=hash_password))
               db.session.commit()
               flash('Password Change Successfully','success')
               return redirect('/user/change-password')
            else:
                flash('Invalid Email','danger')
                return redirect('/user/change-password')

    else:
        return render_template('user/change-password.html',title="Change Password")

# user update profile
@app.route('/user/update-profile', methods=["POST","GET"])
def userUpdateProfile():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User.query.get(id)
    if request.method == 'POST':
        # get all input field name
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        username=request.form.get('username')
        edu=request.form.get('edu')
        if fname =="" or lname=="" or email=="" or username=="" or edu=="":
            flash('Please fill all the field','danger')
            return redirect('/user/update-profile')
        else:
            session['username']=None
            User.query.filter_by(id=id).update(dict(fname=fname,lname=lname,email=email,edu=edu,username=username))
            db.session.commit()
            session['username']=username
            flash('Profile update Successfully','success')
            return redirect('/user/dashboard')
    else:
        return render_template('user/update-profile.html',title="Update Profile",users=users)

# -------------------------Patient area----------------------------

@app.route('/user/Patient' , methods=['GET', 'POST'])
def show_Patients():
    patients = Patient.query.all()
    return render_template('user/Patient.html', patients=patients)

#add Patient
@app.route('/user/add', methods=['GET', 'POST'])
def add_patient():
    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        gender = request.form['gender']
        
        patient = Patient(name=name, age=age, gender=gender)
        db.session.add(patient)
        db.session.commit()
        flash('Patient added successfully!')
        return redirect(url_for('show_Patients'))
    else:
        return render_template('user/add.html')

#edit Patient
@app.route('/user/edit/<int:id>', methods=['GET', 'POST'])
def edit_patient(id):
    patient = Patient.query.get(id)
    if request.method == 'POST':
        patient.name = request.form['name']
        patient.age = request.form['age']
        patient.gender = request.form['gender']
        
        db.session.commit()
        flash('Patient updated successfully!')
        return redirect(url_for('show_Patients'))
    return render_template('user/edit.html', patient=patient)

#delete Patient
@app.route('/user/delete/<int:id>')
def delete_patient(id):
    patient = Patient.query.get(id)
    db.session.delete(patient)
    db.session.commit()
    return redirect(url_for('show_Patients'))

#upload_mri Patient
@app.route('/user/upload_mri/<int:id>', methods=['GET', 'POST'])
def upload_mri(id):
    patient = Patient.query.get(id)
    if request.method == 'POST':
        mri_image = request.files['mri_image']
        if mri_image:
            filename = secure_filename(mri_image.filename)
            mri_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            patient.mri_image = url_for('static', filename=f"uploads/{filename}")
           # Load the pre-trained model using h5py
            model = h5py.File('Models/model.h5', 'r')
            model = tf.keras.models.load_model(model)

           # Preprocess the MRI image
            img = Image.open(mri_image)
            img = img.resize((64, 64))
            img = img.convert('L')  # convert to grayscale
            img = np.array(img)
            img = np.expand_dims(img, axis=0)
            img = np.expand_dims(img, axis=-1)
            img = img / 255.0

            # Predict the anomaly score using the pre-trained model
            anomaly_score = model.predict(img)

            
            # Save the anomaly score to the patient record
            patient.anomaly_score = float(anomaly_score[0][0])
            
            # Update the patient record in the database
            db.session.commit()
            
            flash('MRI image uploaded successfully.')
            
            return redirect(url_for('show_Patients'))
    return render_template('user/upload_mri.html', patient=patient)




#Print Patient Report  
@app.route('/user/report/<int:id>/print')
def patient_report(id):
    patient = Patient.query.get_or_404(id)
    return render_template('user/report.html', patient=patient, print=True)


 

if __name__ == "__main__":
    with app.app_context():
        app.run(debug=True)