from flask import Flask,render_template_string,jsonify,render_template,request,redirect,url_for,make_response
import datetime
from users.models import User
from flask_pymongo import PyMongo
from pymongo import MongoClient
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import JWTManager,jwt_required,create_access_token,get_jwt_identity,set_access_cookies,get_jwt
import os
from flask_cors import CORS
from functools import wraps 

def role_required(allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            current_user = get_jwt()
            print(current_user)
            if current_user.get('role') in allowed_roles:
                return fn(*args, **kwargs)
            else:
                return jsonify(message="Access forbidden. Insufficient role."), 403
        return wrapper
    return decorator



app=Flask(__name__)
CORS(app)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config['SECRET_KEY']= os.urandom(24)
jwt= JWTManager(app)

client=MongoClient(host='auth_test',port=27017,username='root',password='pass')
db=client['user_login']
collection=db['users']

@app.route('/',methods=['GET','POST'])
def home():
        if request.method =='GET':
            print("from get:",request.headers)
            #print("Cookie:", request.cookies.get('token'))
            return render_template('Login.html')
        else:
            email=request.form.get('email')
            password=request.form.get('password')
            user=collection.find_one({'Email':email})
         
                

            if user and  pbkdf2_sha256.verify(password,user['password']):
                if 'admin' not in email:
                    status={"role":"student"}
                    access_token=create_access_token(email,additional_claims=status)
                    response = make_response(redirect(url_for('protected'))) # this the change done , to save that cookie and also return the response only.
                    #response = jsonify({"msg": "login successful"})
                    set_access_cookies(response, access_token)
                    print(access_token)
                    print(response.headers)
                    return response
                else:
                    status={"role":"Admin"}
                    access_token=create_access_token(email,additional_claims=status)
                    response = make_response(redirect(url_for('admin'))) # this the change done , to save that cookie and also return the response only.
                    #response = jsonify({"msg": "login successful"})
                    set_access_cookies(response, access_token)
                    print(access_token)
                    print(response.headers)
                    return response
                    

                #return redirect('/protected')
                #return render_template_string('login success')
                #response.headers['Authorization'] = f'Bearer {access_token}'   
            return render_template('Login.html',data=True)
@app.route('/signup')
def signup():
   return render_template('Signup.html',data=False)

@app.route('/users/signup',methods=['POST'])
def APISignup():
    name=request.form.get('name')
    email=request.form.get('email')
    password=request.form.get('password')

    user= User()
    result=user.signup(name,email,password)
    
    if collection.find_one({"Email": result['Email']}):
        return jsonify({"error": "email address already in use"}), 400

    if collection.insert_one(result):
       return render_template('Signup.html',data={"flag":True})
        #return redirect(url_for('signup',data=True))

    return jsonify({"error":"signup failed"})

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
 
@app.route("/admin", methods=["GET"])
@jwt_required()
@role_required(allowed_roles=['Admin'])
def admin():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__=="__main__":
    app.run(host='0.0.0.0',debug=True)
