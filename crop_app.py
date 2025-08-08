from flask import Flask, render_template, request, redirect, session, url_for, flash,jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
from flask_mail import Mail, Message
import secrets
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from bson import ObjectId
# from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import stripe
import os
from web3 import Web3
import smtplib
import threading, time


app = Flask(__name__, static_url_path='/static')
app.secret_key = 'your_secret_key'

#CONNECTION WITH BLOCKCHAIN
import json

ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

# deployed_contract_address = ""  

with open('build/contracts/CropApplication.json') as f:
    contract_json = json.load(f)

contract_abi = contract_json['abi']
contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)





###########################################################
######################################################

# # Configure Flask-Mail
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 
# app.config['MAIL_USERNAME'] = ''  # Your email
# app.config['MAIL_PASSWORD'] = ''
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False
# mail = Mail(app)




########payment #######################
load_dotenv()
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
stripe_public_key = os.getenv('STRIPE_PUBLIC_KEY')

##############################################

def get_db():
    client = MongoClient('mongodb://localhost:27017/')  
    db = client['test__db']  
    return db

def create_collections():
    db = get_db()
    if 'users' not in db.list_collection_names():
        db.create_collection('users')
    
    if 'admin' not in db.list_collection_names():
        db.create_collection('admin')

    if 'applications' not in db.list_collection_names():
        db.create_collection('applications') 
    if 'stat_applications' not in db.list_collection_names():
        db.create_collection('stat_applications') 
    
    admin_collection = db['admin']
    if admin_collection.count_documents({}) == 0:
        admin_collection.insert_one({"username": "admin", "password": generate_password_hash("admin")})

def create_message_collection():
    db = get_db()
    if 'messages' not in db.list_collection_names():
        db.create_collection('messages')

db = get_db()
if 'reviewteam' not in db.list_collection_names():
        db.create_collection('reviewteam')

db = get_db()
if 'new_reviews' not in db.list_collection_names():
        db.create_collection('new_reviews')


available_accounts = web3.eth.accounts

admin_eth_address = available_accounts[0]  

# ASSIGN USER AND ETH ADDRESS
def get_next_available_address():
    assigned_addresses = db.users.distinct("eth_address")
    for account in available_accounts:
        if account not in assigned_addresses:
            return account
    raise Exception("No available Ethereum addresses!")

eth_address = get_next_available_address()


def insert_user(first_name, last_name, email, username, password,eth_address):
    db = get_db()
    user_data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "username": username,
        "password": generate_password_hash(password),
        "eth_address": eth_address,
        "reset_token": None,
        "subscription": None,  
        "subscription_date": None,
        "subscription_expiry": None
    }
    db['users'].insert_one(user_data)


def is_subscription_valid(user):
    if user.get('subscription_expiry') is None:
        return False
    return datetime.now() <= user['subscription_expiry']

def get_user(username):
    db = get_db()
    return db['users'].find_one({"username": username})

def get_user_by_email(email):
    db = get_db()
    return db['users'].find_one({"email": email})

def get_user_by_reset_token(token):
    db = get_db()
    return db['users'].find_one({"reset_token": token})

def change_password(username, new_password):
    db = get_db()
    db['users'].update_one({"username": username}, {"$set": {"password": generate_password_hash(new_password), "reset_token": None}})

def remove_user(username):
    db = get_db()
    db['users'].delete_one({"username": username})




################################# Admin Functions
def is_admin(username, password):
    db = get_db()
    admin = db['admin'].find_one({"username": username})
    if admin:
        return check_password_hash(admin['password'], password)
    return False


def get_all_users():
    db = get_db()
    users = list(db['users'].find())
    return users


def get_all_applications():
    db = get_db()
    applications = list(db['applications'].find())
    return applications


def get_all_message():
    db = get_db()
    messages = list(db['messages'].find())
    return messages

@app.route('/admin/applications', methods=["GET"])
def admin_applications():
    if 'username' in session and session['username'] == 'admin':
        db = get_db()
        applications = db['applications'].find()
        return render_template(
            'admin_applications.html', 
            applications=applications
        )
    return redirect('/admin_login')


@app.route('/')
def home():
    user_first_name = None
    subscription_status = None
    user = None

    if 'username' in session:
        username = session['username']
        user = get_user(username)
        user_first_name = user['first_name'] if user else None
        # Check subscription status
        if user and 'subscription' in user:
            subscription_status = 'Active' if is_subscription_valid(user) else 'Expired'
    
    return render_template('Home_1.html', user_first_name=user_first_name, subscription_status=subscription_status, user=user)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if get_user(username):
            flash('Username already exists. Please choose another one.', 'error')
            return redirect('/register')
        
        if get_user_by_email(email):
            flash('Email already registered. Please use another email address.', 'error')
            return redirect('/register')
        
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect('/register')
        
        eth_address = get_next_available_address()

        insert_user(first_name, last_name, email, username, password, eth_address)
        
        flash('Registration successful! Please log in.', 'success')
        return redirect('/login')
    
    return render_template('register.html')



@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect('/')
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/admin_logout')
def admin_logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' in session and session['username'] == 'admin':
        users = get_all_users()
        enquiries = get_all_message()
        applications = get_all_applications()  
        return render_template('base_admin.html', users=users, enquiries=enquiries,applications=applications)
    return redirect('/admin_login')


###########################################################################

##############################ROUTES

@app.route('/admin/users', methods=["GET"])
def admin_users():
    if 'username' in session and session['username'] == 'admin':
        users = get_all_users()  # Make sure this function is defined
        return render_template('admin_users.html', users=users)
    return redirect('/admin_login')

@app.route('/admin/enquiries', methods=["GET"])
def admin_enquiries():
    if 'username' in session and session['username'] == 'admin':
        enquiries = get_all_message()
        return render_template('admin_enquiries.html', enquiries=enquiries)
    return redirect('/admin_login')

@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form['email']
        user = get_user_by_email(email)
        if user:
            token = secrets.token_urlsafe()
            db = get_db()
            db['users'].update_one({"email": email}, {"$set": {"reset_token": token}})
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[email])
            msg.body = f'Please click the following link to reset your password: {reset_url}'
            mail.send(msg)
            flash('Password reset email sent. Please check your inbox.', 'success')
            return redirect('/login')
        else:
            flash('Email not found.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=["GET", "POST"])
def reset_password(token):
    user = get_user_by_reset_token(token)
    if not user:
        return "Invalid or expired token."
    
    if request.method == "POST":
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(request.url)
        
        change_password(user['username'], password)
        flash('Password updated successfully! Please log in.', 'success')
        return redirect('/login')
    
    return render_template('reset_password.html')

@app.route('/admin_login', methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if is_admin(username, password):
            session['username'] = username
            return redirect('/admin_dashboard')
        else:
            flash('Invalid username or password', 'error')
    return render_template('admin_login.html')


@app.route('/sell_crop')
def sell_crop():
    if 'username' not in session:
        return redirect(url_for('login', next=url_for('sell_crop')))
    
    username = session['username']
    user = get_user(username)
    
    if is_subscription_valid(user):
        return redirect(url_for('user_dashboard'))
    else:
        return redirect(url_for('dashboard'))

@app.route('/admin')
def admin():
    if 'username' in session and session['username'] == 'admin':
        return redirect('/admin/users')  
    else:
        return redirect('/admin_login')

@app.route('/change_password', methods=["POST"])
def change_password_route():
    if 'username' in session and session['username'] == 'admin':
        username = request.form['username']
        new_password = request.form['new_password']
        change_password(username, new_password)
        flash('Password changed successfully!', 'success')
        return redirect('/admin')
    else:
        return redirect('/admin_login')

@app.route('/remove_user', methods=["POST"])
def remove_user_route():
    if 'username' not in session or session['username'] != 'admin':
        return redirect('/admin_login')
    
    username = request.form['username']
    
    try:
        remove_user(username)
        flash(f'User {username} has been removed successfully!', 'success')
    except Exception as e:
        flash(f'Error removing user: {e}', 'error')
    
    return redirect('/admin_dashboard')

@app.route('/about_us')
def aboutus():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact_us.html')

@app.route('/send_message', methods=["POST"])
def send_message():
    if request.method == "POST":
        name = request.form['name']
        phone = str(request.form['phone'])  
        email = request.form['email']
        message = request.form['message']

        db = get_db()
        db['messages'].insert_one({"name": name, "phone": phone, "email": email, "message": message})

        flash("Message sent successfully!", "success")
        return redirect('/contact')

@app.route('/enquiries')
def enquiries():
    db = get_db()
    enquiries = list(db['messages'].find())
    return render_template('enquiries.html', enquiries=enquiries)

@app.route('/Predict')
def prediction():
    if 'username' in session:
        return render_template('Index.html')
    else:
        return redirect('/login')

@app.route('/form', methods=["POST"])
def brain():
    if 'username' in session:
        Nitrogen = float(request.form['Nitrogen'])
        Phosphorus = float(request.form['Phosphorus'])
        Potassium = float(request.form['Potassium'])
        Temperature = float(request.form['Temperature'])
        Humidity = float(request.form['Humidity'])
        Ph = float(request.form['ph'])
        Rainfall = float(request.form['Rainfall'])
         
        values = [Nitrogen, Phosphorus, Potassium, Temperature, Humidity, Ph, Rainfall]
        
        if 0 < Ph <= 14 and 0 < Temperature < 100 and Humidity > 0:
            model = joblib.load('crop app')  # Update to your model file name
            arr = [values]
            acc = model.predict(arr)
            return render_template('prediction.html', prediction=str(acc[0]).upper())
        else:
            return "Sorry... Error in entered values in the form. Please check the values and fill it again."
    else:
        return redirect('/login')

# Fertilizer Prediction
# dataset = pd.read_csv("")  # Update to your dataset file path
# model_crop = joblib.load('fertilizer_Model.pkl')

@app.route('/fertilizer', methods=['GET', 'POST'])
def fertilizer():
    if 'username' not in session:
        return redirect('/login')
    if request.method == 'POST':
        try:
            nitrogen = float(request.form['nitrogen'])
            phosphorus = float(request.form['phosphorus'])
            potassium = float(request.form['potassium'])
            pH = float(request.form['pH'])
            rainfall = float(request.form['rainfall'])
            temperature = float(request.form['temperature'])

            input_data = pd.DataFrame(
                [[nitrogen, phosphorus, potassium, pH, rainfall, temperature]],
                columns=['Nitrogen', 'Phosphorus', 'Potassium', 'pH', 'Rainfall', 'Temperature']
            )

            predicted_crop = model_crop.predict(input_data)

            recommended_fertilizer = dataset[dataset['Crop'] == predicted_crop[0]]['Fertilizer'].values[0]
            link = dataset[(dataset['Crop'] == predicted_crop[0]) & (dataset['Fertilizer'] == recommended_fertilizer)]['Link'].values[0]

            return render_template('fertilizer.html', crop=predicted_crop[0], fertilizer=recommended_fertilizer, link=link)
        except Exception as e:
            print(f"Error processing form: {e}")
            return "Error processing form data", 500
    else:
        return render_template('fertilizer.html')
    


######################################################
# SUPPLY SYSTEM
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login', next=url_for('dashboard')))
    
    username = session['username']
    user = get_user(username)  

    if is_subscription_valid(user):
        subscription_status = 'Active'
    else:
        subscription_status = 'Expired'
    

    return render_template('dashboard.html', subscription_status=subscription_status)


@app.route('/subscribe/<plan>', methods=['GET', 'POST'])
def subscribe(plan):
    if 'username' not in session:
        return redirect(url_for('login', next=url_for('subscribe', plan=plan)))

    username = session.get('username')
    user = get_user(username)

    session['plan'] = plan  

    if is_subscription_valid(user):
        flash('You already have an active subscription.', 'info')
        return redirect(url_for('user_dashboard'))

    fee = 1000 if plan == 'gold' else 500 if plan == 'silver' else None
    public_key = os.getenv('STRIPE_PUBLIC_KEY')  

    if fee is None:
        flash('Invalid subscription plan.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        
        try:
            stripe_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'INR',
                        'product_data': {'name': f'{plan} subscription'},
                        'unit_amount': fee * 100,  
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=url_for('success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=url_for('cancel', _external=True),
            )

            return jsonify(id=stripe_session.id)
        except Exception as e:
            flash(f"Error creating payment session: {e}", 'error')
            return redirect(url_for('subscribe', plan=plan))

    return render_template('checkout.html', plan=plan, fee=fee, public_key=public_key)


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        plan = request.args.get('plan')  
        if plan == 'gold':
            price = 1000  
        elif plan == 'silver':
            price = 500  
        else:
            return jsonify(error="Invalid plan"), 400

        # Create Stripe checkout session
        stripe_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'INR',
                    'product_data': {
                        'name': f'{plan} subscription'
                    },
                    'unit_amount': price * 100,  
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('cancel', _external=True),
        )

        # Return the session ID as JSON
        return jsonify(id=stripe_session.id)  
    except Exception as e:
        print(f"Error creating Stripe session: {e}")
        return jsonify(error=str(e)), 403


@app.route('/success')
def success():
    stripe_session_id = request.args.get('session_id')
    stripe_session = stripe.checkout.Session.retrieve(stripe_session_id)

    # Get the user's username and the selected plan
    username = session.get('username')
    plan = session.get('plan')  # Gold or Silver subscription

    if stripe_session.payment_status == 'paid':
        # Store payment and subscription details in MongoDB
        subscription_expiry = datetime.now() + timedelta(days=365)  # Expiry set to 1 year from now
        payment_data = {
            "session_id": stripe_session_id,
            "amount": stripe_session.amount_total / 100,  # Convert amount to original currency units
            "currency": stripe_session.currency,
            "status": 'paid'
        }

        # Update MongoDB with the subscription and payment information
        db = get_db()
        db['users'].update_one(
            {"username": username},
            {
                "$set": {
                    "subscription": plan,
                    "subscription_date": datetime.now(),
                    "subscription_expiry": subscription_expiry,
                    "payment_details": payment_data
                }
            }
        )

    flash('Payment successful! Your subscription has been updated.', 'success')
    return redirect(url_for('user_dashboard'))



@app.route('/cancel')
def cancel():
    return "Payment was canceled"


@app.route('/insurance_form', methods=['GET', 'POST'])
def insurance_form():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get the logged-in user's details
    username = session['username']
    user = get_user(username)  # Function to retrieve user from the database

    if request.method == 'POST':
        if user['subscription'] != 'gold':
            # Flash the error message
            flash('Insurance is only available for Gold subscribers.', 'error')
            return render_template('insurance_form.html')  # Stay on the form page

    if request.method == 'POST':
        # Get the user-submitted information
        name = request.form.get('name')
        phone_number = request.form.get('phone-number')
        email = request.form.get('email')
        bank_account = request.form.get('bank-account')
        ifsc_code = request.form.get('ifsc-code')
        address = request.form.get('address')

        # Save user insurance details to the database
        db = get_db()
        db['users'].update_one(
            {"username": username},
            {
                "$set": {
                    "name": name,
                    "phone_number": phone_number,
                    "email": email,
                    "bank_account": bank_account,
                    "ifsc_code": ifsc_code,
                    "address": address,
                    "insurance": True  # Add insurance status
                }
            }
        )

        flash('Insurance details submitted successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('insurance_form.html')

    


@app.route('/user_dashboard')
def user_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    db = get_db()
    username = session['username']
    user = get_user(username)

    # Fetch application from midterm_application (if it exists)
    user_application = db['midterm_application'].find_one(
        {"farmer_details.username": username},
        sort=[("_id", -1)]
    )

    # If not found in midterm_application, check midterm_applications_stage2
    if not user_application:
        user_application = db['midterm_applications_stage2'].find_one(
            {"farmer_details.username": username},
            sort=[("_id", -1)]
        )

    mid_term_scheduled = False
    if user_application:
        market_data = db['market'].find_one({"eth_address": user_application.get("eth_address")})
        if market_data:
            mid_term_scheduled = market_data.get("mid_term_scheduled", False)

    # Debugging: Print fetched data
    print("Fetched User Application:", user_application)
    

    return render_template(
        'user_dashboard.html',
        user_first_name=user['first_name'] if user else None,
        user_application=user_application,
        mid_term_scheduled=mid_term_scheduled
    )




@app.route('/apply_for_sale')
def apply_for_sale():
    if 'username' not in session:
        return redirect(url_for('login', next=url_for('apply_for_sale')))
    
    return render_template('apply_for_sale.html')


# Twilio Credentials
# TWILIO_ACCOUNT_SID = ""
# TWILIO_AUTH_TOKEN = ""
# TWILIO_PHONE_NUMBER = ""

from twilio.rest import Client

def send_sms(to_number, message):
    """Send an SMS using Twilio API."""
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    
    try:
        sms = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=to_number
        )
        print(f"✅ SMS sent successfully! SID: {sms.sid}")
        return True
    except Exception as e:
        print(f"❌ Failed to send SMS: {str(e)}")
        return False


@app.route('/submit_crop', methods=['POST'])
def submit_crop():
    if 'username' not in session:
        return redirect(url_for('login', next=url_for('submit_crop')))

    db = get_db()
    username = session['username']

    existing_application = db['stat_applications'].find_one({"username": username, "status": {"$ne": "Declined"}})
    if existing_application:
        flash('You already have an active crop application. Please wait for the admin’s decision.', 'error')
        return redirect(url_for('apply_for_sale'))

    user = db['users'].find_one({"username": username})
    if not user or "eth_address" not in user:
        return jsonify({"success": False, "message": "No Ethereum address found for this user."}), 400

    user_eth_address = user.get('eth_address')
    if not user_eth_address:
        return jsonify({"success": False, "message": "Ethereum address not found for user."}), 400

    try:
        sow_date = datetime.strptime(request.form['sow_date'], '%Y-%m-%d')
        harvest_date = datetime.strptime(request.form['harvest_date'], '%Y-%m-%d')

        crop_details = {
            "cropName": request.form.get('crop_name'),
            "cropType": request.form.get('crop_type'),
            "sowDate": sow_date.strftime('%Y-%m-%d'),
            "harvestDate": harvest_date.strftime('%Y-%m-%d'),
            "district": request.form.get('district')
        }
        
        farmer_details = {
            "username": username,
            "userAddress": request.form.get('USER_ADDRESS'),
            "contactNumber": request.form.get('contact_number', ''),
            "landOwnerName": request.form.get('land_owner_name', ''),
            "landSurveyNumber": request.form.get('land_survey_number', '')
        }

        if not farmer_details["contactNumber"]:
            return jsonify({"success": False, "message": "Contact number is required."}), 400
        
        if not farmer_details["contactNumber"].startswith('+'):
            farmer_details["contactNumber"] = '+91' + farmer_details["contactNumber"] 

        # Blockchain transaction
        tx_hash = contract.functions.submitApplication(
            crop_details["cropName"],
            crop_details["cropType"],
            int(sow_date.timestamp()),
            int(harvest_date.timestamp()),
            crop_details["district"],
            farmer_details["username"],
            farmer_details["userAddress"],
            farmer_details["contactNumber"],
            farmer_details["landOwnerName"],
            farmer_details["landSurveyNumber"]
        ).transact({'from': user_eth_address, 'gas': 6000000})

        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        application_id_bytes32 = contract.functions.getLastApplicationId().call()  

        application_id_hex = Web3.to_hex(application_id_bytes32)

        application_data = {
            "id": application_id_hex,  
            "username": username,
            "crop_details": crop_details,
            "farmer_details": farmer_details,
            "ETH_ADDRESS": user_eth_address,
            "status": "Submitted",
            "blockchain_id": application_id_hex  
        }

        db['applications'].insert_one(application_data)
        db['stat_applications'].insert_one(application_data)
        message = f"Hello {username}, your crop application has been successfully submitted! Your Application ID is {application_id_hex}."
        send_sms(farmer_details["contactNumber"], message)


        return redirect(url_for('user_dashboard'))

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"success": False, "message": "Invalid input or internal error occurred."}), 400


from flask import Flask, jsonify, request
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Table, TableStyle
from flask_mail import Mail, Message
from web3 import Web3


@app.route('/admin/send_review_email/<application_id>', methods=['POST'])
def send_review_email(application_id):
    db = get_db()
    application = db['applications'].find_one({"_id": ObjectId(application_id)})

    if not application:
        print(f"❌ Application not found for ID: {application_id}")

        return jsonify({"success": False, "message": "Application not found."}), 404

    username = application.get("username")
    user = db['users'].find_one({"username": username})

    if not user:
        print(f"❌ User not found for username: {username}")
        return jsonify({"success": False, "message": "User not found."}), 404

    email = user.get("email")
    if not email:
        print(f"❌ Email not found for user: {username}")
        return jsonify({"success": False, "message": "User email not found."}), 400
    print(f"✅ Sending email to: {email}")
    eth_address = application.get("ETH_ADDRESS")
    if not eth_address:
        return jsonify({"success": False, "message": "Ethereum address not found for user."}), 400

    crop_details = application["crop_details"]
    farmer_details = application["farmer_details"]

    # Generate Timestamp
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Blockchain Transaction
    try:
        application_id_hex = application.get("blockchain_id")
        app_id_bytes32 = Web3.to_bytes(hexstr=application_id_hex)

        tx_hash = contract.functions.updateApplicationStatus(
            app_id_bytes32,
            "Application Under Review"
        ).transact({'from': admin_eth_address, 'gas': 6000000})
    
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        blockchain_id = tx_receipt.transactionHash.hex()

        db['new_reviews'].insert_one({
            "application_id": application_id,
            "blockchain_id": blockchain_id,
            "crop_details": crop_details,
            "farmer_details": farmer_details,
            "eth_address": eth_address,
            "status": "Application Under Review"
        })

        db['stat_applications'].update_one(
            {"_id": ObjectId(application_id)},
            {"$set": {"status": "Application Under Review", "blockchain_id": blockchain_id}}
        )

    except Exception as blockchain_error:
        print(f"Blockchain Error: {str(blockchain_error)}")
        return jsonify({"success": False, "message": "Error updating blockchain status."}), 500
    contact_number = farmer_details.get('contactNumber')
    if contact_number:
        if not contact_number.startswith('+'):
            contact_number = '+91' + contact_number
        sms_message = f"Hello {username}, your crop application is now under review! 🌾 Stay tuned for updates from Harvest Helper."
        send_sms(contact_number, sms_message)


    # **Generate PDF Receipt**
    pdf_buffer = BytesIO()
    pdf = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(200, height - 50, "Harvest Helper - Crop Review Receipt")
    
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, height - 80, f"Date & Time: {current_datetime}")
    pdf.drawString(50, height - 100, "Contact for queries: suyashutekar11@gmail.com")

    data = [
        ["Field", "Details"],
        ["Username", username],
        ["Crop Name", crop_details.get('cropName', 'N/A')],
        ["Crop Type", crop_details.get('cropType', 'N/A')],
        ["Sow Date", crop_details.get('sowDate', 'N/A')],
        ["Harvest Date", crop_details.get('harvestDate', 'N/A')],
        ["District", crop_details.get('district', 'N/A')],
        ["Farmer Address", farmer_details.get('userAddress', 'N/A')],
        ["Contact Number", farmer_details.get('contactNumber', 'N/A')],
        ["Ethereum Address", eth_address],
        ["Blockchain Transaction ID", blockchain_id],
    ]

    table = Table(data, colWidths=[200, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    table.wrapOn(pdf, width, height)
    table.drawOn(pdf, 50, height - 400)

    pdf.save()
    pdf_buffer.seek(0)

    # **Send Email with PDF**
    try:
        msg = Message(
            "Application Under Review",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"""
        Hello {username},

        Your crop application has been accepted and is now under review. Please find the attached receipt for your records.
        
        Thank you for choosing Harvest Helper.

        Best Regards,
        Harvest Helper Team
        """

        msg.attach("Crop_Application_Review.pdf", "application/pdf", pdf_buffer.read())
        mail.send(msg)

        db['applications'].delete_one({"_id": ObjectId(application_id)})

        return jsonify({"success": True, "message": "Application recorded on blockchain, and email with PDF sent successfully."}), 200
    
    except Exception as e:
        print(f"Error sending email: {e}")
        print("Email not found!")
        return jsonify({"success": False, "message": f"Failed to send email: {str(e)}"}), 500








# #ACCEPT DECLINE APPLICATION
# # Accept Application for Review
# @app.route('/admin/apply_for_review/<application_id>', methods=['POST'])
# def apply_for_review(application_id):
#     db = get_db()

#     # Fetch application details
#     application = db['applications'].find_one({"_id": ObjectId(application_id)})

#     if not application:
#         return jsonify({"success": False, "message": "Application not found"}), 404

#     user_eth_address = application.get('ETH_ADDRESS')
#     if not user_eth_address:
#         return jsonify({"success": False, "message": "Ethereum address not found for this application"}), 400

#     print(f"User Ethereum Address: {user_eth_address}")
#     app_id = application.get("id")
#     if not app_id:
#         return jsonify({"success": False, "message": "Application ID not found"}), 400
    


#     try:
#         # Blockchain interaction for review
#         tx_hash = contract.functions.reviewApplication(
#         app_id,
#         application['crop_name'],
#         application['crop_type'],
#         application['sow_date'],
#         application['harvest_date'],
#         application['state'],
#         application['district'],
#         application['USER_ADDRESS'],
#         application['land_ownership'],
#             "Under Review",
#             user_eth_address
#         ).transact({'from': admin_eth_address, 'gas': 3000000})

#         tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
#         blockchain_id_review = tx_receipt.transactionHash.hex()

#         print(f"Application Review Recorded on Blockchain: {blockchain_id_review}")

#         # Update MongoDB and insert review
#         db['new_reviews'].insert_one({
#     "application_id": application_id,
#     "blockchain_id_review": blockchain_id_review,
#     "status": "Under Review",
#     "admin_eth_address": admin_eth_address,
#     "crop_name": application['crop_name'],
#     "crop_type": application['crop_type'],
#     "sow_date": application['sow_date'],
#     "harvest_date": application['harvest_date'],
#     "state": application['state'],
#     "district": application['district'],
#     "user_address": application['USER_ADDRESS'],
#     "land_ownership": application['land_ownership']
#         })
#         db['applications'].delete_one({"_id": ObjectId(application_id)})
#         db['stat_applications'].update_one(
#             {"_id": ObjectId(application_id)},
#             {"$set": {"status": "Under Review", "blockchain_id_review": blockchain_id_review}}
#         )

#         return jsonify({"success": True, "message": "Application sent for review successfully!"})
    

#     except Exception as e:
#         print(f"Error during review process: {e}")
#         return jsonify({"success": False, "message": "Error recording review on blockchain."}), 500
    



@app.route('/admin/decline_application/<application_id>', methods=['POST'])
def decline_application(application_id):
    db = get_db()
    application = db['applications'].find_one({"_id": ObjectId(application_id)})

    if not application:
        return jsonify({"success": False, "message": "Application not found"}), 404

    user_eth_address = application['USER_ADDRESS']
    try:
        tx_hash = contract.functions.declineApplication(
            int(application_id, 16)
        ).transact({'from': admin_eth_address, 'gas': 3000000})

        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        blockchain_id = tx_receipt.transactionHash.hex()

        db['declined_applications'].insert_one({
            "application_id": application_id,
            "blockchain_id": blockchain_id,
            "status": "Declined",
            "admin_eth_address": admin_eth_address,
            "user_eth_address": user_eth_address
        })

        db['applications'].delete_one({"_id": ObjectId(application_id)})

        return jsonify({"success": True, "message": "Application declined successfully."})

    except Exception as e:
        print(f"Error declining application: {e}")
        return jsonify({"success": False, "message": "Error recording decline on blockchain."}), 500




#Status Code
@app.route('/status')
def crop_status():
    if 'username' not in session:
        return redirect(url_for('login', next=url_for('crop_status')))
    
    db = get_db()
    user_id = session['username']

    # Fetch the latest application for the logged-in user
    application = db.stat_applications.find_one({"username": user_id}, sort=[("_id", -1)])

    print(f"User: {user_id}, Fetched Application: {application}")  # Debugging
    
    if application is None:
        application = {}

    # Extract the grade from status if not directly stored
    if 'status' in application and "Grade Given is:" in application['status']:
        import re
        match = re.search(r"Grade Given is: ([A-C])", application['status'])
        if match:
            application['grade'] = match.group(1)
    print("Final application data sent to template:", application)


    return render_template(
        'status.html',
        application=application,
    )







#REVIEW TEAM CODE
# Route for login page (renamed to revlogin)
@app.route('/revlogin', methods=['GET', 'POST'])
def revlogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db['reviewteam'].find_one({'username': username})

        if user and check_password_hash(user['password'], password):
            session['username'] = username  # Set session
            return redirect(url_for('Reviewteam'))  # Redirect to new_reviews after login
        else:
            return "Invalid credentials. Please try again.", 401  # Unauthorized

    return render_template('revlogin.html')  # Render revlogin form

@app.route('/Reviewteam')
def Reviewteam():
    if 'username' not in session:  # Check if user is logged in
        return redirect(url_for('revlogin'))
    db = get_db()
    application_count = db.new_reviews.count_documents({})
    print("Application Count:", application_count)
  # Count all documents
    return render_template('Reviewteam.html', application_count=application_count)
    

@app.route('/revlogout')
def revlogout():
    session.pop('username', None)  # Clear session
    return redirect('/') 


# Route for managing review team members
@app.route('/admin/manage_reviewteam', methods=['GET', 'POST'])
def manage_reviewteam():
    db = get_db()

    # If POST request, handle the creation of a new review team member
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        # Insert new user into the reviewteam collection
        db['reviewteam'].insert_one({
            'username': username,
            'password': hashed_password
        })

        flash('New review team member added successfully!', 'success')

    # Fetch all review team members from the database
    reviewteam_members = db['reviewteam'].find()

    return render_template('manage_reviewteam.html', reviewteam_members=reviewteam_members)



@app.route('/new_reviews')
def new_reviews():
    # Ensure user is logged in
    if 'username' not in session:
        return redirect(url_for('login', next=url_for('new_reviews')))
    
    # Connect to the database
    db = get_db()

    # Fetch applications under review
    new_reviews = list(db.new_reviews.find({"status": "Application Under Review"}))

    return render_template('new_reviews.html', reviews=new_reviews)


@app.route('/review/<review_id>')
def review_details(review_id):
    db = get_db()
    review = db.stat_applications.find_one({"_id": ObjectId(review_id)})
    if not review:
        return "Review not found", 404
    return render_template('review_details.html', review=review)


from flask_mail import Mail, Message
mail = Mail(app)



def send_notification(username, message):
    db = get_db()
    user = db['users'].find_one({"username": username})

    if not user or "email" not in user:
        print(f"Notification failed: No email found for user {username}")
        return False

    email = user["email"]

    try:
        msg = Message(
            subject="Details Verification Appointment Needed",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email],
            body=message
        )
        mail.send(msg)
        print(f"Notification sent to {username} at {email}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False







@app.route('/review_accept', methods=['POST'])
def review_accept():
    db = get_db()

    # Fetch ETH address from the form
    eth_address = request.form.get('eth_address').strip().lower()  # Normalize case

    print(f"Received eth_address: {eth_address}")

    # Fetch application details using ETH address (Case-insensitive)
    application = db['new_reviews'].find_one({
        "eth_address": {"$regex": f"^{eth_address}$", "$options": "i"}
    })

    print(f"Application found: {application}")

    if not application:
        return jsonify({"success": False, "message": "Application not found"}), 404

    # **Check if the application exists on the blockchain**
    try:
        print(f"Checking blockchain for eth_address: {eth_address}")
        exists = contract.functions.applicationExistsByAddress(Web3.to_checksum_address(eth_address)).call()
        print(f"Application exists on blockchain: {exists}")

        if not exists:
            return jsonify({"message": "Application does not exist on the blockchain", "success": False}), 400
    except Exception as e:
        return jsonify({"message": f"Error checking blockchain: {str(e)}", "success": False}), 500

    # **Calculate mid-term check deadline**
    
    sow_date = datetime.strptime(application['crop_details']['sowDate'], '%Y-%m-%d')
    mid_term_deadline = sow_date + timedelta(days=15) 

    # **Update Blockchain Status**
    try:
        tx_hash = contract.functions.updateApplicationStatusByAddress(
            Web3.to_checksum_address(eth_address),
            "Application Under Mid-Term Review"
        ).transact({'from': admin_eth_address, 'gas': 6000000})

        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        blockchain_tx_id = tx_receipt.transactionHash.hex()

        # **Insert into midterm_application collection**
        db['midterm_application'].insert_one({
            "application_id": str(application["_id"]),
            "blockchain_id": blockchain_tx_id,
            "crop_details": application["crop_details"],
            "farmer_details": application["farmer_details"],
            "eth_address": application["eth_address"],
            "status": "Application Under Mid-Term Review",
            "mid_term_deadline": mid_term_deadline,
            "mid_term_scheduled": False  # No booking yet
        })

        # **Update stat_applications collection status**
        db['stat_applications'].update_one(
            {"_id": application["_id"]},
            {"$set": {
                "status": "Application Under Mid-Term Review",
                "blockchain_id": blockchain_tx_id,
                "mid_term_deadline": mid_term_deadline,
                "mid_term_scheduled": False
            }}
        )

        # **Remove from new_reviews**
        db['new_reviews'].delete_one({"_id": application["_id"]})

        # **Send notification to the farmer**
        farmer_username = application["farmer_details"]["username"]
        send_notification(farmer_username, f"Book your details verification appointment before {mid_term_deadline.strftime('%Y-%m-%d')} or your application will be canceled.")

        return redirect(url_for('new_reviews'))

    except Exception as blockchain_error:
        print(f"Blockchain Transaction Error: {str(blockchain_error)}")
        return jsonify({"success": False, "message": "Error updating blockchain status."}), 500


    
from flask import request, jsonify, session
from datetime import datetime, timezone
from pymongo import MongoClient



##Details verification appointment date selection
@app.route('/book_midterm/<eth_address>', methods=['POST'])
def book_midterm(eth_address):
    if 'username' not in session:
        return jsonify({"success": False, "message": "User not logged in."}), 403

    db = get_db()
    username = session['username']
    data = request.get_json()
    midterm_date = data.get("midterm_date")

    if not midterm_date:
        return jsonify({"success": False, "message": "Date is required."}), 400

    try:
        midterm_date_obj = datetime.strptime(midterm_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid date format. Use YYYY-MM-DD."}), 400

    app_record = db['midterm_application'].find_one(
        {"eth_address": eth_address, "farmer_details.username": username}
    )
    if not app_record:
        return jsonify({"success": False, "message": "No matching application found."}), 404

    result = db['midterm_application'].update_one(
        {"eth_address": eth_address, "farmer_details.username": username},
        {"$set": {"mid_term_date": midterm_date_obj, "mid_term_scheduled": True}}
    )

    if result.modified_count == 0:
        return jsonify({"success": False, "message": "Failed to schedule appointment."}), 500



    return jsonify({"success": True, "message": "Details Verification appointment booked successfully."})









@app.route('/accept_application', methods=['POST'])
def accept_application():
    db = get_db()
    data = request.get_json()
    eth_address = data.get('eth_address')

    if not eth_address:
        return jsonify({"success": False, "message": "ETH Address is missing"}), 400

    eth_address = eth_address.strip()  # Normalize ETH address format

    # **Check MongoDB for Application**
    application = db["midterm_application"].find_one({"eth_address": eth_address})

    print(f"Querying for ETH Address: {eth_address}")
    if not application:
        return jsonify({"success": False, "message": "Application not found in MongoDB"}), 404

    # **Check if Application Exists on Blockchain**
    try:
        exists = contract.functions.applicationExistsByAddress(Web3.to_checksum_address(eth_address)).call()
        if not exists:
            return jsonify({"success": False, "message": "Application does not exist on blockchain"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": f"Blockchain check error: {str(e)}"}), 500

    # **Update Blockchain Using acceptApplicationByAddress**
    try:
        tx_hash = contract.functions.acceptApplicationByAddress(
            Web3.to_checksum_address(eth_address)
        ).transact({'from': web3.eth.accounts[0], 'gas': 6000000})  # Ensure valid sender
        web3.eth.wait_for_transaction_receipt(tx_hash)
    except Exception as blockchain_error:
        return jsonify({"success": False, "message": f"Blockchain Transaction Error: {str(blockchain_error)}"}), 500

    # **Move Application to midterm_applications_stage2**
    application["status"] = "Details Verified Successfully"
    db["midterm_applications_stage2"].insert_one(application)  # Copy details to new collection
    db["midterm_application"].delete_one({"eth_address": eth_address})  # Remove from stage 1

    # **Update stat_applications**
    stat_update_result = db["stat_applications"].update_one(
        {"ETH_ADDRESS": eth_address},  
        {"$set": {"status": "Details Verified Successfully"}}
    )

    if stat_update_result.matched_count == 0:
        print(f"Warning: No matching record found in stat_applications for {eth_address}")



     # **Fetch Farmer Details for Notification**

    farmer_details = application["farmer_details"]
    farmer_username = farmer_details["username"]
    farmer_contact = farmer_details.get("contactNumber", "").strip()

    user_data = db['users'].find_one({"username": farmer_username})
    farmer_email = user_data["email"] if user_data else None

    # **Prepare Message**
    notification_message = f"""
    Hello {farmer_username},

    Your crop application details have been successfully verified.
    Please book your mid-crop assessment date within the next 90 days.

    Visit your dashboard to book your appointment.

    Regards,
    Harvest Helper Team
    """

    # **Send Email Notification**
    if farmer_email:
        msg = Message("Details Verified Successfully - Mid-Crop Assessment Required",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[farmer_email])
        msg.body = notification_message
        mail.send(msg)

    # **Send SMS Notification**
    if farmer_contact:
        # Ensure contact number is in E.164 format (e.g., +14155552671)
        if not farmer_contact.startswith('+'):
            farmer_contact = '+91' + farmer_contact  # Assuming India, change as needed

        send_sms(farmer_contact, f"Hello {farmer_username}, your crop application has been verified! Book your mid-crop assessment date within 90 days.")
    return jsonify({"success": True, "message": "Application details verified successfully."})


@app.route('/midterm_checks')
def midterm_checks():
    db = get_db()
    applications = list(db['midterm_application'].find({"mid_term_scheduled": True}))

    return render_template('midterm_checks.html', applications=applications)



@app.route('/get_application_details/<application_id>', methods=['GET'])
def get_application_details(application_id):
    db = get_db()
    application = db['midterm_application'].find_one({"application_id": application_id})
    if not application:
        application = db['midterm_applications_stage2'].find_one({"application_id": application_id})
    if not application:
        print(f"Application {application_id} not found!") 
        return jsonify({"success": False, "message": "Application not found"}), 404

    return jsonify({
        "application_id": application["application_id"],
        "blockchain_id": application["blockchain_id"],
        "crop_details": application["crop_details"],
        "farmer_details": application["farmer_details"],
        "eth_address": application["eth_address"],
        "mid_term_date": application["mid_term_date"].strftime('%Y-%m-%d')
    })






@app.route('/reject_application/<application_id>', methods=['POST'])
def reject_application(application_id):
    db = get_db()
    
    # Find application details before deleting
    application = db['midterm_application'].find_one({"application_id": application_id})

    if not application:
        return jsonify({"success": False, "message": "Application not found"}), 404

    eth_address = application["eth_address"]

    # Delete from `midterm_application`
    midterm_result = db['midterm_application'].delete_one({"application_id": application_id})

    # Delete from `stat_applications` using `ETH_ADDRESS`
    stat_result = db['stat_applications'].delete_one({"ETH_ADDRESS": eth_address})

    if midterm_result.deleted_count == 0 and stat_result.deleted_count == 0:
        return jsonify({"success": False, "message": "Failed to delete application."}), 500

    # Send rejection email
    farmer_username = application["farmer_details"]["username"]
    farmer_email = db['users'].find_one({"username": farmer_username})["email"]

    try:
        msg = Message(
            "Application Rejected",
            sender=app.config['MAIL_USERNAME'],
            recipients=[farmer_email]
        )
        msg.body = f"""
        Hello {farmer_username},

        We regret to inform you that your crop application associated with ETH Address {eth_address} has been rejected during the mid-term check.

        If you have any questions, please contact our support team.

        Best Regards,  
        Harvest Helper Team
        """
        mail.send(msg)

    except Exception as e:
        print(f"Error sending email: {e}")

    return jsonify({"success": True, "message": "Application rejected, deleted from all collections, and farmer notified."})









# **🔹 Listen for Blockchain Events & Update MongoDB**
def listen_for_events():
    """ Continuously listens for blockchain events and updates MongoDB accordingly """
    while True:
        try:
            # **🔹 MidCropAssessmentBooked Event**
            for event in contract.events.MidCropAssessmentBooked.create_filter(from_block="latest").get_all_entries():
                application_id = Web3.to_hex(event.args.id)
                assessment_date = event.args.assessmentDate
                db["midterm_applications_stage2"].update_one(
                    {"application_id": application_id},
                    {"$set": {"mid_term_date": assessment_date, "status": "Mid-Term Assessment Scheduled"}}
                )

            # **🔹 ApplicationMovedToMidAssessment Event**
            for event in contract.events.ApplicationMovedToMidAssessment.create_filter(from_block="latest").get_all_entries():
                application_id = Web3.to_hex(event.args.id)
                db["midterm_applications_stage2"].update_one(
                    {"application_id": application_id},
                    {"$set": {"status": "Under Process Mid Crop Assessment"}}
                )
                print(f"Application {application_id} moved to 'Under Process Mid Crop Assessment'")

            # **🔹 ApplicationMovedToHarvestStage Event**
            for event in contract.events.ApplicationMovedToHarvestStage.create_filter(from_block="latest").get_all_entries():
                application_id = Web3.to_hex(event.args.id)
                db["midterm_applications_stage2"].update_one(
                    {"application_id": application_id},
                    {"$set": {"status": "Under Process Harvest Applications"}}
                )
                print(f"Application {application_id} moved to 'Under Process Harvest Applications'")

            # **🔹 CropGraded Event**
            for event in contract.events.CropGraded.create_filter(from_block="latest").get_all_entries():
                application_id = Web3.to_hex(event.args.id)
                grade = event.args.grade
                db["midterm_applications_stage2"].update_one(
                    {"application_id": application_id},
                    {"$set": {"status": f"Mid Crop Assessment Done Successfully and Grade Given is: {grade}"}}
                )

            # **🔹 PerKgRateAssigned Event**
            for event in contract.events.PerKgRateAssigned.create_filter(from_block="latest").get_all_entries():
                application_id = Web3.to_hex(event.args.id)
                rate = event.args.rate
                db["midterm_applications_stage2"].update_one(
                    {"application_id": application_id},
                    {"$set": {"per_kg_rate": rate}}
                )

        except Exception as e:
            print(f"Error in event listener: {e}")

        time.sleep(10)  # Poll every 10 seconds

# **🔹 Run Event Listener in Background Thread**
import threading
event_thread = threading.Thread(target=listen_for_events, daemon=True)
event_thread.start()

# **🔹 Flask Route to Check Blockchain Connection**
@app.route("/check_blockchain", methods=["GET"])
def check_blockchain():
    try:
        last_app_id = contract.functions.getLastApplicationId().call()
        return jsonify({"success": True, "last_application_id": Web3.to_hex(last_app_id)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    

@app.route('/midcrop_assessment')
def midcrop_assessment():
    db = get_db()
    today = datetime.today()

    # Fetch applications that are scheduled for assessment today and have not been graded
    applications = db["midterm_applications_stage2"].find({
        "mid_term_date": {"$lte": today},
        "grade": {"$exists": False}  # Ensures only applications without a grade are fetched
    })

    return render_template("midcrop_assessment.html", applications=applications)









import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
import hashlib

###CROP GRADING 
@app.route('/grade_crop', methods=['POST'])
def grade_crop():
    """Handles the mid-crop grading process with debugging"""
    try:
        db = get_db()
        data = request.json
        
        eth_address = data.get("eth_address")  # Use ETH address instead
        grade = data.get("grade")
        
        if not eth_address or not grade:
            return jsonify({"success": False, "message": "Missing ETH address or grade"}), 400

        # **Retrieve Application from Database**
        application = db["midterm_applications_stage2"].find_one({"eth_address": eth_address})
        if not application:
            return jsonify({"success": False, "message": "Application not found in database"}), 404

        # 🔹 **FETCH THE APPLICATION ID FROM BLOCKCHAIN**
        blockchain_application_id = contract.functions.ethToApplicationId(Web3.to_checksum_address(eth_address)).call()
        
        if blockchain_application_id == Web3.to_bytes(hexstr="0x" + "0" * 64):  # Empty bytes32 check
            return jsonify({"success": False, "message": "Application ID not found on blockchain"}), 400

        print(f"Blockchain Application ID: {Web3.to_hex(blockchain_application_id)}")

        # **Check if Application Exists on Blockchain**
        exists_on_chain = contract.functions.applicationExistsByAddress(Web3.to_checksum_address(eth_address)).call()
        if not exists_on_chain:
            return jsonify({"success": False, "message": "Application does not exist on blockchain"}), 400

        # **Check If Already Graded**
        stored_application = contract.functions.cropApplications(blockchain_application_id).call()
        current_grade_status = stored_application[9]  # `graded` field in Solidity struct


        if current_grade_status:
            return jsonify({"success": False, "message": "Application already graded"}), 400

        # **Update on Blockchain**
        tx_hash = contract.functions.gradeCrop(blockchain_application_id, grade).transact({
            'from': web3.eth.accounts[0],
            'gas': 6000000
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)

        # **Update MongoDB**
        # **Update MongoDB (`midterm_applications_stage2`)**
        db["midterm_applications_stage2"].update_one(
            {"eth_address": eth_address},
            {"$set": {
            "status": f"Mid Crop Assessment Done Successfully and Grade Given is: {grade}",
            "grade": grade  # Store grade separately
             }}
            )


# **Update stat_applications Status**
        stat_update_result = db["stat_applications"].update_one(
            {"ETH_ADDRESS": eth_address},  
            {"$set": {
                "status": f"Mid Crop Assessment Done Successfully and Grade Given is: {grade}",
                "grade": grade  # Store grade separately
                }}
            )


        if stat_update_result.matched_count == 0:
            print(f"Warning: No matching record found in stat_applications for {eth_address}")

        # **Retrieve Farmer's Contact Information**
        farmer = db['users'].find_one({"username": application["farmer_details"]["username"]})
        if not farmer:
            print(f"❌ Farmer not found for username: {application['farmer_details']['username']}")
            return jsonify({"success": False, "message": "Farmer details not found"}), 500

        farmer_email = farmer.get("email")
        farmer_phone = application.get("farmer_details", {}).get("contactNumber")  # Assuming 'phone' field exists in users collection

        if not farmer_email:
            print(f"⚠️ Email not found for user: {application['farmer_details']['username']}")
            return jsonify({"success": False, "message": "Farmer email not found"}), 500

        # **Send Email Notification**
        msg = Message(
            "Mid-Crop Assessment Completed",
            sender=app.config['MAIL_USERNAME'],
            recipients=[farmer_email]
        )
        msg.body = f"""
        Hello {application['farmer_details']['username']},

        Your mid-term crop assessment is completed.
        Your crop has been graded as: {grade}.

        Please book your harvest appointment within the next 90 days.

        Regards,
        Harvest Helper Team
        """
        mail.send(msg)

        print(f"📧 Email sent to {farmer_email}")

        # **Send SMS Notification (if phone number exists)**
        if farmer_phone:
            sms_message = f"Hello {application['farmer_details']['username']}, Your mid-crop assessment is complete. Grade: {grade}. Book harvest appointment within 90 days."
            sms_sent = send_sms(farmer_phone, sms_message)
            if sms_sent:
                print(f"📱 SMS sent to {farmer_phone}")
            else:
                print(f"⚠️ Failed to send SMS to {farmer_phone}")
        else:
            print(f"⚠️ No phone number found for {application['farmer_details']['username']}")

        print(f"✅ Grading submitted successfully for ETH Address {eth_address}: Grade {grade}")
        return jsonify({"success": True, "message": f"Grading done successfully"})

    except Exception as e:
        print(f"Error in grading process: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500


@app.route('/book_mid_crop_assessment', methods=['POST'])
def book_mid_crop_assessment():
    db = get_db()
    data = request.json

    # Debugging print statements
    print("Received request:", data)

    eth_address = data.get("eth_address")
    date = data.get("date")

    if not eth_address or not date:
        print("Error: ETH Address or date missing")
        return jsonify({"success": False, "message": "ETH Address or date missing"}), 400

    date_obj = datetime.strptime(date, "%Y-%m-%d")
    application = db["midterm_applications_stage2"].find_one({"eth_address": eth_address})

    if not application:
        print("Error: Application not found in database")
        return jsonify({"success": False, "message": "Application not found in database"}), 404

    try:
        exists = contract.functions.applicationExistsByAddress(Web3.to_checksum_address(eth_address)).call()
        print("Application exists on blockchain:", exists)

        if not exists:
            return jsonify({"success": False, "message": "Application does not exist on blockchain"}), 400

        tx_hash = contract.functions.bookMidCropAssessmentByAddress(
            Web3.to_checksum_address(eth_address), int(date_obj.timestamp())
        ).transact({'from': web3.eth.accounts[0], 'gas': 6000000})
        
        web3.eth.wait_for_transaction_receipt(tx_hash)

    except Exception as e:
        print("Blockchain error:", str(e))
        return jsonify({"success": False, "message": f"Blockchain Error: {str(e)}"}), 500

    db["midterm_applications_stage2"].update_one(
        {"eth_address": eth_address},
        {"$set": {"mid_term_date": date_obj}}
    )

    print("Mid-crop assessment date booked successfully")
    return jsonify({"success": True, "message": "Mid-crop assessment date booked successfully."})










###   HARVEST CODE 
# harvest date booking code 

@app.route('/book_harvest_date', methods=['POST'])
def book_harvest_date():
    db = get_db()
    data = request.json
    eth_address = data.get("eth_address")
    date = data.get("date")

    if not eth_address or not date:
        return jsonify({"success": False, "message": "ETH Address or date missing"}), 400

    date_obj = datetime.strptime(date, "%Y-%m-%d")

    application = db["midterm_applications_stage2"].find_one({"eth_address": eth_address})
    if not application:
        return jsonify({"success": False, "message": "Application not found in database"}), 404

    try:
        # **Check if Application Exists on Blockchain**
        exists = contract.functions.applicationExistsByAddress(Web3.to_checksum_address(eth_address)).call()
        if not exists:
            return jsonify({"success": False, "message": "Application does not exist on blockchain"}), 400

        # **Store Harvest Date on Blockchain**
        tx_hash = contract.functions.bookHarvestDateByAddress(
            Web3.to_checksum_address(eth_address), int(date_obj.timestamp())
        ).transact({'from': web3.eth.accounts[0], 'gas': 6000000})

        web3.eth.wait_for_transaction_receipt(tx_hash)

    except Exception as e:
        return jsonify({"success": False, "message": f"Blockchain Error: {str(e)}"}), 500

    # **Store Harvest Date in MongoDB**
    db["midterm_applications_stage2"].update_one(
        {"eth_address": eth_address},
        {"$set": {"harvest_date": date_obj}}
    )

    return jsonify({"success": True, "message": "Harvest date booked successfully."})


# RETRIVE HARVEST APPLICATION
@app.route('/harvest_applications', methods=['GET'])
def get_harvest_applications():
    db = get_db()
    today = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)

    # Fetch applications whose harvest date is today or earlier
    applications = list(db["midterm_applications_stage2"].find({
        "harvest_date": {"$lte": today},
        "per_kg_rate": {"$exists": False} 
    }))
    for app in applications:
        if "harvest_date" in app:
            app["harvest_date"] = app["harvest_date"].strftime("%d-%b-%Y")
    return render_template("harvest_applications.html", applications=applications)


#RATE ASSIGNING CODE 
@app.route('/assign_per_kg_rate', methods=['POST'])
def assign_per_kg_rate():
    """Assigns a per KG rate and quantity to a harvest application."""
    try:
        db = get_db()
        data = request.json

        eth_address = data.get("eth_address")
        rate_per_kg = data.get("rate_per_kg")
        quantity = data.get("quantity")
 
        if not eth_address or not rate_per_kg or not quantity:
            print("Missing Field: eth_address={}, rate={}, quantity={}".format(eth_address, rate_per_kg, quantity))  # Debugging
            return jsonify({"success": False, "message": "Missing ETH address, rate, or quantity"}), 400
        # **Check if Application Exists on Blockchain**
        exists_on_chain = contract.functions.applicationExistsByAddress(Web3.to_checksum_address(eth_address)).call()
        if not exists_on_chain:
            return jsonify({"success": False, "message": "Application does not exist on blockchain"}), 400

        # **Fetch Application ID from Blockchain**
        application_id_bytes32 = contract.functions.ethToApplicationId(Web3.to_checksum_address(eth_address)).call()
        if application_id_bytes32 == Web3.to_bytes(hexstr="0x" + "0" * 64):  # Empty bytes32 check
            return jsonify({"success": False, "message": "Application ID not found on blockchain"}), 400

        print(f"Blockchain Application ID: {Web3.to_hex(application_id_bytes32)}")

        # **Check if Rate is Already Assigned**
        stored_application = contract.functions.cropApplications(application_id_bytes32).call()
        if stored_application[8]:  # `rateAssigned` field in Solidity struct
            return jsonify({"success": False, "message": "Rate already assigned"}), 400

        # **Call Blockchain Function to Assign Rate & Quantity**
        tx_hash = contract.functions.assignPerKgRate(
            application_id_bytes32, int(rate_per_kg), int(quantity)
        ).transact({'from': web3.eth.accounts[0], 'gas': 6000000})
        
        web3.eth.wait_for_transaction_receipt(tx_hash)

        # **Fetch Current Grade from Status Before Updating**
        application = db["midterm_applications_stage2"].find_one({"eth_address": eth_address})
        if not application:
            return jsonify({"success": False, "message": "Application not found in database"}), 404
        
        previous_status = application.get("status", "Mid Crop Assessment Done Successfully and Grade Given is: Unknown")
        grade = previous_status.split("Grade Given is: ")[-1]  # Extract grade from previous status

        farmer_details = application.get("crop_details", {}).get("farmer_details", {})
        farmer_phone = application.get("farmer_details", {}).get("contactNumber")
        
        # **Update MongoDB (`midterm_applications_stage2`)**
        new_status = f"Application is accepted and Grade given is {grade}, rate assigned per kg is {rate_per_kg} Rs for quantity {quantity} kg."

        db["midterm_applications_stage2"].update_one(
            {"eth_address": eth_address},
            {"$set": {"per_kg_rate": rate_per_kg, "quantity": quantity, "status": new_status}}
        )

        # **Update MongoDB (`stat_applications`)**
        db["stat_applications"].update_one(
            {"ETH_ADDRESS": eth_address},
            {"$set": {"status": new_status}}
        )
        # **Fetch Farmer's Email and Phone Number**
        user_details = db["users"].find_one({"eth_address": eth_address})
        farmer_email = user_details.get("email") if user_details else None



        # **Send Email Notification**
        msg = Message(
            "Congratulations! Your Application Is Accepted",
            sender=app.config['MAIL_USERNAME'],
            recipients=[farmer_email]
        )
        msg.body = f"""
        Hello {application['farmer_details']['username']},

        Your crop has been graded and assigned a rate:       
        Grade Given: {grade},
        Assigned Rate per KG : {rate_per_kg} Rs
        Total Quantity : {quantity} kg

        If you are aggreed with the deal please press the accept button available on the dashboard and also provide your bank details.
        Do this action in upcoming 5 days or else application will be declined.

        Regards,
        Harvest Helper Team
        """
        mail.send(msg)

        # **Send SMS Notification**
        if farmer_phone:
            sms_message = f"Hello {application['farmer_details']['username']},\n" \
                          f"Your crop has been graded!\n" \
                          f"Grade: {grade}, Rate: {rate_per_kg} Rs/kg, Quantity: {quantity} kg.\n" \
                          f"Accept the deal within 5 days via the dashboard and also provide your bank details."

            sms_status = send_sms(farmer_phone, sms_message)
            if sms_status:
                print(f"✅ SMS sent successfully to {farmer_phone}")
            else:
                print(f"❌ SMS sending failed for {farmer_phone}")

        print(f"Grading submitted successfully for ETH Address {eth_address}: Grade {grade}")
        return jsonify({"success": True, "message": "Rate assigned successfully"})

    except Exception as e:
        print(f"Error in assigning per KG rate: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500










###CONFIRM SALE CODE #####
@app.route('/confirm_sale', methods=['POST'])
def confirm_sale():
    """Handles user's decision on the assigned rate."""
    try:
        print("✅ Received request for /confirm_sale")

        db = get_db()
        data = request.json
        eth_address = data.get("eth_address")
        accepted = data.get("accepted")
        bank_details = data.get("bank_details", {})

        

        print(f"🔍 ETH Address: {eth_address}, Accepted: {accepted}")

        if not eth_address:
            print("❌ Error: ETH address missing in request.")
            return jsonify({"success": False, "message": "ETH address missing"}), 400

        application = db["midterm_applications_stage2"].find_one({"eth_address": eth_address})

        if not application:
            print(f"❌ Error: Application not found for ETH Address: {eth_address}")
            return jsonify({"success": False, "message": "Application not found"}), 404

        farmer_username = application["farmer_details"]["username"]

        farmer_username = application.get("farmer_details", {}).get("username")

        farmer_phone = application.get("farmer_details", {}).get("contactNumber")

        print(f"👤 Farmer Username: {farmer_username}, 📞 Farmer Phone: {farmer_phone if farmer_phone else 'Not Found'}")

        if accepted:
            
            print(f"✅ Farmer {farmer_username} accepted the assigned rate.")
            application["bank_details"] = bank_details

            # Move data to crop_sale collection
            db["crop_sale"].insert_one(application)
            print("📂 Moved application to crop_sale collection.")

            # Remove from midterm_applications_stage2
            db["midterm_applications_stage2"].delete_one({"eth_address": eth_address})
            print("🗑️ Removed application from midterm_applications_stage2.")

            # Send SMS Notification for Sale Confirmation
            if farmer_phone:
                sms_body = "Your crop has been successfully added to selling process we will check the application and will let you know."
                sms_status = send_sms(farmer_phone, sms_body)
                print(f"📩 SMS Sent: {'Success' if sms_status else 'Failed'}")

            return jsonify({"success": True, "message": "Sale confirmed. Your crop has been successfully added to selling process we will check the application and will let you know."})

        else:
            print(f"❌ Farmer {farmer_username} rejected the assigned rate.")

            # Remove from midterm_applications_stage2
            db["midterm_applications_stage2"].delete_one({"eth_address": eth_address})
            print("🗑️ Removed application from midterm_applications_stage2.")

            # Send SMS Notification for Rejection
            if farmer_phone:
                sms_body = "You have rejected the assigned rate. Your application has been removed."
                sms_status = send_sms(farmer_phone, sms_body)
                print(f"📩 SMS Sent: {'Success' if sms_status else 'Failed'}")

            return jsonify({"success": True, "message": "Application removed. You rejected the sale."})

    except Exception as e:
        print(f"❌ Error in confirming sale: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

    




@app.route('/crop_sale_applications')
def crop_sale_applications():
    db = get_db()
    crop_sale_collection = db["crop_sale"]

    applications = list(crop_sale_collection.find({}, {"_id": 0}))  # Fetch all applications

    return render_template('crop_sale.html', applications=applications)








@app.route('/ecommerce')
def ecommerce():
    db = get_db()
    crops_for_sale = list(db['market'].find({}, {
        "_id": 0,
        "crop_details.cropName": 1,
        "crop_details.district": 1,
        "per_kg_rate": 1,
        "quantity": 1,
        "grade": 1,
        "eth_address": 1  # add this if you're linking to status page
    }))

    # Fetch buyer's session information (name or ID)
    buyer_name = session.get("buyer_name")

    # Pass crops and buyer_name to the template
    return render_template('ecommerce.html', crops=crops_for_sale, buyer_name=buyer_name)


#BUYER REGISTER ROUTE 
@app.route("/buyer_register", methods=["POST"])
def buyer_register():
    db = get_db()
    buyers_collection = db["buyers"]

    username = request.form["username"].strip()
    first_name = request.form["first_name"].strip()
    last_name = request.form["last_name"].strip()
    contact_number = request.form["contact_number"].strip()
    address = request.form["address"].strip()
    email = request.form["email"].strip()
    password = request.form["password"]
    confirm_password = request.form["confirm_password"]

    # Check if passwords match
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("ecommerce"))

    # Check if email already exists
    if buyers_collection.find_one({"email": email}):
        flash("Email already registered! Please login.", "warning")
        return redirect(url_for("ecommerce"))

    # Check if username already exists
    if buyers_collection.find_one({"username": username}):
        flash("Username already taken! Please choose a different username.", "warning")
        return redirect(url_for("ecommerce"))

    # Hash password and store user
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
    buyers_collection.insert_one({
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "contact_number": contact_number,
        "address": address,
        "email": email,
        "password": hashed_password
    })

    flash("Registration successful! Please login.", "success")
    return redirect(url_for("ecommerce"))


# Buyer Login Route
@app.route("/buyer_login", methods=["POST"])
def buyer_login():
    db = get_db()
    buyers_collection = db["buyers"]

    username = request.form["username"].strip()   # <-- important
    password = request.form["password"]

    buyer = buyers_collection.find_one({"username": username})
    app.logger.debug(f"Buyer document: {buyer}")

    if not buyer or not check_password_hash(buyer["password"], password):
        flash("Invalid username or password!", "danger")
        return redirect(url_for("ecommerce"))

    session["buyer_id"] = str(buyer["_id"])
    session["buyer_name"] = buyer["username"]

    app.logger.debug(f"Buyer {buyer['username']} logged in with session: {session}")

    flash("Login successful!", "success")
    return redirect(url_for("ecommerce"))





@app.route('/buyer_logout')
def buyer_logout():
    session.pop("buyer_name", None)  # Remove the buyer's session
    flash("You have logged out successfully.", "success")
    return redirect(url_for("ecommerce"))



@app.route('/stages')
def stages():
    if "buyer_id" not in session:
        flash("Please login to view the crop timeline.", "warning")
        return redirect(url_for("ecommerce"))
    
    eth_address = request.args.get('ethAddress')
    return render_template('stages.html', ethAddress=eth_address)




def send_email(to_email, subject, body):
    try:
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to_email])
        msg.body = body
        mail.send(msg)
        print(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Email failed: {str(e)}")
        return False
@app.route('/add_to_market', methods=['POST'])
def add_to_market():
    data = request.json
    if not data:
        return jsonify({"message": "Invalid data"}), 400

    db = get_db()
    market_collection = db["market"]
    users_collection = db["users"]
    crop_sale_collection = db["crop_sale"]

    # Insert into Market Collection
    market_collection.insert_one(data)
    crop_sale_collection.delete_one({"eth_address": data["eth_address"]})

    # Get farmer email from `users` collection
    eth_address = data["eth_address"]
    user_details = users_collection.find_one({"eth_address": eth_address})
    farmer_email = user_details.get("email") if user_details else None

    # Farmer Contact Details
    farmer_phone = data["farmer_details"]["contactNumber"]
    farmer_name = data["farmer_details"]["username"]
    crop_name = data["crop_details"]["cropName"]

    # Notifications
    email_subject = "Crop Added to Market"
    email_body = f"Dear {farmer_name},\n\nYour crop ({crop_name}) has been successfully added to the market.\n\nBest Regards,\nCrop Market Team"
    sms_message = f"Your crop ({crop_name}) is now listed in the market."

    if farmer_email:
        send_email(farmer_email, email_subject, email_body)
    else:
        print("❌ No email found for this farmer.")

    send_sms(farmer_phone, sms_message)

    return jsonify({"message": "Crop added to market and farmer notified"}), 200

@app.route('/ratesofcrop')
def rates_of_crop():
    return render_template('ratesofcrop.html')


@app.route('/buy_now/<eth_address>', methods=['GET'])
def buy_now(eth_address):
    if 'buyer_id' not in session:
        flash("Please log in to proceed with the purchase.", "warning")
        return redirect(url_for("ecommerce"))

    db = get_db()
    crop = db['market'].find_one({"eth_address": eth_address})
    if not crop:
        flash("Crop not found!", "danger")
        return redirect(url_for("ecommerce"))

    return render_template("buy_now.html", crop=crop, public_key=stripe_public_key)




import requests

@app.route('/create_checkout', methods=['POST'])
def create_checkout():
    if 'buyer_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db()
    eth_address = request.form.get('eth_address')
    quantity = int(request.form.get('quantity'))
    buyer_location = request.form.get('location')  # Buyer's location input
    contact_number = request.form.get('contact_number')  # Contact number input

    crop = db['market'].find_one({"eth_address": eth_address})
    if not crop:
        return jsonify({"error": "Crop not found"}), 404

    available_quantity = int(crop['quantity'])
    per_kg_rate = float(crop['per_kg_rate'])

    if quantity > available_quantity:
        flash("Entered quantity exceeds available stock!", "danger")
        return redirect(url_for('buy_now', eth_address=eth_address))

    ### --- New Code: Distance API --- ###
    seller_location = crop['farmer_details']['userAddress']  # Seller address from DB

    DISTANCE_API_KEY = 'UJTMijw6thCrpK4KvQD04dwU1e3oD7kNOHdoUTtfmWRksgSegF918oG2qjHBFk1v'
    url = f"https://api.distancematrix.ai/maps/api/distancematrix/json?origins={seller_location}&destinations={buyer_location}&key={DISTANCE_API_KEY}"

    response = requests.get(url)
    distance_data = response.json()

    try:
        # Extract the distance in meters
        distance_meters = distance_data['rows'][0]['elements'][0]['distance']['value']
        distance_km = distance_meters / 1000  # Convert meters to KM
    except Exception as e:
        flash("Failed to calculate delivery distance. Please check address.", "danger")
        return redirect(url_for('buy_now', eth_address=eth_address))

    ### --- Calculate Delivery Fee --- ###
    PER_KM_RATE = 2  # ₹2 per KM
    delivery_fee = round(distance_km * PER_KM_RATE, 2)

    ### --- Calculate Total Price --- ###
    crop_total_price = quantity * per_kg_rate
    final_total_price = crop_total_price + delivery_fee

    # Save order to DB
    order_data = {
        "buyer_id": session['buyer_id'],
        "eth_address": eth_address,
        "quantity": quantity,
        "location": buyer_location,  # Save buyer location
        "contact_number": contact_number,  # Save contact number
        "crop_total_price": crop_total_price,
        "delivery_fee": delivery_fee,
        "final_total_price": final_total_price,
        "distance_km": distance_km,
        "status": "pending"
    }
    order_id = db['pending_orders'].insert_one(order_data).inserted_id

    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'inr',
                'product_data': {
                    'name': f"Crop Purchase - {crop['crop_details']['cropName']} (Including Delivery)",
                },
                'unit_amount': int(final_total_price * 100),  # Stripe expects paise
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('payment_success', order_id=str(order_id), _external=True),
        cancel_url=url_for('buy_now', eth_address=eth_address, _external=True),
    )

    return redirect(checkout_session.url, code=303)




@app.route('/payment_success')
def payment_success():
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    order_id = request.args.get('order_id')
    if not order_id:
        flash("Missing order reference. Payment cannot be verified.", "danger")
        return redirect(url_for('ecommerce'))

    db = get_db()
    order = db['pending_orders'].find_one({"_id": ObjectId(order_id)})

    if not order:
        flash("Order not found or already processed.", "danger")
        return redirect(url_for('ecommerce'))

    eth_address = order["eth_address"]
    quantity_purchased = order["quantity"]
    location = order["location"]
    total_price = order["final_total_price"]
    buyer_id = order["buyer_id"]

    # Fetch crop and buyer details
    crop = db['market'].find_one({"eth_address": eth_address})
    buyer = db['buyers'].find_one({"_id": ObjectId(buyer_id)})

    if not crop or not buyer:
        flash("Missing crop or buyer information.", "danger")
        return redirect(url_for('ecommerce'))

    # Update crop quantity
    updated_quantity = int(crop["quantity"]) - int(quantity_purchased)
    db['market'].update_one(
        {"eth_address": eth_address},
        {"$set": {"quantity": updated_quantity}}
    )

    # Update blockchain
    try:
        tx_hash = contract.functions.reduceQuantityByAddress(
            Web3.to_checksum_address(eth_address),
            int(quantity_purchased)
        ).transact({'from': web3.eth.accounts[0], 'gas': 6000000})
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("✅ Blockchain quantity updated.")
    except Exception as e:
        print(f"❌ Blockchain error: {str(e)}")
        flash("Blockchain update failed, but payment succeeded.", "warning")

    # Store final order
    order_data = {
        "buyer_username": buyer["username"],
        "buyer_email": buyer["email"],
        "eth_address": eth_address,
        "crop_name": crop["crop_details"]["cropName"],
        "crop_type": crop["crop_details"]["cropType"],
        "grade": crop.get("grade", "N/A"),
        "district": crop["crop_details"]["district"],
        "quantity": quantity_purchased,
        "per_kg_rate": crop["per_kg_rate"],
        "total_price": total_price,
        "location": location,
        "order_date": datetime.now(),
        "delivery_estimate": datetime.now() + timedelta(days=40)
    }
    db['orders'].insert_one(order_data)

    # Delete from pending orders
    db['pending_orders'].delete_one({"_id": ObjectId(order_id)})

    # Generate PDF
    pdf_buffer = BytesIO()
    pdf = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(200, height - 50, "Harvest Helper - Order Receipt")

    pdf.setFont("Helvetica", 12)
    y = height - 100
    pdf.drawString(50, y, f"Order Date: {order_data['order_date'].strftime('%Y-%m-%d')}")
    y -= 20
    pdf.drawString(50, y, f"Buyer Username: {order_data['buyer_username']}")
    y -= 20
    pdf.drawString(50, y, f"Crop Name: {order_data['crop_name']}")
    y -= 20
    pdf.drawString(50, y, f"Crop Type: {order_data['crop_type']}")
    y -= 20
    pdf.drawString(50, y, f"Grade: {order_data['grade']}")
    y -= 20
    pdf.drawString(50, y, f"District: {order_data['district']}")
    y -= 20
    pdf.drawString(50, y, f"Quantity: {order_data['quantity']} KG")
    y -= 20
    pdf.drawString(50, y, f"Rate per KG: Rs. {order_data['per_kg_rate']}")
    y -= 20
    pdf.drawString(50, y, f"Total Price: Rs. {order_data['total_price']}")
    y -= 20
    pdf.drawString(50, y, f"Shipping Location: {order_data['location']}")
    y -= 20
    pdf.drawString(50, y, f"Estimated Delivery: {order_data['delivery_estimate'].strftime('%Y-%m-%d')}")

    pdf.save()
    pdf_buffer.seek(0)

    # Email the receipt
    try:
        msg = Message(
            "Your Harvest Helper Order Receipt",
            sender=app.config['MAIL_USERNAME'],
            recipients=[buyer["email"]]
        )
        msg.body = f"""
Hello {order_data['buyer_username']},

✅ Your order has been successfully placed on Harvest Helper!

Crop: {order_data['crop_name']}  
Quantity: {order_data['quantity']} KG  
Total: Rs. {order_data['total_price']}  
Expected Delivery: {order_data['delivery_estimate'].strftime('%Y-%m-%d')}

Thank you for supporting our farmers 🌾
        """
        msg.attach("Order_Receipt.pdf", "application/pdf", pdf_buffer.read())
        mail.send(msg)
        print("📧 Email sent to buyer.")
    except Exception as e:
        print(f"❌ Email send failed: {e}")
        flash("Order placed, but email receipt could not be sent.", "warning")

    flash("✅ Payment successful! Order placed and receipt sent.", "success")
    return redirect(url_for('ecommerce'))

@app.route('/order_history')
def order_history():
    # Ensure the user is logged in
    buyer_username = session.get('buyer_name')
    if not buyer_username:
        return redirect(url_for('buyer_login'))

    db = get_db()  # Assuming you have a function to get the MongoDB connection
    orders = list(db.orders.find({"buyer_username": buyer_username}))

    # Convert datetime objects to readable strings for display in the template
    for order in orders:
        if isinstance(order.get("order_date"), datetime):
            order["order_date"] = order["order_date"].strftime("%Y-%m-%d")
        if isinstance(order.get("delivery_estimate"), datetime):
            order["delivery_estimate"] = order["delivery_estimate"].strftime("%Y-%m-%d")

    return render_template('order_history.html', orders=orders)

@app.route('/ecommerce_orders')
def ecommerce_orders():

    db = get_db()  # Assuming you have a function to get the MongoDB connection
    orders = list(db.orders.find())  # Fetch all orders from the 'orders' collection

    # Optional: Convert datetime objects to strings for easy display in template
    for order in orders:
        if isinstance(order.get("order_date"), datetime):
            order["order_date"] = order["order_date"].strftime("%Y-%m-%d")
        if isinstance(order.get("delivery_estimate"), datetime):
            order["delivery_estimate"] = order["delivery_estimate"].strftime("%Y-%m-%d")

    return render_template('ecommerce_orders.html', orders=orders)





# new features
@app.route('/change_password_user', methods=["POST"])
def change_password_user():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})

    username = session['username']
    current_password = request.form['current_password']
    new_password = request.form['new_password']

    user = get_user(username)
    if not user or not check_password_hash(user['password'], current_password):
        return jsonify({'success': False, 'message': 'Current password is incorrect.'})

    db = get_db()
    db['users'].update_one({"username": username}, {"$set": {"password": generate_password_hash(new_password)}})

    return jsonify({'success': True, 'message': 'Password updated successfully!'})


@app.route("/ecommerce_inventory")
def ecommerce_inventory():
    db = get_db()
    market_collection = db["market"]

    inventory = list(market_collection.find())

    return render_template("admin_ecommerce_inventory.html", inventory=inventory)

if __name__ == '__main__':
    create_collections()
    create_message_collection()
    app.run(debug=True)
