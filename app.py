from flask import Flask, jsonify, request, render_template, redirect, session, make_response, url_for
from flask_restful import Resource, Api
from functools import wraps
import requests
import os
import bcrypt
import jwt
import datetime
import psycopg2

app=Flask(__name__)

app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

SECRET_KEY = os.environ.get('SECRET_KEY') or 'secretxxXx'
app.config['SECRET_KEY'] = SECRET_KEY
app.config['DATABASE_USER'] = 'feagvrqs'
app.config['DATABASE_PASSWORD'] = 'nfkB8S2c3Oljs8GTGhq8XC0RKnOG3v4u'
app.config['DATABASE_DB'] = 'feagvrqs'
app.config['DATABASE_HOST'] = 'satao.db.elephantsql.com'

db = psycopg2.connect(host = app.config['DATABASE_HOST'] , database = app.config['DATABASE_DB'], user = app.config['DATABASE_USER'], password = app.config['DATABASE_PASSWORD'])

api = Api(app)

# Check token
def token_required(f) :
    @wraps(f)
    def decorated(*args, **kwargs) :
        # token = None
        # if 'x-access-tokens' in request.headers:
        #    token = request.headers['x-access-tokens']
        token = session['token']
        if not token :
            response = jsonify('Token is missing!.')
            response.status_code = 403
            return response
        try :
            user = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if (user is None) :
                response = jsonify('Token is invalid!.')
                response.status_code = 403
                return response
        except Exception as e :
            response = jsonify(message = 'Token is invalid!.', error = str(e))
            response.status_code = 403
            return response
        return f(*args, **kwargs)
    return decorated

# Home
class MainPage(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('home.html'), 200, headers)

# Dashboard
class Dashboard(Resource):
    @token_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('dashboard.html'), 200, headers)

# Menu to different types of View
class ViewMenu(Resource):
    @token_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('viewmenu.html'), 200, headers)

# View all data
class View(Resource):
    @token_required
    def get(self):
        try:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM MATERNAL_RISK")
            rows = cursor.fetchall()
            return jsonify(rows)
        except Exception as e:
            print(e)
        finally:
            cursor.close()

# View data by ID
class ViewbyID(Resource):
    @token_required
    def post(self):
        try:
            cursor = db.cursor()
            get_idmr = request.form['id']
            cursor.execute(f"""SELECT * FROM MATERNAL_RISK WHERE idmr = {get_idmr}""")
            rows = cursor.fetchall()
            return jsonify(rows)
        except Exception as e:
            print(e)
        finally:
            cursor.close()

#View data by Risk
class ViewRisk(Resource):
    @token_required
    def post(self):
        try:
            cursor = db.cursor()
            get_risk = request.form['Risk']
            cursor.execute(f"""SELECT * FROM MATERNAL_RISK WHERE RiskLevel = '{get_risk}'""")
            rows = cursor.fetchall()
            return jsonify(rows)
        except Exception as e:
            print(e)
        finally:
            cursor.close()

# Insert data to DB
class Insert(Resource):
    @token_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('insert.html'), 200, headers)

    def post(self):
        try:
            cursor = db.cursor()
            _womanage = int(request.form['Age'])
            _systolicbp = int(request.form['SystolicBP'])
            _diastolicbp = int(request.form['DiastolicBP'])
            _bs = float(request.form['BS'])
            _bodytemp = float(request.form['BodyTemp'])
            _heartrate = int(request.form['HeartRate'])
            _risk = request.form['RiskLevel']
            insertval = f"""INSERT INTO maternal_risk(WomenAge, SystolicBP, DiastolicBP, BS, BodyTemp, HeartRate, RiskLevel) VALUES({_womanage}, {_systolicbp}, {_diastolicbp}, {_bs}, {_bodytemp}, {_heartrate}, '{_risk}')"""
            cursor.execute(insertval)
            db.commit()
            response = jsonify(message='Data added to the dataset successfully.', id=cursor.lastrowid)
            response.status_code = 200
        except Exception as e:
            print(e)
            response = jsonify(message = 'Failed to add data to the dataset.', error = str(e))
            response.status_code = 400
        finally:
            cursor.close()
            return response

# Update data to DB
class Update(Resource):
    @token_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('update.html'), 200, headers)

    def post(self):
        try:
            cursor = db.cursor()
            up_idmr = int(request.form['id'])
            _womenage = request.form['Age']
            _systolicbp = int(request.form['SystolicBP'])
            _diastolicbp = int(request.form['DiastolicBP'])
            _bs = float(request.form['BS'])
            _bodytemp = float(request.form['BodyTemp'])
            _heartrate = request.form['HeartRate']
            _risk = request.form['RiskLevel']
            updateval = f"""UPDATE MATERNAL_RISK SET WomenAge = {_womenage}, SystolicBP = {_systolicbp}, DiastolicBP = {_diastolicbp}, BS = {_bs}, BodyTemp = {_bodytemp}, HeartRate = {_heartrate}, RiskLevel = '{_risk}' WHERE IDMR = {up_idmr}"""      
            cursor.execute(updateval)
            db.commit()
            response = jsonify(message='Data in the dataset updated successfully.', id=cursor.lastrowid)
            response.status_code = 200
        except Exception as e:
            print(e)
            response = jsonify('Failed to update data in the dataset.')
            response.status_code = 400
        finally:
            cursor.close()
            return(response)

# Delete data from DB
class Delete(Resource):
    @token_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('delete.html'), 200, headers)

    def post(self):
        try:
            cursor = db.cursor()
            del_idmr = int(request.form['id'])
            delval = f"""DELETE FROM MATERNAL_RISK WHERE IDMR = {del_idmr}"""
            cursor.execute(delval)
            db.commit()
            response = jsonify(message='Data in the dataset deleted successfully.', id=cursor.lastrowid)
            response.status_code = 200
        except Exception as e:
            print(e)
            response = jsonify('Failed to delete data in the dataset.')
            response.status_code = 400
        finally:
            cursor.close()
            return(response)

# Register Account
class Register(Resource) :
    def check_password(self, password) :
        if len(password) >= 6 and len(password) <= 20 and any(char.isdigit() for char in password) \
            and any(char.isupper() for char in password) and any(char.islower() for char in password):
            return True
        else:
            return False

    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('register.html'), 200, headers)

    def post(self):
        cursor = db.cursor()
        try :
            username = request.form['username']
            password = request.form['password']
            if (username == "" or password == ""):
                response = jsonify('Please provide both username and password.')
                response.status_code = 400
                return response

            # check password validation
            if not self.check_password(password):
                response = jsonify('Password must be between 6 and 20 characters, and must contain at least one digit, one uppercase letter, and one lowercase letter.')
                response.status_code = 400
                return response
            
            # check if username is unique by querying into db
            cursor.execute(f"""SELECT * FROM USERS WHERE username = '{username}'""")
            rows = cursor.fetchall()
            if len(rows) > 0:
                response = jsonify('Username already exists.')
                response.status_code = 400
                return response

            # insert new user into db
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            cursor.execute("INSERT INTO USERS (username, password) VALUES (%s, %s)", (username, hashed_password.decode('utf-8')))
            db.commit()
            response = jsonify('User registered successfully.')
            response.status_code = 201
            # headers = {'Content-Type': 'text/html'}
            return redirect(url_for("mainpage"))
        except Exception as e:
            print(e)
            response = jsonify(message = 'Failed to add data to the dataset.', error = str(e))
            response.status_code = 400
        finally:
            cursor.close()

# Login Account
class Login(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('login.html'), 200, headers)

    def post(self):
        cursor = db.cursor()
        try:
            username = request.form['username']
            password = request.form['password']
            if (username == "" or password == ""):
                response = jsonify('Please provide both username and password.')
                response.status_code = 400
                return response

            # check if username is in db
            cursor.execute(f"""SELECT * FROM USERS WHERE username = '{username}'""")
            rows = cursor.fetchone()
            if len(rows) == 0:
                response = jsonify('Username does not exist.')
                response.status_code = 400
                return response

            # check if password is correct
            if bcrypt.checkpw(password.encode('utf-8'), rows[2].encode('utf-8')):
                token = jwt.encode({'username': username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
                response = jsonify(message = 'User logged in successfully.', token = token)
                session['name'] = username
                session['token'] = token
                # create token for user
                response.status_code = 200
                if username == "pavita":
                    return jsonify(token)
                return redirect(url_for("dashboard"))         
            else:
                response = jsonify('Incorrect password.')
                response.status_code = 400
                return response
        except :
            response = jsonify(message = 'Fail to log in.')
            response.status_code = 400
            return response
        finally:
            cursor.close()    

# Logout
class Logout(Resource):
    def get(self):
        session.clear()
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('home.html'), 200, headers)

# Core
class Core(Resource):
    @token_required
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('core.html'), 200, headers)

    def post(self):
        womanage = request.form['Age']
        risk = request.form['Risk']
        # Predict compatible age match to woman based on some traits based on their age and maternal risk
        url = 'https://tubeststpav.azurewebsites.net/grey/' + str(womanage)
        jsonresp = requests.get(url).json()
        fertile = filter(lambda x: x[4] == "Normal", jsonresp) # filter out infertile ones
        listage = []
        result = []
        respmsg = ""
        if risk == "high risk":
            # no alcohol and no smoking
            temp = filter(lambda x: x[2] == "hardly ever or never", fertile) # alcohol filter
            result = filter(lambda x: x[3] == "never", temp) # smoking filter
            respmsg = f"""For woman with high maternal risk, it is better to find man who hardly ever or never drink alcohol and never smoke."""
        elif risk == "mid risk":
            # alcohol once a week is still acceptable, smocking occasionally is still acceptable
            temp = filter(lambda x: x[2] == "hardly ever or never" or x[2] == "once a week", fertile) # alcohol filter
            result = filter(lambda x: x[3] == "never" or x[3] == "occasional", temp) # smoking filter
            respmsg = f"""For woman with mid maternal risk, it is better to find man who hardly ever or never drink, but drinking once a week is still tolerable. Also, smoking occasionally is still tolerable."""
        elif risk == "low risk":
            # as long as the alcohol consumption is not every day
            result = filter(lambda x : x[2] != "several times a day" or x[2] != "every day", fertile)
            respmsg = f"""For woman with low maternal risk, it is okay as long as the alcohol consumption is not every day."""
        print(result)
        for man in result:
            listage.append(man[1])
            print(man)
        maxage = max(listage, default=0)
        minage = min(listage, default=0)
        if(minage == 0 or maxage == 0):
            respmsg = "Sorry, reccomendation for woman this age is not available"
        response = jsonify(message = respmsg, minimal_age = minage, maximal_age = maxage)
        response.status_code = 200
        return response


# API connected with friend
class Pavita(Resource):
    def get(self, risk):
        # blood pressure data
        cursor = db.cursor()
        sysup = 0
        sysdown = 0
        diasup = 0
        diasdown = 0
        searchval = ""
        risk = risk.replace("-", " ")
        if risk == 'low risk':
            # normal bp
            sysup = 120
            sysdown = 90
            diasup = 80
            diasdown = 60
        elif risk == "mid risk":
            # pre-high bp
            sysup = 140
            sysdown = 120
            diasup = 90
            diasdown = 80
        elif risk == "high risk":
            # high and low blood pressure
            sysup = 190
            sysdown = 140
            diasup = 100
            diasdown = 90
            sysuplow = 90
            sysdownlow = 70
            diasuplow = 60
            diasdownlow = 40
            searchval = f"""SELECT SystolicBP, DiastolicBP, RiskLevel FROM maternal_risk WHERE (SystolicBP BETWEEN {sysdown} AND {sysup} AND DiastolicBP BETWEEN {diasdown} AND {diasup}) OR (SystolicBP BETWEEN {sysdownlow} AND {sysuplow} AND DiastolicBP BETWEEN {diasdownlow} AND {diasuplow}) AND RiskLevel = '{risk}'"""
        if risk != "high risk":
            searchval = f"""SELECT SystolicBP, DiastolicBP, RiskLevel FROM maternal_risk WHERE SystolicBP BETWEEN {sysdown} AND {sysup} AND DiastolicBP BETWEEN {diasdown} AND {diasup} AND RiskLevel = '{risk}'"""
        try :
            cursor.execute(searchval)
            rows = cursor.fetchall()
            return jsonify(rows)
        except Exception as e :
            response = jsonify(message = 'Failed to fetch data in the dataset.')
            response.status_code = 400
            return response
        finally:
            cursor.close()

# API Resource Routes
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(Register, '/register')
api.add_resource(MainPage, '/')
api.add_resource(Dashboard, '/dashboard')
api.add_resource(ViewMenu, '/view-menu')
api.add_resource(View, '/view-all')
api.add_resource(ViewRisk, '/view-risk')
api.add_resource(ViewbyID, '/view-id')
api.add_resource(Insert, '/insert')
api.add_resource(Update, '/update') 
api.add_resource(Delete, '/delete')
api.add_resource(Pavita, '/pavita/<string:risk>')
# api.add_resource(Core, '/core/<string:risk>/<int:womanage>')
api.add_resource(Core, '/core')

if __name__=="__main__":
    app.run(debug=True, host="0.0.0.0", port=5002)