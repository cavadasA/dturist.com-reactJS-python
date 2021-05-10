"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Propiedad, Amenidades
from api.utils import generate_sitemap, APIException
from aws import upload_file_to_s3
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import get_jwt_identity
import random
from werkzeug.security import generate_password_hash, check_password_hash

import stripe
# This is your real test secret API key.
stripe.api_key = 'pk_test_51InoiJDKwicxTU51Yb2iXOAobK6fsMNPOKLLpXpfs9o2epiwDUW9HcrhHbC90yRrVmy6DFp7KmlQtSYU3Fpme3kO00V0r29ECt'

 
api = Blueprint('api', __name__)

@api.route('/', methods=['POST'])
def search():
    body = request.get_json()
    availableProperties = []
    propiedades1 = Propiedad.getByLocation(body["location"], body["capacidad"])
    
    for propiedad in propiedades1:
        availableProperties.append(propiedad.serialize())

    return jsonify(availableProperties)


@api.route('/signup', methods=['POST'])
def signup():
    body = request.get_json()
    password = body["password"]
    hashed = generate_password_hash(password, "sha256")

    User.create_user(body["name"], body["lastname"],
                        body["email"], hashed) 

    return jsonify({}), 200

@api.route("/login", methods=["POST"])
def login():
    body = request.get_json()
    email = body["email"]
    password = body["password"]
    user = User.get_with_email(email)
    
    if user is None:
        raise APIException("Datos incorrectos")
    if check_password_hash(user.password, password):
        access_token = create_access_token(identity = user.id)
        return jsonify({"access_token": access_token})
    else:
        raise APIException("Datos incorrectos")
    
@api.route("/profile", methods=['GET'])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.get(current_user_id)
    print(user)
    return jsonify(user.serialize())

@api.route("/upload-images", methods=["POST"])
def upload_images():
    url_image= ''
    files = request.files
    print(files)
    for key in files:
        file = files[key]
        print(file)
        # user_id = 10
        try:
            # new_filename ="{}-{}".format(user_id, file.filename)
            url_image = upload_file_to_s3(file, os.environ.get('S3_BUCKET_NAME'))
        except Exception as e:
            print(e)
            raise APIException(e)

    return jsonify({"url":url_image}), 200
    
@api.route('/forgot-password', methods=['POST'])
def forgot_password():
    request_json = request.get_json()
    print(request_json)
    email = request_json["email"]
    
    if email is None:
        raise APIException("Email required")
    
    token = random.randint(100000000,199990000)
    user = User.get_user_email(email)
    if user is None:
        raise APIException("user no encontrado")
    user.token = str(token)

    db.session.commit()

    forgot_password = ForgotPasswordEmail(email, token)
    # forgot_password.send()      
    url= forgot_password.send()

    # return jsonify({}), 200
    return jsonify({"url": url, "token": token }), 200
   

@api.route('/newPassword', methods=['POST'])
def reset_password():
    request_json = request.get_json()
    print(type(request_json["token"]))
    # email = request_json["email"]
    token = str(request_json["token"])
    password = request_json["password"]

    user = User.get_for_forgot( token)
    user.password = password
    user.token = None

    db.session.commit()

    return jsonify({}), 200

@api.route('/propiedades', methods=['POST'])
@jwt_required()
def propiedades():
    body = request.get_json()
    user_id = get_jwt_identity()    
    propiedad_id = Propiedad.create_propiedad(user_id, body["titulo"], body["calle"], body["numero"],
                                body["ciudad"], body["codigo_postal"],
                                body["provincia"], body["dormitorios"],
                                body["huespedes"], body["camas"],
                                body["bathrooms"], body["precio"], body["descripcion"])
    propiedad = Propiedad.get(propiedad_id)
        
    for amenidad in body["amenidades"]:
        if (Amenidades.get(amenidad) != None):
            existing_amenity = Amenidades.get(amenidad)
            propiedad.amenidades.append(existing_amenity)
            db.session.add(existing_amenity)
            db.session.commit()
        else: 
            raise APIException("Amenidad no existente")
    
    return jsonify("se subio la informacion"), 200

@api.route("/misPropiedades", methods=['GET'])
@jwt_required()
def mis_propiedades():
    current_user_id = get_jwt_identity()
    user = User.get(current_user_id)
    propiedades = []
    for propiedad in user.propiedades:
        propiedades.append(propiedad.serialize())

    return jsonify(propiedades)


app = Flask(__name__,
            static_url_path='',
            static_folder='.')

YOUR_DOMAIN = 'https://3000-peach-tiglon-d07e06w2.ws-eu04.gitpod.io/'
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price_data': {
                        'currency': '€',
                        'unit_amount': 2000,
                        'product_data': {
                            'name': 'Paga tu reserva',
                            'images': ['https://i.imgur.com/EHyR2nP.png'],
                        },
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url='https://3000-peach-tiglon-d07e06w2.ws-eu04.gitpod.io/' + '?success=true',
            cancel_url='https://3000-peach-tiglon-d07e06w2.ws-eu04.gitpod.io/' + '?canceled=true',
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403
if __name__ == '__main__':
    app.run(port=4242)