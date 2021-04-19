"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Propiedad, Amenidades, Provincias, Localidades
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import get_jwt_identity
import random
from werkzeug.security import generate_password_hash, check_password_hash

# library for Simple Mail Transfer Protocol# library for Simple Mail Transfer Protocol
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import email.message

api = Blueprint('api', __name__)

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
    return jsonify(user.serialize())

@api.route("/upload-images", methods=["POST"])
def upload_images():
    files = request.files
    print(files)
    # for key in files:
    #     file = files[key]
        
    #     user_id = 10
    #     try:
    #         new_filename ="{}-{}".format(user_id, file.filename)
    #         url_image = upload_file_to_s3(file, os.environ.get('S3_BUCKET_NAME'))
    #     except Exception as e:
    #         raise APIException(e)

    return jsonify("has subido las fotos"), 200
    
@api.route('/request_reset_pass', methods =['POST'])
def request_reset_pass():
    body = request.get_json()
    user_email = body["email"]
    frontend_URL = os.environ.get('FRONTEND_URL')

    user = User.find_by_email(user_email)

    if user:
        try:
            token = jwt.encode({
            'id': user.id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
            }, app.config['SECRET_KEY'])

            short_token = token.decode("utf-8").split(".")[0]

            result_upadte = user.update_user(token=short_token)

            url_reset_email = frontend_URL + "/reset_pass?token=" + short_token

            url_reset_app = "/reset_pass?token=" + short_token

        except:
            raise APIException("Algo esta mal. Su contraseña no ha podido ser cambiada.", 401)

        message_email=f"Hola {user.email}! como nos pidió, aca esta el link para reestablecer su contraseña: {url_reset_email}"
        email = send_email(receiver=user.email, message=message_email)

        return jsonify({'token' : user.token, 'url_reset':url_reset_app}), 201

    else:
        raise APIException("Este usuario no existe", 401)


@api.route('/reset_pass', methods =['POST'])
def reset_pass():
    body = request.get_json()
    user_email = body["email"]
    user_passw = body["password"]
    user_token = body["token"]

    user = User.find_by_email(user_email)

    if user:
        if user.token != user_token:
            raise APIException("The token of request is not correct.", 401)
        try:
            hashed_password = generate_password_hash(user_passw, "sha256")

            result_upadte = user.update_user(password=hashed_password, token="")
        except:
            raise APIException("Algo esta mal. Su contraseña no ha podido ser cambiada", 401)

        return jsonify({"message" :"Su contraseña ha sido cambiada con exito."}), 201
    else:
        raise APIException("Este usuario no existe", 401)


def send_email(receiver=None, message=""):
    if receiver is not None:
        try:
            msg = MIMEMultipart()
            password = os.environ.get('PASS_EMAIL')
            msg['From'] = "ready2helpemail@gmail.com"
            msg['To'] = receiver
            msg['Subject'] = "Ready2Help - Reset Password"
            # add in the message body
            msg.attach(MIMEText(message, 'plain'))
            #create server
            server = smtplib.SMTP('smtp.gmail.com: 587')
            server.starttls()
            # Login Credentials for sending the mail
            server.login(msg['From'], password)
            # send the message via the server.
            server.sendmail(msg['From'], msg['To'], msg.as_string())
            server.quit()
            print("Enviado con exito al correo: %s" % (msg['To']))
        except:
            raise APIException("Algo esta mal, su correo electronico no ha sido enviado.", 401)
    else:
        raise APIException("Algo esta mal, el correo no puede estar vacio.", 401)

@api.route('/propiedades', methods=['POST'])
@jwt_required()
def propiedades():
    body = request.get_json()
    print(body)

    user_id = get_jwt_identity()
    

    Propiedad.create_propiedad(user_id, body["calle"], body["numero"],
                                body["ciudad"], body["codigo_postal"],
                                body["comunidad"], body["dormitorios"],
                                body["huespedes"], body["camas"],
                                body["bathrooms"], body["descripcion"])

    return jsonify("se subio la informacion"), 200

@api.route('/amenidades', methods=['POST'])
def amenidades():
    body = request.get_json()
    print(body)

    try:
        Amenidades.create_amenidades(body["piscina"], body["cocina"],
                                    body["parking"], body["wifi"],
                                    body["tv"], body["aire_acondicionado"],
                                    body["calefaccion"], body["chimenea"],
                                    body["agua_caliente"], body["zona_trabajo"])
    except Exception as err:
        print(err)

    # except:
    #     raise APIException("Error")

    return jsonify("se subio la informacion"), 200

# @api.route('/provincias', methods=['POST'])
# def provincias():
#     body = request.get_json()
#     print(body)

#     try:
#         Provincias.create_provincias(body["almeria"], body["cadiz"],
#                                     body["cordoba"], body["granada"],
#                                     body["huelva"], body["jaen"],
#                                     body["malaga"], body["sevilla"])
                                    
    # except Exception as err:
    #     print(err)

    # except:
    #     raise APIException("Error")

    return jsonify("se subio la informacion"), 200

@api.route('/localidades', methods=['POST'])
def localidades():
    body = request.get_json()
    print(body)

    try:
        Localidades.create_provincias(body["ciudad"])
        #  body["agua_amarga"], body["berja"], body["las_negras"],body["lucainena_de_las_torres"], body["mojacar"],   body["malaga"], body["sevilla"], body["rodalquilar"], body["velez_blanco"],
        # body["arcos_de_la_frontera"], body["castellar_de_la_frontera"],body["chipiona"], body["grazalema"],   body["medina_sidonia"], body["olvera"],body["sanlucar_de_barrameda"], body["vejer_de_la_frontera"],
        # body["almodovar_del_rio"], body["baena"], body["espejo"], body["iznajar"],body["luque"], body["priego_de_cordoba"], body["zuheros"],
        # body["albañuelas"], body["castril"], body["guadix"], body["montefrio"], body["nigüelas"], body["nivar"], body["pampaneira"], body["salobreña"], body["trevelez"], 
        # body["alcala_la_real"], body["alcaudete"],body["baeza"], body["baños_de_la_encima"], body["cazorla"], body["hornos"],body["la_iruela"], body["ubeda"],
        # body["alajar"], body["almonaster_la_real"],body["ayamonte"], body["aracena"], body["el_rocio_almonte"], body["el_rompido"],body["jagubo"], body["moguer"],body["palos_de_frontera"],
        # body["antequera"],body["archidona"],body["casares"],body["frigiliana"],body["marbella"],body["mijas"],body["nerja"],body["ojen"],body["ronda"],
        # body["aznalcazar"],body["carmona"],body["cazalla_de_la_sierra"],body["constatina"],body["ecija"],body["estepa"],body["lebrija"],body["marchena"], body["osuna"],body["sanlucar_la_mayor"],body["santiponce"],body["utrera"])                                                     
                                    
    except Exception as err:
        print(err)

    # except:
    #     raise APIException("Error")

    return jsonify("se subio la informacion"), 200

@api.route('/provincias', methods=['POST'])
def provincias():
    body = request.get_json()
    print(body)

    try:
        Provincias.create_provincias(body["comunidad"])
    except Exception as err:
        print(err)

    # except:
    #     raise APIException("Error")

    return jsonify("se subio la informacion"), 200
@api.route('/localidad', methods=['POST'])
def localidad():
    body = request.get_json()
    print(body)

    try:
        Localidades.create_localidad(body["ciudad"])
    except Exception as err:
        print(err)

    # except:
    #     raise APIException("Error")

    return jsonify("se subio la informacion"), 200
