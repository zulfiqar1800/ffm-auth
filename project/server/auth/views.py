from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
import validators
import phonenumbers
from flask import current_app

from project.server import bcrypt, db
from project.server.models import User, BlacklistToken, Module, UserModule, Companies, DashboardUser, CompanyPanel, CompanyUsers
from project.server.config import SECRET_TEXT

auth_blueprint = Blueprint('auth', __name__)


class Register(MethodView):
    def post(self):
        post_data = {}
        response_msg = []
        try:
            post_data = request.get_json()
        except Exception as e:
            print(e)
            response_msg.append('Request body must be non-empty')
            responseObject = {
                'status': 'failed',
                'message': response_msg
            }
            return make_response(jsonify(responseObject)), 403

        if post_data.get('phone_number', '') == '':
            response_msg.append('phone_number must be non-empty')
        if post_data.get('iso_code', '') == '':
            response_msg.append('iso_code must be non-empty')
        if post_data.get('company_id', '') == '':
            response_msg.append('company_id must be non-empty')
        if post_data.get('first_name', '') == '':
            response_msg.append('first_name must be non-empty')
        if post_data.get('last_name', '') == '':
            response_msg.append('last_name must be non-empty')
        if post_data.get('nid', '') == '':
            response_msg.append('nid must be non-empty')
        if post_data.get('designation', '') == '':
            response_msg.append('designation must be non-empty')
        if post_data.get('department', '') == '':
            response_msg.append('department must be non-empty')

        if len(response_msg) > 0:
            responseObject = {
                'status': 'failed',
                'message': response_msg
            }
            return make_response(jsonify(responseObject)), 403
        if not phonenumbers.is_valid_number(phonenumbers.parse(post_data.get('phone_number'), post_data.get('iso_code'))):
            responseObject = {
                    'status': 'fail',
                    'message': 'Valid Phone number is required.'
                }
            return make_response(jsonify(responseObject)), 403

        user = User.query.filter_by(phone_number=post_data.get('phone_number')).first()
        is_company = Companies.query.filter_by(id=post_data.get('company_id')).first()
        if not is_company:
            responseObject = {
                    'status': 'fail',
                    'message': 'Company does not exists. Please try again.'
                }
            return make_response(jsonify(responseObject)), 404
        if not user:
            try:
                user = User(
                    company_id=post_data.get('company_id'),
                    phone_number=post_data.get('phone_number'),
                    first_name=post_data.get('first_name'),
                    last_name=post_data.get('last_name'),
                    nid=post_data.get('nid'),
                    designation=post_data.get('designation'),
                    department=post_data.get('department'),
                    profile_photo='https://randomuser.me/api/portraits/lego/5.jpg',
                    member_type=3
                )
                db.session.add(user)
                db.session.commit()

                company_user = CompanyUsers(
                        company_id=post_data.get('company_id'),
                        user_id=user.id
                )
                db.session.add(company_user)
                db.session.commit()

                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.'
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                print(e)
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Phone Number already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 400


class AdminRegister(MethodView):
    def post(self):
        post_data = request.get_json()
        response_msg = []
        if post_data.get('email') == '':
            response_msg.append('email must be non-empty')
        if post_data.get('password') == '':
            response_msg.append('password must be non-empty')
        if post_data.get('username') == '':
            response_msg.append('username must be non-empty')
        if post_data.get('firstname') == '':
            response_msg.append('firstname must be non-empty')
        if post_data.get('lastname') == '':
            response_msg.append('lastname must be non-empty')

        if len(response_msg) > 0:
            responseObject = {
                'status': 'failed',
                'message': response_msg
            }
            return make_response(jsonify(responseObject)), 403
        if not validators.email(post_data.get('email')):
            responseObject = {
                    'status': 'fail',
                    'message': 'Provide a valid e-mail.'
                }
            return make_response(jsonify(responseObject)), 403

        user = DashboardUser.query.filter_by(email=post_data.get('email')).first()
        is_username = DashboardUser.query.filter_by(username=post_data.get('username')).first()
        is_company = Companies.query.filter_by(id=1).first()
        if not is_company:
            company = Companies(
                    name='admin',
                    address='ts4u',
                    tin='1111111111111'
                )
            db.session.add(company)
            db.session.commit()
        if not user and not is_username:
            try:
                user = DashboardUser(
                    email=post_data.get('email'),
                    password=post_data.get('password'),
                    username=post_data.get('username'),
                    first_name=post_data.get('firstname'),
                    last_name=post_data.get('lastname'),
                    company_id=1,
                    member_type=1
                )
                try:
                    db.session.add(user)
                    db.session.commit()
                    print(user.id)
                    panel_user = CompanyPanel(
                        panel_user_id=user.id,
                        company_id=1
                    )
                    db.session.add(panel_user)
                    db.session.commit()
                except Exception as e:
                    print(e)
                    print("error creating user. Please try again.")

                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered admin user ' + str(post_data.get('username')) + '.'
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                print(e)
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Email/Username already exists. Please try again.'
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 400


class DashboardUserRegister(MethodView):
    def post(self):
        post_data = request.get_json()
        response_msg = []
        if post_data.get('email') == '':
            response_msg.append('email must be non-empty')
        if post_data.get('password') == '':
            response_msg.append('password must be non-empty')
        if post_data.get('username') == '':
            response_msg.append('username must be non-empty')
        if post_data.get('firstname') == '':
            response_msg.append('firstname must be non-empty')
        if post_data.get('lastname') == '':
            response_msg.append('lastname must be non-empty')
        if post_data.get('company_id') == '':
            response_msg.append('company id must be non-empty')

        if len(response_msg) > 0:
            responseObject = {
                'status': 'failed',
                'message': response_msg
            }
            return make_response(jsonify(responseObject)), 403
        if not validators.email(post_data.get('email')):
            responseObject = {
                    'status': 'fail',
                    'message': 'Provide a valid e-mail.'
                }
            return make_response(jsonify(responseObject)), 403

        user = DashboardUser.query.filter_by(email=post_data.get('email')).first()
        is_username = DashboardUser.query.filter_by(username=post_data.get('username')).first()
        is_company = Companies.query.filter_by(id=post_data.get('company_id')).first()
        if not is_company:
            responseObject = {
                    'status': 'fail',
                    'message': 'Company does not exists. Please try again.'
                }
            return make_response(jsonify(responseObject)), 404
        if not user and not is_username:
            try:
                user = DashboardUser(
                    email=post_data.get('email'),
                    password=post_data.get('password'),
                    username=post_data.get('username'),
                    first_name=post_data.get('firstname'),
                    last_name=post_data.get('lastname'),
                    company_id=post_data.get('company_id'),
                    member_type=2
                )
                try:
                    db.session.add(user)
                    db.session.commit()
                    print(user.id)
                    panel_user = CompanyPanel(
                        panel_user_id=user.id,
                        company_id=post_data.get('company_id')
                    )
                    db.session.add(panel_user)
                    db.session.commit()
                except Exception as e:
                    print(e)
                    print("error creating user. Please try again.")

                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered dashboard user ' + str(post_data.get('username')) + '.'
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                print(e)
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Email/Username already exists. Please try again.'
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 400


class CompanyRegister(MethodView):
    def post(self):
        post_data = request.get_json()
        response_msg = []
        if post_data.get('name') == '':
            response_msg.append('name must be non-empty')
        if post_data.get('address') == '':
            response_msg.append('address must be non-empty')
        if post_data.get('tin') == '':
            response_msg.append('tin must be non-empty')

        if len(response_msg) > 0:
            responseObject = {
                'status': 'failed',
                'message': response_msg
            }
            return make_response(jsonify(responseObject)), 403

        company = Companies.query.filter_by(name=post_data.get('name')).first()
        is_tin = Companies.query.filter_by(tin=post_data.get('tin')).first()
        if is_tin:
            responseObject = {
                'status': 'fail',
                'message': 'TIN already exists. Please try with an unique TIN.',
            }
            return make_response(jsonify(responseObject)), 400
        if not company:
            try:
                company = Companies(
                    name=post_data.get('name'),
                    address=post_data.get('address'),
                    tin=post_data.get('tin')
                )
                db.session.add(company)
                db.session.commit()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'company_id': company.id,
                        'company_name': company.name,
                        'company_address': company.address,
                        'tin': company.tin
                    },
                    'message': 'Successfully registered company \'' + str(company.name) + '\' .'
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                print(e)
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Company Name already exists. Please try with another name.',
            }
            return make_response(jsonify(responseObject)), 400


class UserLogin(MethodView):
    def post(self):
        post_data = request.get_json()
        response_msg = []
        if post_data.get('firebase_id') == '':
            response_msg.append('firebase_id must be non-empty')
        if post_data.get('phone_number') == '':
            response_msg.append('phone_number must be non-empty')
        if post_data.get('phone_number_int') == '':
            response_msg.append('phone_number_int must be non-empty')
        if post_data.get('iso_code') == '':
            response_msg.append('country_code must be non-empty')
        if post_data.get('secret_text') == '':
            response_msg.append('secret_text must be non-empty')
        # if post_data.get('company_id') == '':
        #     response_msg.append('company_id must be non-empty')

        if len(response_msg) > 0:
            responseObject = {
                'status': 'failed',
                'message': response_msg
            }
            return make_response(jsonify(responseObject)), 403
        if not phonenumbers.is_valid_number(phonenumbers.parse(post_data.get('phone_number'), post_data.get('iso_code'))):
            responseObject = {
                    'status': 'fail',
                    'message': 'Valid Phone number is required.'
                }
            return make_response(jsonify(responseObject)), 403
        try:
            user = User.query.filter_by(phone_number=post_data.get('phone_number')).first()
            or_user = User.query.filter_by(phone_number=post_data.get('phone_number_int')).first()

            is_secret = True if post_data.get('secret_text') == SECRET_TEXT else False
            # is_company = True if post_data.get('company_id') == user.company_id else False
            # if not user or not is_company:
            #     responseObject = {
            #         'status': 'fail',
            #         'message': 'User doesn\'t exist'
            #     }
            #     return make_response(jsonify(responseObject)), 404
            if not is_secret:
                responseObject = {
                    'status': 'fail',
                    'message': 'Auth Key does not match.'
                }
                return make_response(jsonify(responseObject)), 404
            if user or or_user:
                moudle_list_obj = UserModule.query.filter_by(user_id=user.id).all()
                modules = []
                for module in moudle_list_obj:
                    print(module.module_id)
                    mod = Module.query.filter_by(id=module.module_id).first()
                    modules.append(mod.name)
                auth_token = user.encode_auth_token(user.id, modules)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode(),
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 400
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'Fail',
                'message': 'User Login Failed because of wrong phone_number/firebase_id.'
            }
            return make_response(jsonify(responseObject)), 400


class DashboardUserLogin(MethodView):
    def post(self):
        post_data = request.get_json()
        response_msg = []
        if post_data.get('email') == '':
            response_msg.append('email must be non-empty')
        if post_data.get('password') == '':
            response_msg.append('password must be non-empty')

        if len(response_msg) > 0:
            responseObject = {
                'status': 'failed',
                'message': response_msg
            }
            return make_response(jsonify(responseObject)), 403

        if not validators.email(post_data.get('email')):
            print('hello')
            responseObject = {
                    'status': 'fail',
                    'message': 'Provide a valid e-mail.'
                }
            return make_response(jsonify(responseObject)), 403
        try:
            user = DashboardUser.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.id)
                current_app.logger.info(auth_token)
                current_app.logger.info(type(auth_token))
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode(),
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'E-mail/Password is wrong.'
                }
                return make_response(jsonify(responseObject)), 400
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'User Login Failed because of wrong email/password.'
            }
            return make_response(jsonify(responseObject)), 400


class Authentication(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 403
        else:
            auth_token = ''
        if auth_token:
            try:
                resp = User.decode_auth_token(auth_token)
                if not isinstance(resp, str):
                    user = User.query.filter_by(id=resp).first()
                    responseObject = {
                        'status': 'success',
                        'data': user.id
                    }
                    return make_response(jsonify(responseObject)), 200

                responseObject = {
                    'status': 'fail',
                    'message': "Failed to parse auth token."
                }
                return make_response(jsonify(responseObject)), 400
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': "Failed to parse auth token."
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class DashboardAuthentication(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 403
        else:
            auth_token = ''
        if auth_token:
            try:
                resp = DashboardUser.decode_auth_token(auth_token)
                if not isinstance(resp, str):
                    user = DashboardUser.query.filter_by(id=resp).first()
                    responseObject = {
                        'status': 'success',
                        'data': user.id
                    }
                    return make_response(jsonify(responseObject)), 200
                responseObject = {
                    'status': 'fail',
                    'message': "Failed to parse auth token."
                }
                return make_response(jsonify(responseObject)), 400
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': "Failed to parse auth token."
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class RefreshToken(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 403
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                moudle_list_obj = UserModule.query.filter_by(user_id=user.id).all()
                modules = []
                for module in moudle_list_obj:
                    print(module.module_id)
                    mod = Module.query.filter_by(id=module.module_id).first()
                    modules.append(mod.name)

                auth_token = user.encode_auth_token(user.id, modules)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully refreshed token.',
                        'auth_token': auth_token,
                    }
                    return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class Logout(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                db.session.add(user)
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 400
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class DashboardLogout(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = DashboardUser.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = DashboardUser.query.filter_by(id=resp).first()
                db.session.add(user)
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 400
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class GetCompanyList(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 403
        else:
            auth_token = ''
        if auth_token:
            try:
                resp = DashboardUser.decode_auth_token(auth_token)
                current_app.logger.info(resp)
                current_app.logger.info('==============info================')
                if not isinstance(resp, str):
                    user = DashboardUser.query.filter_by(id=resp).first()
                    current_app.logger.info('=========here===========')
                    responseObject = []
                    if user:
                        current_app.logger.info('============there==========')
                        companies = Companies.query.all()
                        for company in companies:
                            responseObject.append({
                                "id": company.id,
                                "name": company.name,
                                "address": company.address,
                                "tin": company.tin
                            })
                        return make_response(jsonify(responseObject)), 200
                    responseObject = {
                        'status': 'fail',
                        'message': "You do not have sufficient permission."
                    }
                    return make_response(jsonify(responseObject)), 400    
                responseObject = {
                    'status': 'fail',
                    'message': "You do not have sufficient permissions."
                }
                return make_response(jsonify(responseObject)), 400
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': "Failed to parse auth token."
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class GetCompanyUsers(MethodView):
    def get(self, company_id):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 403
        else:
            auth_token = ''
        if auth_token:
            try:
                resp = DashboardUser.decode_auth_token(auth_token)
                if not isinstance(resp, str):
                    user = DashboardUser.query.filter_by(id=resp).first()
                    responseObject = []
                    if user:
                        users = CompanyUsers.query.filter_by(company_id=company_id).all()
                        for user in users:
                            user_info = User.query.filter_by(id=user.user_id).first()
                            responseObject.append({
                                "id": user_info.id,
                                "registered_on": user_info.registered_on,
                                "first_name": user_info.first_name,
                                "phone_number": user_info.phone_number,
                                "email": user_info.email
                            })
                        return make_response(jsonify(responseObject)), 200
                    responseObject = {
                        'status': 'fail',
                        'message': "You do not have sufficient permission."
                    }
                    return make_response(jsonify(responseObject)), 400    
                responseObject = {
                    'status': 'fail',
                    'message': "You do not have sufficient permission."
                }
                return make_response(jsonify(responseObject)), 400
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': "Failed to parse auth token."
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class GetCompanyContacts(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 403
        else:
            auth_token = ''
        if auth_token:
            try:
                resp = User.decode_auth_token(auth_token)
                if not isinstance(resp, str):
                    user = User.query.filter_by(id=resp).first()
                    responseObject = []
                    if user:
                        users = DashboardUser.query.filter_by(company_id=user.company_id).all()
                        for user in users:
                            responseObject.append({
                                "name": user.first_name + " " + user.last_name,
                                "department": user.department,
                                "designation": user.designation,
                                "phone_number": user.phone_number,
                                "email": user.email,
                                "profile_photo": user.profile_photo
                            })
                        return make_response(jsonify(responseObject)), 200
                    responseObject = {
                        'status': 'fail',
                        'message': "You do not have sufficient permission."
                    }
                    return make_response(jsonify(responseObject)), 401    
                responseObject = {
                    'status': 'fail',
                    'message': "You do not have sufficient permission."
                }
                return make_response(jsonify(responseObject)), 401
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': "Failed to parse auth token."
                }
                return make_response(jsonify(responseObject)), 400
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class Health(MethodView):
    def get(self):
        responseObject = {
            'status': 'success'
        }
        return make_response(jsonify(responseObject)), 200


health_view = Health.as_view('health_api')
registration_view = Register.as_view('register_api')
company_registration_view = CompanyRegister.as_view('company_register_api')
dashboard_user_registration_view = DashboardUserRegister.as_view('dashboard_user_register_api')
admin_user_registration_view = AdminRegister.as_view('admin_register_api')
login_view = UserLogin.as_view('login_api')
panel_user_login_view = DashboardUserLogin.as_view('panel_user_login_api')
logout_view = Logout.as_view('logout_api')
logout_panel_view = DashboardLogout.as_view('logout_panel_api')
authentication_view = Authentication.as_view('authentication_api')
authentication_dashboard_view = DashboardAuthentication.as_view('dashboard_authentication_api')
refreshtoken_view = RefreshToken.as_view('refreshtoken_api')
get_company_list_view = GetCompanyList.as_view('get_company_list_api')
get_company_users_view = GetCompanyUsers.as_view('get_company_users_api')
get_company_contact_view = GetCompanyContacts.as_view('get_company_contact_api')

auth_blueprint.add_url_rule(
    '/',
    view_func=health_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/register-user',
    view_func=registration_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/register-company',
    view_func=company_registration_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/register-dashboard-user',
    view_func=dashboard_user_registration_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/register-admin-user',
    view_func=admin_user_registration_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/user-login',
    view_func=login_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/dashboard-user-login',
    view_func=panel_user_login_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/logout-user',
    view_func=logout_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/logout-dashboard-user',
    view_func=logout_panel_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/authenticate-user',
    view_func=authentication_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/authenticate-dashboard-user',
    view_func=authentication_dashboard_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/refresh-token',
    view_func=refreshtoken_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/get-company-list',
    view_func=get_company_list_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/get-company-users/<int:company_id>',
    view_func=get_company_users_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/api/v1/field-force/auth/get-company-contacts',
    view_func=get_company_contact_view,
    methods=['GET']
)
