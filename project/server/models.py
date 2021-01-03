from datetime import datetime
from datetime import timedelta
from project.server import app, db, bcrypt
import jwt


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    registered_on = db.Column(db.DateTime, nullable=True)
    first_name = db.Column(db.String(255), unique=False, nullable=True)
    last_name = db.Column(db.String(255), unique=False, nullable=True)
    phone_number = db.Column(db.String(20), unique=False, nullable=False)
    nid = db.Column(db.String(255), nullable=True)
    profile_photo = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    designation = db.Column(db.String(255), nullable=True)
    department = db.Column(db.String(255), nullable=True)
    member_type = db.Column(db.Integer, nullable=False)
    company_id = db.Column(db.Integer, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, company_id, phone_number, first_name='', last_name='', nid='', designation='', department='', profile_photo='', member_type=''):
        self.company_id = company_id
        self.first_name = first_name
        self.last_name = last_name
        self.phone_number = phone_number
        self.nid = nid
        self.designation = designation
        self.department = department
        self.profile_photo = profile_photo
        self.registered_on = datetime.utcnow()
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()
        self.member_type = member_type

    def encode_auth_token(self, user_id, modules):
        user_details = User.query.filter_by(id=user_id).first()
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=7),
                'iat': datetime.utcnow(),
                'sub': user_id,
                'modules': modules,
                'user_type': 'General',
                'name': user_details.first_name + ' ' + user_details.last_name,
                'phone_number': user_details.phone_number,
                'member_type': user_details.member_type
            }
            token = jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
            return token
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class DashboardUser(db.Model):
    __tablename__ = "dashboard_users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(255), unique=False, nullable=False)
    last_name = db.Column(db.String(255), unique=False, nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=True)
    designation = db.Column(db.String(255), nullable=True)
    department = db.Column(db.String(255), nullable=True)
    nid = db.Column(db.String(255), nullable=True)
    profile_photo = db.Column(db.String(255), nullable=True)
    company_id = db.Column(db.String(255), nullable=False)
    member_type = db.Column(db.Integer, nullable=False)

    def __init__(self, email, password, username, first_name, last_name, company_id, phone_number='', nid='', profile_photo='', member_type=''):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.now()
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.company_id = company_id
        self.phone_number = phone_number
        self.nid = nid
        self.profile_photo = profile_photo
        self.member_type = member_type

    def encode_auth_token(self, user_id):
        user_details = DashboardUser.query.filter_by(id=user_id).first()
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=0, seconds=3600),
                'iat': datetime.utcnow(),
                'sub': user_id,
                'user_type': 'Dashboard',
                'name': user_details.first_name + ' ' + user_details.last_name,
                'email': user_details.email,
                'member_type': user_details.member_type,
                'company_id': user_details.company_id,
                'designation': user_details.designation,
                'department': user_details.department
            }
            token = jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
            return token
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class Companies(db.Model):
    __tablename__ = "companies"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    address = db.Column(db.String(255), nullable=False)
    agreement_file = db.Column(db.String(255), nullable=True)
    verification_file = db.Column(db.String(255), nullable=True)
    tin = db.Column(db.String(255), unique=False, nullable=False)

    def __init__(self, name, address, tin, agreement_file='', verification_file=''):
        self.name = name
        self.address = address
        self.agreement_file = agreement_file
        self.verification_file = verification_file
        self.tin = tin


class CompanyPanel(db.Model):
    __tablename__ = "company_dashboard_users"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    dashboard_user_id = db.Column(db.Integer(), nullable=False)
    company_id = db.Column(db.Integer(), nullable=False)

    def __init__(self, dashboard_user_id, company_id):
        self.dashboard_user_id = dashboard_user_id
        self.company_id = company_id


class CompanyUsers(db.Model):
    __tablename__ = "company_general_users"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    company_id = db.Column(db.Integer(), nullable=False)
    user_id = db.Column(db.Integer(), nullable=False)

    def __init__(self, company_id, user_id):
        self.company_id = company_id
        self.user_id = user_id


class Module(db.Model):
    __tablename__ = 'modules'
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=False)

    def __init__(self, name):
        self.name = name


class UserModule(db.Model):
    __tablename__ = 'user_modules'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    module_id = db.Column(db.Integer(), db.ForeignKey('modules.id', ondelete='CASCADE'))


class BlacklistToken(db.Model):
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False


class Albums(db.Model):
    __tablename__ = "albums"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    field_attendence_id = db.Column(db.Integer(), nullable=False)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, field_attendence_id=''):
        self.field_attendence_id = field_attendence_id
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()


class TaskAlbums(db.Model):
    __tablename__ = "task_albums"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer(), nullable=False)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, task_id=''):
        self.task_id = task_id
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()


class FieldAttendance(db.Model):
    __tablename__ = "field_attendence"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    assigned_time = db.Column(db.String(255), nullable=False)
    assigned_location_lattitude = db.Column(db.String(255), nullable=False)
    assigned_location_longitude = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    admin_id = db.Column(db.Integer(), nullable=False)
    attendence_time = db.Column(db.String(255), nullable=True)
    attendence_location_lattitude = db.Column(db.String(255), nullable=True)
    attendence_location_longitude = db.Column(db.String(255), nullable=True)
    attendence_status = db.Column(db.Boolean(), nullable=True)
    comment = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer(), nullable=True)
    album_id = db.Column(db.Integer(), nullable=True)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, title, assigned_time, assigned_location_lattitude, assigned_location_longitude, address, admin_id):
        self.title = title
        self.assigned_time = assigned_time
        self.assigned_location_lattitude = assigned_location_lattitude
        self.assigned_location_longitude = assigned_location_longitude
        self.address = address
        self.admin_id = admin_id
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()


class Photos(db.Model):
    __tablename__ = "photos"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    album_id = db.Column(db.Integer(), nullable=False)
    photo_url = db.Column(db.String(255), nullable=False)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, album_id='', photo_url=''):
        self.album_id = album_id
        self.photo_url = photo_url
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()


class TaskPhotos(db.Model):
    __tablename__ = "task_photos"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    album_id = db.Column(db.Integer(), nullable=False)
    photo_url = db.Column(db.String(255), nullable=False)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, album_id='', photo_url=''):
        self.album_id = album_id
        self.photo_url = photo_url
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()


class Services(db.Model):
    __tablename__ = "services"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    service_type = db.Column(db.String(255), nullable=True)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, name='', service_type=''):
        self.name = name
        self.service_type = service_type
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()


class CompanyServices(db.Model):
    __tablename__ = "company_services"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    company_id = db.Column(db.Integer(), nullable=False)
    service_id = db.Column(db.Integer(), nullable=False)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, company_id='', service_id=''):
        self.company_id = company_id
        self.service_id = service_id
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()


class TaskService(db.Model):
    __tablename__ = "task_service"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    is_paid = db.Column(db.Boolean(), nullable=False)
    payment_status = db.Column(db.Boolean(), nullable=False)
    assigned_time = db.Column(db.String(255), nullable=False)
    assigned_location_lattitude = db.Column(db.String(255), nullable=False)
    assigned_location_longitude = db.Column(db.String(255), nullable=False)
    assigned_address = db.Column(db.String(255), nullable=False)
    admin_id = db.Column(db.Integer(), nullable=False)
    user_id = db.Column(db.Integer(), nullable=False)
    task_complete_time = db.Column(db.String(255), nullable=True)
    task_complete_location_lattitude = db.Column(db.String(255), nullable=True)
    task_complete_location_longitude = db.Column(db.String(255), nullable=True)
    task_complete_status = db.Column(db.Boolean(), nullable=True)
    bill_amount = db.Column(db.Float(), nullable=True)
    billing_address = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.String(255), nullable=True)
    album_id = db.Column(db.Integer(), nullable=True)
    createdAt = db.Column(db.DateTime, nullable=False)
    updatedAt = db.Column(db.DateTime, nullable=False)

    def __init__(self, title, is_paid, assigned_time, assigned_location_lattitude, assigned_location_longitude, assigned_address, admin_id, user_id, payment_status=False):
        self.title = title
        self.is_paid = is_paid
        self.assigned_time = assigned_time
        self.assigned_location_lattitude = assigned_location_lattitude
        self.assigned_location_longitude = assigned_location_longitude
        self.assigned_address = assigned_address
        self.admin_id = admin_id
        self.user_id = user_id
        self.payment_status = payment_status
        self.createdAt = datetime.utcnow()
        self.updatedAt = datetime.utcnow()
