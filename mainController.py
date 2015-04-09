import webapp2
import jinja2
import os
import os.path
import random
import string
import re

#from google.appengine.ext import db
from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError
from google.appengine.ext import ndb

############################
#Setup for auth and sessions
############################
config = {}
config['webapp2_extras.sessions'] = {
	'secret_key': 'scrum-bags',
}

# config['webapp2_extras.auth'] = {
# 	'user_model': User_Data,
# }


def login_required(handler):
#		def check_login(self, *args, **kwargs):
#			auth = self.auth
#			if not auth.get_user_by_session():
#				try:
#					self.redirect("/login")
#				except(AttribueError, KeyError), e:
#					self.abort(403)
#			else:
#				return handler(self, * args, **kwargs)
#		return check_login
	def check_login(self, *args, **kwargs):
		if not self.user:
			return self.redirect("/login")
		else:
			return handler(self, *args, **kwargs)
	return check_login

########################################
#Path stuff for finding jinja2 templates
########################################
view_dir = os.path.join(os.path.dirname(__file__), 'views')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(view_dir), autoescape=True)


##################################
#Regex for signup input validation
##################################
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_pword(password):
    return PWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

def same_pass(password, verify):
    if password == verify:
        return True 
    else:
        return False

#########
#Handlers
#########

class Handler(webapp2.RequestHandler):
	def write(self, *args, **kwargs):
		self.response.out.write(*args, **kwargs)


	def render_str(self, template, **params):
		temp = jinja_env.get_template(template)
		return temp.render(params)

	def render(self, template, **kwargs):
		self.write(self.render_str(template, **kwargs))


	@webapp2.cached_property
	def session_store(self):
		return sessions.get_store(request=self.request)


	@webapp2.cached_property
	def session(self):
		return self.session_store.get_session()


	def dispatch(self):
		try:
			super(Handler, self).dispatch()
		finally:
			self.session_store.save_sessions(self.response)


	@webapp2.cached_property
	def auth(self):
		return auth.get_auth()


	@webapp2.cached_property
	def user(self):
		user = self.auth.get_user_by_session()
		return user


	@webapp2.cached_property
	def user_model(self):
		user_model, timestamp = self.auth.store.user_model.get_by_auth_token(
			self.user['user_id'],
			self.user['token']) if self.user else (None, None)
		return user_model



class MainPage(Handler):
	def get(self):
		self.render('front.html')	






class Login(Handler):
	def get(self):
		self.render('login.html')	

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')


		try:
			self.auth.get_user_by_password(username, password)
			return self.redirect("/welcome")
		except(auth.InvalidAuthIdError, auth.InvalidPasswordError):
			error = 'Invalid Login'
		self.render('login.html',error=error)
		# u = users.User_Data.login(username, password)
		# if u:
		# 	self.redirect("/welcome")
		# else:
		# 	error = 'Invalid login'
		# 	self.render('login.html', error=error)



class Logout(Handler):
	@login_required
	def get(self):
		self.auth.unset_session()
		self.redirect("/login")







class Signup(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False

		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username, email = self.email)

		if not valid_username(self.username):
			params['error_username']='not a valid username'
			have_error=True
		if not valid_pword(self.password):
			params['error_password']='not a valid password'
			have_error= True
		elif self.password!=self.verify:
			params['error_verify']='your passwords do not match'
			have_error=True
		if self.email !='' and not valid_email(self.email):
			params['error_email']='your email is not valid'
			have_error=True

		if have_error:
			print params
			self.render("signup.html", **params)	
		else:
			vals = {}
			vals['email'] = self.email
			vals['role'] = 1
			vals['username'] = self.username
			#u = users.User_Data.all().filter("user_name = ", self.username).get()
			success, info = self.auth.store.user_model.create_user(self.username, 
				password_raw=self.password, **vals)

			if not success:
				params['error_username']='that user already exists'
				self.render("signup.html", **params)
			else:
				self.auth.set_session(self.auth.store.user_to_dict(info), remember=True)	
#				m = self.user_model
#				m.email = self.email
#				m.role = 0
				self.redirect("/welcome")


			#	new_user = users.User_Data.register(self.username, self.password, self.email)
			#	new_user.put()
			#	self.redirect("/welcome")


class WelcomeHandler(Handler):
	@login_required
	def get(self):
		self.response.out.write("Welcome, " +  str(self.user_model.username))

class AdminHandler(Handler):
	@login_required
	def get(self):
		is_Admin = False

		is_Admin = (self.user_model.role == 0)

		if is_Admin:
			self.redirect("/admin")
		else:
			self.redirect("/welcome")


app = webapp2.WSGIApplication([('/', MainPage),
							 ('/admin', AdminHandler),
							 ('/welcome', WelcomeHandler),
							 ('/signup', Signup),
							 ('/login', Login),
							 ('/logout', Logout),
							 ], debug=True, config=config)