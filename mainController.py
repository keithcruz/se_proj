import webapp2
import jinja2
import os
import os.path
import random
import string
import re

from google.appengine.ext import db
from models import users

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




class MainPage(Handler):
	def get(self):
		self.render('front.html')	






class Login(Handler):
	def get(self):
		self.render('login.html')	

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User_Data.login(username, password)
		if u:
			self.redirect("/welcome")
		else:
			error = 'Invalid login'
			self.render('login.html', error=error)







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
			u = User_Data.all().filter("user_name = ", self.username).get()


			if u:
				params['error_username']='that user already exists'
				self.render("signup.html", **params)
			else:
				new_user = User_Data.register(self.username, self.password, self.email)
				new_user.put()
				self.redirect("/welcome")


class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		self.response.out.write("Welcome, you successfully created an account")


app = webapp2.WSGIApplication([('/', MainPage),
							 ('/welcome', WelcomeHandler),
							 ('/signup', Signup),
							 ('/login', Login),
							 ], debug=True)