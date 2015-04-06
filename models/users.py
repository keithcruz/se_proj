import webapp2

from google.appengine.ext import db



############################
#Database to store user data
############################

#def users_key(group = 'default'):
#	return db.Key.from_path('users', group)
class User_Data(db.Model):
	user_name = db.StringProperty(required=True)
	pass_word = db.StringProperty(required=True)
	email = db.StringProperty(required=False)
	role = db.IntegerProperty(required=False)

#	@classmethod
#	def by_id(cls, uid):
#		return User_Data.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User_Data.all().filter('user_name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
	
		return User_Data(parent = users_key(), 
						user_name = name, 
						pass_word = pw, 
						email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and u.pass_word == pw:
			return u