import webapp2
from google.appengine.ext import db
#import webapp2_extras.appengine.auth.models as auth_models
#from google.appengine.ext import db



############################
#Database to store user data
############################

# The Messaging_System class uses a database to send, store, and 
# receive messages between parties.
class Messaging_System(db.Model):
	sender = db.StringProperty(required = True)
	recipient = db.StringProperty(required = True)
	subject = db.StringProperty(required = True)
	message = db.StringProperty(required = False)
	read = db.BooleanProperty(required = False)
	timestamp = db.DateTimeProperty(auto_now = True)

	# Creates a new message of the given values and then stores
	# it in the database.
	@classmethod
	def send_message(cls, send, rec, sub, mes):
		new_message = Messaging_System(sender = send,
								recipient = rec,
								subject = sub,
								message = mes,
								read = False)
		new_message.put()

	# Returns all messages associated with a given recipient.
	@classmethod
	def get_messages(cls, name):
		messages = Messaging_System.all().filter('recipient =', name).get()
		return messages