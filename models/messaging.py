#import webapp2
#from google.appengine.ext import ndb
#import webapp2_extras.appengine.auth.models as auth_models
#from google.appengine.ext import db



############################
#Database to store user data
############################

# The Messaging_System class uses a database to send, store, and 
# receive messages between parties.
class Messaging_System(nbd.Model):
	sender = ndb.StringProperty(required = True)
	recipient = nbd.StringProperty(required = True)
	subject = nbd.StringProperty(required = True)
	message = nbd.StringProperty(required = False)
	read = nbd.BooleanProperty(required = True)

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