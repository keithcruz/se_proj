import webapp2
from google.appengine.ext import db



############################
#Database to store user data
############################

class Schedule_Data(db.Model):
    user_name = db.StringProperty(required=True)
    date = db.StringProperty(required=True)
    time = db.StringProperty(required=True)
    reason_for_visit = db.TextProperty(required=False)

    @classmethod
    def get_appointments(cls, name):
	    appointments = Schedule_Data.all().filter('user_name =', name).get()
	    return appointments
