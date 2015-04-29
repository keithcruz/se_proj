import webapp2
from google.appengine.ext import db



############################
#Database to store user data
############################

class Medical_Data(db.Model):
    user_name = db.StringProperty(required=True)
    height = db.StringProperty(required=False)
    weight = db.StringProperty(required=False)
    blood_pressure = db.StringProperty(required=False)
    diagnosis = db.TextProperty(required=False)
    notes = db.TextProperty(required=False)

    @classmethod
    def by_name(cls, name):
        u = User_Data.all().filter('user_name =', name).get()
        return u
