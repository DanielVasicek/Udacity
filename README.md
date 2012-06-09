#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Udacity Final Exam "wiki"
import re, os
import cgi
import webapp2
import random
import string
import datetime
import hashlib, hmac
from google.appengine.ext import db
secret = 'MTzgl2cRLFchZ2bhqGCZFovuWPBCUcfQEiLtl8eh'

USER_RE  = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE   = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
	
form1 ="""<html><head> <title>Vasicek Wiki</title></head></head><body>"""
form2="""<form method = "post">><textarea name ="content" >"""

form6="""</textarea> <br> </form></body></html>"""
form6a="""</body></html>"""
form5 = """</textarea> <br><input type="submit"> </form></body></html>"""
form="""
<form method = "post">
   <b> Please input your desired username, password, and email address.</b>  
   The username must be 3-20 alphanumeric characters and may include -_.  The password can be 3-20 of any characters and the verification password must match the original password. <br>
   <table>
   <tr>
   <td>Username</td>
   <td><input type="text" name ="username" value ="%(username)s"> </td>
   <td>%(username_error)s</td></tr>
   <tr>
   <td>Password</td>
   <td><input type="password" name ="password"   value ="%(password)s"> </td>
   <td>%(password_error)s</td></tr>
   <tr>
   <td>Verification Password</td>
   <td><input type="password" name ="verify"     value ="%(verify)s"></td>
   <td>%(verify_error)s</td></tr>
   <tr>
   <td>Email Address</td>
   <td><input type="text" name ="email" value ="%(email)s"></td>
   <td>%(email_error)s</td></tr></table>
 
    <br><br> <input type="submit">
</form>
"""
wid=''
web_pre=''
old_content=''
lform="""
<form method = "post">
   <b> Please input your username, and password</b> 
   <table>
   <tr>
   <td>Username</td>
   <td><input type="text" name ="username" value ="%(username)s"> </td></tr>
   <tr>
   <td>Password</td>
   <td><input type="password" name ="password"   value ="%(password)s"> </td>
   </tr>
   </table>
   <br> %(error)s
 
    <br><br> <input type="submit"></form>
    """

def datetime2str(dt):
	year   =str(getattr(dt,'year'))
	month  =str(getattr(dt,'month'))
	day    =str(getattr(dt,'day'))
	hour   =str(getattr(dt,'hour'))
	minute =str(getattr(dt,'minute'))
	second =str(getattr(dt,'second'))
	ms     =str(getattr(dt,'microsecond'))
	return year+':'+month+':'+day+':'+hour+':'+minute+':'+second+':'+ ms
def str2datetime(dt):
	s=dt.split(':')
	return datetime.datetime(int(s[0]),int(s[1]),int(s[2]),int(s[3]),int(s[4]),int(s[5]),int(s[6]))

			
def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
def check_secure_val(secure_val):
	# check that the hash val and val are consistent
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def escape_html(s):
	return cgi.escape(s, quote = True)

def valid_username(username):
	if USER_RE.match(username):
		return username
	else:
		return ""
    
def valid_password(password):
	if PWD_RE.match(password):
		return password
	else:
		return ""
	  
def valid_email(email):
	if EMAIL_RE.match(email):
                return str(email)

def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in range(length))

def make_pw_hash(name, pw, salt = None ):
	if not salt:
		salt = make_salt()
        h = hashlib.sha256(str(name) + pw + salt).hexdigest()
    	return '%s|%s' % (h, salt)

def valid_pw(name, pw, hh):
    [h,salt]=hh.split('|')
    return h == make_pw_hash(name, pw, salt)

def users_key(group= 'default'):
    return db.Key.from_path('users', group)

def count_db_results(d):
    l=0
    for b in d:
    	l+=1
    return l

def set_secure_cookie( self, name, val): 
    cookie_val = make_secure_val(val)
    self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

def read_secure_cookie(self,  name):
	cookie_val = self.request.cookies.get(name)
	return cookie_val and check_secure_val(cookie_val)

def login(self, user):
	self.set_secure_cookie('username', str(user.key().id()))

def logout(self):
	self.response.headers.add_header('Set-Cookie', 'username=; Path=/')

def initialize(self, *a, **kw):
	webapp2.RequestHandler.initialize(self, *a, **kw)
	uid = self.read_secure_cookie('username')
	self.user = uid and User.by_id(int(uid))

class Pages(db.Model):
	loc     =db.StringProperty  (required     = True)
	content =db.TextProperty    (required     = True)
	user    =db.StringProperty  (required     = True)
	created =db.DateTimeProperty(auto_now_add = True)
	modified=db.DateTimeProperty(auto_now     = True)

    
class User(db.Model):
	username=db.StringProperty (required=True)
	password=db.StringProperty (required=True)
	created =db.DateTimeProperty(auto_now_add = True)
	# email   =db.EmailProperty()
	email   =db.StringProperty()

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
				name    = name,
				pw_hash = pw_hash,
				email   = email)


	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

class Signup(webapp2.RequestHandler):
    def set_secure_cookie( self, name, val): 
   	 cookie_val = str(make_secure_val(val))
    	 self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' %(name, cookie_val))

    def read_secure_cookie(self,  name):
	cookie_val = self.request.cookies.get(name)
	return cookie_val and check_secure_val(cookie_val)
    userid=''
    useridc=''
    id=0
    def write_form(self,username="", username_error="", password="",password_error="", verify  ="", verify_error  ="", email   ="",email_error   ="" ):
	# self.response.headers['Content-Type'] = 'text/plain'   
    	self.response.out.write(form % { "username"       : escape_html(username), 
		                         "username_error" : username_error,         
				         "password"       : escape_html(password),  
					 "password_error" : password_error,          
				         "verify"         : escape_html(verify),
					 "verify_error"   : verify_error, 
	                                 "email"          : escape_html(email),
					 "email_error"    : email_error})


    def get(self):
		self.write_form(username="", username_error="", password='', password_error="", verify='', verify_error='', email='', email_error='')

    def post(self):	    
	user_username   = escape_html(self.request.get('username'))
        user_password   = escape_html(self.request.get('password'))
	user_verify     = escape_html(self.request.get('verify'  ))
	user_email      = escape_html(self.request.get('email'   ))
	username        = str(valid_username(user_username))
        password        = str(valid_password(user_password))
	verify          = str(valid_password(user_verify))
	email           = str(valid_email(user_email))
	# self.response.headers['Content-Type'] = 'text/plain'
	# usernamehash =self.request.cookies.get('usernamehash','')
	# usernamec    =self.request.cookies.get('username','')
	anerror=False
	username_error=''
	password_error=''
	verify_error=''
	email_error=''
	if (username == '' ):
		username_error='Please select a valid username.'
		anerror = True
	if not (anerror):
		uids=db.GqlQuery("select * from User where username = '%s' " % username)
		if count_db_results(uids) >0 :
			username_error='That username is already taken!'
			anerror =True
		else:
			if not(valid_username(username)):
				username_error='Please select a valid username.'
				anerror=True

	if (password == '' ):
		password_error='Please select a valid password.'
		anerror = True
	if not(password == verify):
		verify_error='The verification password must match the password.'
		password=''
		verify=''
		anerror = True
	if not(user_email =='') and not(email == user_email):
		email_error='Please select a valid email address.'
		anerror=True
	if anerror:
		self.write_form(user_username, username_error,
				user_password, password_error, 
				user_verify,   verify_error,
				user_email,    email_error)
	else:
		
		a=User(username=username, password=password, email=email)
		a.put()
		id=a.key().id()

		set_secure_cookie(self, 'user_id',str(id))
		set_secure_cookie(self, 'username',str(username))

		self.redirect(web_pre+wid)


class Logout(Signup):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
		self.redirect(web_pre+wid)

class Login(Signup):
	def get(self):
		blank =''
		self.response.out.write(lform % { "username"       : blank,
						  "password"       : blank,
				                  "error"          : blank})

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
                #  u = User.login(username, password)
		users = db.GqlQuery("Select * from User")
		l=0
		u=None
		found=False
		for b in users:
			l=l+1
			u=b
			if str(b.username) == str(username) and str(b.password) == str(password):
				u=b
				found=True
				break


		if  found :
			set_secure_cookie(self, 'username',str(username))
			self.redirect(web_pre+wid)
		else:
			msg="Invalid Login  username =" + username + " password = " + password + "  up=" + str(l)
			username=""
			password =""
			self.response.out.write(lform % { "username"       : escape_html(username),
							  "password"       : escape_html(password),
				                          "error"          : msg})
class Inventory(Signup):
	def get(self):
		t1="""<form method = "post">
   <b>Table of usernames and passwords</b> 
   <table>
		"""

		users = db.GqlQuery("Select * from User order by created desc")
		t2='<tr> <td>Username</td> <td>Password</td></tr>'
		for u in users:
			t2 = t2+ '<tr><td> ' + str(u.username)+ '</td><td>' +  str(u.password) + '</td></tr>'

		self.response.out.write(t1+t2 + '</table> </form>' )

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
                #  u = User.login(username, password)
		users = db.GqlQuery("Select * from User")
		l=0
		for b in users:
			l=l+1
			u=b
			if str(b.username) == str(username) and str(b.password) == str(password):
				u=b
				break

class Blogsummary(Signup):
	def get(self):
		posts = db.GqlQuery("Select * from Blogs order by created desc limit 10")
		t1= """<form method = "post"> <b>Table of 10 most recent Subjects and Blogs</b><br>"""
		body=''
		for p in posts:
			body = body+ 'Subject: <br>' + p.subject +'<br> Content:<br> ' + p.content + '<br> ---'+str(p.modified) +'---------------- <br>'
		self.response.out.write(t1+body + '''<br><a href='/blogs/newpost'>Add a new blog</a> </form>''' )


class WikiPage(webapp2.RequestHandler):
	# to generate wiki pages. DJV  Create a bootstrap:
	def get(self, id):
		global wid, web_pre
		web_pre=''
		wid=str(id)
		m=None
		m1=self.request.get('m')
		m=m1.split(':')
		username1     = self.request.cookies.get('username','')
		username      = read_secure_cookie(self,  'username')
		if username:
			thtml="""<a href='_edit""" + wid + """'> edit</a> |  <a href='_history""" + wid + """'> history</a> """ + username + """          | <a href='/logout'> logout</a>"""
		else:
			thtml="""                                            <a href='_history""" + wid + """'> history</a>  <a href='/login'> login</a>| <a href='/signup'> signup</a>"""
		if len(m) >4 :
			po = db.GqlQuery("""Select * from Pages where loc ='""" + wid+ """'order by modified desc """)
			pp=None
			for p in po:
				x=datetime2str(p.modified).split(':')
				deltat=0
				for i in range(6):
					deltat=deltat+abs(int(m[i])-int(x[i]))
				if deltat==0:
					pp=p						
					break
		else:
			post = db.GqlQuery("""Select * from Pages where loc ='""" + wid+ """'   order by modified desc limit 2""")
			pp=None
			for p in post:
				pp=p
				break

		
		if pp:
			#self.response.out.write(form1 + thtml + form2+pp.content + form6)
			self.response.out.write(form1+thtml+'<br>'+ pp.content +form6a)
		else:
			if username:
				web_pre='/_edit'
				self.redirect('/_edit'+wid)
			else:
				self.response.out.write("""There is no such page and you must be logged in to create a page.  <a href='/login'> login</a>| <a href='/signup'> signup</a>""")


class IPages(WikiPage):
	def get(self):
		pages=db.GqlQuery("""Select * from Pages order by modified desc""")
		d='<html><body><h1>Inventory Pages</h1><br> ----- Date Modified -------------- Location  ----- content ------ username <br>'
		for p in pages:
			d=d+str(p.modified) + """ ---- <a href='""" + str(p.loc)+ """'> """ + str(p.loc) + '</a> --- '+ str(p.content) + ' ---- ' +  str(p.user) +' <br>'
		d=d+'</body></html>'

		self.response.out.write(d)

class IUsers(Signup):
	def get(self):
		self.response.out.write('Inventory Users')

class EditPage(WikiPage):
	def get(self, id):
		global web_pre, wid, old_content
		username      = read_secure_cookie(self,  'username')
		if username:
			web_pre='/_edit'
			wid=str(id)
			m1=self.request.get('m')
			m=m1.split(':')
			
	

			thtml= username + """          | <a href='/logout'> logout</a>"""
			pp=None
			if len(m)>4:
				po = db.GqlQuery("""Select * from Pages where loc ='""" + wid+ """'order by modified desc """)
				for p in po:
					x=datetime2str(p.modified).split(':')
					deltat=0
					for i in range(6):
						deltat=deltat+abs(int(m[i])-int(x[i]))
					if deltat==0:
						pp=p						
						break
				
			else:
				po = db.GqlQuery("""Select * from Pages where loc ='""" + wid+ """'order by modified desc limit 2 """)
				for p in po:
					pp=p
					break
				
				
			if pp:
				self.response.out.write(form1 + thtml + form2+escape_html(pp.content) + form5)
				old_content=pp.content
			else:
				self.response.out.write(form1 + thtml + form2 + form5)
	
		else:
			self.redirect('/login')
	
	def post(self,id):
		content=self.request.get("content")
		username = read_secure_cookie(self,  'username')
		if username=='':
			self.error(400)
			return
		if content=='' or (content== old_content):
			return


		a=Pages(loc=str(wid), content= content, user=username)
		a.put()
		self.redirect(wid)


		
class HistoryPage(WikiPage):
	def get(self,id):
		global web_pre, wid
		web_pre='/_history'
		wid=str(id)
		username      = read_secure_cookie(self,  'username')
		if username:
			thtml="""<a href='/_edit""" + wid + """'> edit most recent</a> |  <a href='""" + wid + """'> view most recent | </a> """ + username + """  | <a href='/logout'> logout</a>"""
		else:
			thtml="""<a href='/"""      + wid + """'> view most recent</a> | <a href='/login'> login</a> | <a href='/signup'> signup</a>"""
		po = db.GqlQuery("""Select * from Pages where loc ='""" + wid+ """'   order by modified desc""")
		l=0
		d='<html><title>History Wiki</title><body>' + thtml + '<br> <table>'
		for p in po:
			l=l+1
			s3=datetime2str(p.modified)
			s=escape_html(p.content)
			ss=s
			if len(s)>50:
				ss=s[0:49]


			d=d+"<tr><td>"+ s3+'</td><td>' + ss+ """</td> <td><a href='""" + wid+"""?m="""+s3+"""' >view</a> </td><td> <a href='/_edit""" + wid + """?m=""" +s3 + """'> edit</a></td></tr>"""


		self.response.out.write( d +"</table></body></html>")







PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
			       ('/inventory', Inventory),
			       ('/inventory_pages',IPages),
			       ('/inventory_users',IUsers),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, WikiPage)
                               ], debug=True)
