import os
import re
import hashlib
import hmac
import random
import string
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
SECRET = 'asdlfkjSDdsfaFdfsdfDFSkljq'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

def user_key(name = 'default'):
    return db.Key.from_path('users', name)

class UserInfo(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email_address = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


#User Accounts
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    #return '%s,%s' % (h, salt)
    return '%s' % (h)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)
##End User Accounts

#Cookie

def hash_str(s):
   #return hashlib.md5(s).hexdigest()
   return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s,hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

#End Cookie

class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            #hash user name with secret and salt
            salt = make_salt()
            user_hash = make_pw_hash(username, password, salt)

            #add user to db
            if username and user_hash:
                u = UserInfo(parent = user_key(), username = username, password = user_hash, emal_address = email)
                u.put()
            #set cookie
            self.response.headers['Content-Type'] = 'text/plain'

            user_cookie_str = self.request.cookies.get('user')
            if user_cookie_str:
                cookie_val = check_secure_val(user_cookie_str)
                if cookie_val:
                    user = cookie_val
            new_cookie_val = make_secure_val(username)

            self.response.headers.add_header('Set-Cookie', 'user=%s' % str(new_cookie_val))

            self.redirect("/welcome")

class Welcome(BlogHandler):
    def get(self):
        #check if valid cookie. If not redirect to signup
        user_cookie_str = self.request.cookies.get('user')
        if user_cookie_str:
            cookie_val = check_secure_val(user_cookie_str)
            if cookie_val:
                user = cookie_val
                username = user.split('|')[0]
                self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')


class UserList(BlogHandler):
    def get(self):
        users = db.GqlQuery("select * from UserInfo order by created desc")
        self.render('userlist.html', users = users)

app = webapp2.WSGIApplication([('/blog/signup', Signup),
                               ('/blog/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/userlist', UserList)
                               ],
                              debug=True)
