import sqlalchemy.exc
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '8BYkEfBA6O6donzWlSihBXox7C0sKR6b')
ckeditor = CKEditor(app)
Bootstrap(app)

##Connect to loginManager
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##INITIALISE Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blogPost"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), unique=True, nullable=False)

    author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blogPost.id"))


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##admin_only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous:
            return abort(403)
        elif current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            flash("You've already signed up with that email. Login instead!")
            return redirect('/login')
        else:
            login_user(new_user)
            return redirect('/')
    return render_template("register.html", form=form)


@app.route('/login',  methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        logged_in_password = form.password.data
        data = User.query.filter_by(email=form.email.data).first()
        try:
            registered_password = data.password
        except AttributeError:
            flash("The email does not exist. Please register")
            return redirect('/register')
        else:
            if check_password_hash(registered_password, logged_in_password):
                login_user(data)
                return redirect('/')
            else:
                flash("Incorrect Password please try again.")
                form.email = form.email.data
                return redirect('/login')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment = CommentForm()
    if comment.validate_on_submit():
        try:
            data = Comment(
                text=comment.body.data,
                author=current_user,
                post=requested_post
            )
            db.session.add(data)
            db.session.commit()
        except AttributeError:
            flash("Please login to comment.")
            return redirect("/login")
        else:
            return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment, comments=requested_post.comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author=current_user
        )
        db.create_all()
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
