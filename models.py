from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from datetime import datetime

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()

# User Model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # e.g., 'user', 'tech_writer', 'admin'
    is_active = db.Column(db.Boolean, default=True)
    profile_picture = db.Column(db.String(255), default="default.jpg")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)  # Track last login
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Track updates
    profile_complete = db.Column(db.Boolean, default=False)  # Optional: Track if the user has completed their profile

    # Relationships
    subscribed_categories = db.relationship('Category', secondary='user_category')
    wishlist = db.relationship('Content', secondary='user_wishlist')
    content = db.relationship('Content', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)

    def __init__(self, username, email, password_hash, user_type):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.user_type = user_type

    def __repr__(self):
        return f"<User {self.username}>"

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')


class TechWriterProfile(db.Model):
    __tablename__ = 'tech_writer_profiles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bio = db.Column(db.String(500))
    expertise = db.Column(db.String(100))
    published_articles_count = db.Column(db.Integer, default=0)  # Track the number of published articles

    user = db.relationship('User', backref=db.backref('tech_writer_profile', uselist=False))

    def __repr__(self):
        return f"<TechWriterProfile {self.user.username}>"

class Badge(db.Model):
    __tablename__ = 'badges'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    icon_url = db.Column(db.String(500), nullable=True)
    earned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Badge {self.name}>"

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "icon_url": self.icon_url,
            "earned_at": self.earned_at.isoformat()
        }


class Content(db.Model):
    __tablename__ = 'content'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)  # SEO-friendly URL
    content = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    media_url = db.Column(db.String(500))
    tags = db.Column(db.String(500))
    approved = db.Column(db.Boolean, default=False)
    flagged = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Track updates
    draft = db.Column(db.Boolean, default=True)  # Flag for draft content
    views_count = db.Column(db.Integer, default=0)  # Track number of views

    # Relationships
    user = db.relationship('User', backref=db.backref('content', lazy=True))
    category = db.relationship('Category', backref=db.backref('content', lazy=True))
    reviews = db.relationship('ContentReview', backref='content', lazy=True)

    def __repr__(self):
        return f"<Content {self.title} - User {self.user.username}>"

    # Search function (using SQLAlchemy)
    @staticmethod
    def search(query):
        return Content.query.filter(Content.title.ilike(f"%{query}%")).all()


class ContentReview(db.Model):
    __tablename__ = 'content_reviews'

    id = db.Column(db.Integer, primary_key=True)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=True)  # Star rating or other numerical rating
    review_type = db.Column(db.String(20), nullable=False)  # e.g., 'like', 'dislike', 'star'
    comment = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    content = db.relationship('Content', backref=db.backref('reviews', lazy=True))
    user = db.relationship('User', backref=db.backref('reviews', lazy=True))

    def __repr__(self):
        return f"<ContentReview {self.review_type} - Content {self.content_id}>"


class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(500), nullable=True)  # Optional: Add a description for the category

    def __repr__(self):
        return f"<Category {self.name}>"

class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    comment_text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Track updates
    likes_count = db.Column(db.Integer, default=0)  # Track likes for comment

    # Relationships
    replies = db.relationship('Reply', backref='comment', lazy=True)

    def __repr__(self):
        return f"<Comment by {self.user.username}>"

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)
    notification_url = db.Column(db.String(500))  # Link to content or action
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<Notification for {self.user.username}>"

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)  # e.g., 'created_content', 'deleted_user'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AuditLog {self.action} by User {self.user_id}>"

class UserSettings(db.Model):
    __tablename__ = 'user_settings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receive_notifications = db.Column(db.Boolean, default=True)
    receive_email_updates = db.Column(db.Boolean, default=True)
    theme_preference = db.Column(db.String(10), default="light")  # e.g., 'dark' or 'light'

    def __repr__(self):
        return f"<UserSettings for User {self.user_id}>"

class ActivityFeed(db.Model):
    __tablename__ = 'activity_feed'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)  # e.g., 'liked_content', 'commented'
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class ContentRating(db.Model):
    __tablename__ = 'content_ratings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # e.g., 1 to 5 stars

    def __repr__(self):
        return f"<ContentRating {self.rating} for Content {self.content_id}>"

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # e.g., 'login_attempt', 'api_call'
    status = db.Column(db.String(20), nullable=False)  # e.g., 'success', 'failure'
    message = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Log {self.action} - {self.status}>"


class Reply(db.Model):
    __tablename__ = 'replies'

    id = db.Column(db.Integer, primary_key=True)
    reply_text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    likes_count = db.Column(db.Integer, default=0)  # Track the number of likes for each reply

    # Relationships
    user = db.relationship('User', backref=db.backref('replies', lazy=True))
    comment = db.relationship('Comment', backref=db.backref('replies', lazy=True))

    def __repr__(self):
        return f"<Reply by {self.user.username} on Comment {self.comment_id}>"

class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    permissions = db.Column(db.String(500))  # JSON of permissions for each role

    def __repr__(self):
        return f"<Role {self.name}>"

class Tag(db.Model):
    __tablename__ = 'tags'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"<Tag {self.name}>"
    
class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reported_content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=True)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reason = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default='pending')  # e.g., 'pending', 'reviewed', 'resolved'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Report by {self.reporter_id} - Status {self.status}>"

class UserFollow(db.Model):
    __tablename__ = 'user_follows'

    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    followee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<UserFollow {self.follower_id} follows {self.followee_id}>"

class ContentVersion(db.Model):
    __tablename__ = 'content_versions'

    id = db.Column(db.Integer, primary_key=True)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    version_number = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    edited_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ContentVersion {self.version_number} for Content {self.content_id}>"



class Media(db.Model):
    __tablename__ = 'media'

    id = db.Column(db.Integer, primary_key=True)
    media_type = db.Column(db.String(20))  # e.g., 'video', 'audio', 'image'
    url = db.Column(db.String(500))
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'))

    def __repr__(self):
        return f"<Media {self.media_type} - {self.url}>"
    

content_tags = db.Table('content_tags',
    db.Column('content_id', db.Integer, db.ForeignKey('content.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)


user_category = db.Table('user_category',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('categories.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)  # Track when user subscribed to category
)

user_wishlist = db.Table('user_wishlist',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('content_id', db.Integer, db.ForeignKey('content.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)  # Track when content was added to wishlist
)

content_likes = db.Table('content_likes',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('content_id', db.Integer, db.ForeignKey('content.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)  # Timestamp of when the like was added
)

content_dislikes = db.Table('content_dislikes',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('content_id', db.Integer, db.ForeignKey('content.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)  # Timestamp of when the dislike was added
)

user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

