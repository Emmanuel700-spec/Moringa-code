from flask import Blueprint, request, jsonify
from auth.models import ContentReview
from auth.models import db, User, TechWriterProfile, Content, Category, Reply, Comment, AuditLog, UserSettings, ActivityFeed, ContentRating, Log, Reply, Role, Tag, Report, UserFollow, ContentVersion, Badge, Media, content_tags, user_category, user_wishlist, content_likes, content_dislikes, user_roles, Notification, User
from datetime import datetime
from marshmallow import ValidationError
from auth.schemas import UserSchema, ContentSchema
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import SQLAlchemyError
from flask import Flask, jsonify, request, abort
app = Flask(__name__)

auth_bp = Blueprint('auth', __name__)
user_bp = Blueprint('user', __name__)

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()

    # Check if required fields are provided
    if not all(key in data for key in ('username', 'email', 'password', 'user_type')):
        raise BadRequest("Missing required fields.")

    # Hash the password
    password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    try:
        # Create new user
        new_user = User(
            username=data['username'],
            email=data['email'],
            password_hash=password_hash,
            user_type=data['user_type']
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 400
    
@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or user.password_hash != data['password']:  # Password should be hashed and compared
        return jsonify({'message': 'Invalid email or password'}), 401

    # Create JWT token
    token = create_access_token(identity={'id': user.id, 'username': user.username, 'user_type': user.user_type})

    return jsonify({'token': token})

@auth_bp.route('/api/auth/logout', methods=['GET'])
@jwt_required()
def logout():

    # Here, we would typically use a blacklist to invalidate tokens, but Flask-JWT-Extended doesn't support it out of the box.
    return jsonify({'message': 'Logged out successfully'})

@auth_bp.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_user_profile():
    current_user = get_jwt_identity()

    user = User.query.get(current_user['id'])

    if user:
        return jsonify({
            'user': {
                'username': user.username,
                'email': user.email,
                'user_type': user.user_type,
                'profile_picture': user.profile_picture
            }
        })
    return jsonify({'message': 'User not found'}), 404

@auth_bp.route('/api/tech-writer/profile', methods=['POST'])
@jwt_required()
def create_profile():
    current_user = get_jwt_identity()
    data = request.get_json()
    bio = data.get('bio')
    expertise = data.get('expertise')

    if not bio or not expertise:
        return jsonify({"message": "Bio and expertise are required"}), 400

    try:
        existing_profile = TechWriterProfile.query.filter_by(user_id=current_user).first()
        if existing_profile:
            return jsonify({"message": "Profile already exists"}), 400

        profile = TechWriterProfile(user_id=current_user, bio=bio, expertise=expertise)
        db.session.add(profile)
        db.session.commit()
        return jsonify({"message": "Profile created successfully"}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

# Route for Admin and Tech Writer content posting
@auth_bp.route('/api/content', methods=['POST'])
@jwt_required()
def post_content():
    user_identity = get_jwt_identity()
    
    # Ensure user has the appropriate role
    if not user_identity or 'user_type' not in user_identity or user_identity['user_type'] not in ['admin', 'tech_writer']:
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json() or {}
    
    # Validate required fields
    title = data.get('title')
    description = data.get('description')
    if not title or not description:
        return jsonify({"message": "Title and description are required"}), 400

    try:
        # Create new content with default approval status
        new_content = Content(
            title=title,
            description=description,
            user_id=user_identity.get('id'),
            is_approved=False  # Needs admin approval by default
        )
        
        db.session.add(new_content)
        db.session.commit()
        return jsonify({"message": "Content posted successfully"}), 201

    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"message": "An error occurred while posting content"}), 500 


# Route specifically for Tech Writers to post content
@auth_bp.route('/api/tech-writer/content', methods=['POST'])
@jwt_required()
def post_content_tech_writer():
    current_user = get_jwt_identity()

    # Ensure the user is a tech writer
    if current_user.get('user_type') != 'tech_writer':
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json() or {}

    # Extract and validate required fields
    title = data.get('title')
    content = data.get('content')
    category = data.get('category')
    media_url = data.get('media_url')
    tags = data.get('tags')

    # Validate required fields
    if not all([title, content, category, media_url, tags]):
        return jsonify({"message": "All fields are required"}), 400

    # Ensure tags is a list
    if not isinstance(tags, list):
        return jsonify({"message": "Tags should be a list"}), 400

    try:
        # Create a new content object with tags joined as a string
        new_content = Content(
            title=title,
            content=content,
            category=category,
            media_url=media_url,
            tags=','.join(tags),
            user_id=current_user.get('id')  # Ensuring proper user_id assignment
        )
        db.session.add(new_content)
        db.session.commit()
        return jsonify({"message": "Content posted successfully"}), 201
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"message": "An error occurred while posting content"}), 500


def check_if_admin():
    current_user = get_jwt_identity()  # Get the current user's ID from the JWT token
    user = User.query.get(current_user)  # Query the user from the database using the user ID

    if not user:
        return False  # If the user doesn't exist, return False

    return user.role == 'admin'

@auth_bp.route('/api/tech-writer/content/<int:id>/approve', methods=['POST'])
@jwt_required()
def approve_content_tech_writer(id):
    content_item = Content.query.get(id)
    
    if not content_item:
        return jsonify({"message": "Content not found"}), 404

    if not check_if_admin():
        return jsonify({"message": "Only admins can approve content"}), 403

    try:
        content_item.approved = True
        db.session.commit()
        return jsonify({"message": "Content approved for publishing"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500


@auth_bp.route('/api/admin/content/<int:id>/approve', methods=['POST'])
@jwt_required()
def approve_content_admin(id):
    if get_jwt_identity()['user_type'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    
    content = Content.query.get(id)
    if content:
        content.is_approved = True
        db.session.commit()
        return jsonify({"message": "Content approved"}), 200
    return jsonify({"message": "Content not found"}), 404


@auth_bp.route('/api/content/<int:id>/approve', methods=['POST'])
@jwt_required()
def approve_content_writer(id):
    user_identity = get_jwt_identity()
    content = Content.query.get(id)
    
    if not content:
        return jsonify({"message": "Content not found"}), 404
    
    # Allow only Admin or Tech Writers to approve
    if user_identity['user_type'] not in ['admin', 'tech_writer']:
        return jsonify({"message": "Unauthorized"}), 403
    
    content.is_approved = True
    db.session.commit()
    return jsonify({"message": "Content approved"}), 200

@auth_bp.route('/api/content/<int:id>/flag', methods=['POST'])
@jwt_required()
def flag_content(id):
    user_identity = get_jwt_identity()
    content = Content.query.get(id)
    
    if not content:
        return jsonify({"message": "Content not found"}), 404

    # Users and Tech Writers can flag content
    if content.flagged:
        return jsonify({"message": "Content already flagged"}), 400
    
    content.flagged = True
    db.session.commit()
    return jsonify({"message": "Content flagged"}), 200

@auth_bp.route('/api/tech-writer/content/<int:id>/flag', methods=['POST'])
@jwt_required()
def flag_content_tech_writer(id):  # Renamed function
    content_item = Content.query.get(id)
    
    if not content_item:
        return jsonify({"message": "Content not found"}), 404
    
    try:
        content_item.flagged = True
        db.session.commit()
        return jsonify({"message": "Content flagged"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

@auth_bp.route('/api/tech-writer/content/<int:id>/review', methods=['POST'])
@jwt_required()
def review_content(id):
    current_user = get_jwt_identity()
    data = request.get_json()
    rating = data.get('rating')
    comment = data.get('comment')

    if not rating or not comment:
        return jsonify({"message": "Rating and comment are required"}), 400

    content_item = Content.query.get(id)
    
    if not content_item:
        return jsonify({"message": "Content not found"}), 404
    
    try:
        review = ContentReview(content_id=id, user_id=current_user, rating=rating, comment=comment)
        db.session.add(review)
        db.session.commit()
        return jsonify({"message": "Review submitted"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

@auth_bp.route('/api/tech-writer/categories', methods=['GET'])
@jwt_required()
def get_categories():
    categories = ["DevOps", "Fullstack", "Front-End"]
    return jsonify({"categories": categories}), 200

@auth_bp.route('/api/tech-writer/categories', methods=['POST'])
@jwt_required()
def create_category():
    data = request.get_json()
    category_name = data.get('category_name')

    if not category_name:
        return jsonify({"message": "Category name is required"}), 400

    try:
        new_category = Category(name=category_name)
        db.session.add(new_category)
        db.session.commit()
        return jsonify({"message": "Category created successfully"}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500


@auth_bp.route('/api/admin/categories', methods=['POST'])
@jwt_required()
def create_category_admin():  # Renamed function
    if get_jwt_identity()['user_type'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    
    # Check if category already exists
    existing_category = Category.query.filter_by(name=data['name']).first()
    if existing_category:
        return jsonify({"message": "Category already exists"}), 400
    
    category = Category(name=data['name'])
    db.session.add(category)
    db.session.commit()
    return jsonify({"message": "Category created successfully"}), 201

@app.route('/content/<int:content_id>/comment', methods=['POST'])
@jwt_required()
def add_comment(content_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    comment_text = data.get('comment_text')

    new_comment = Comment(
        comment_text=comment_text,
        user_id=user_id,
        content_id=content_id,
        created_at=datetime.utcnow()
    )

    db.session.add(new_comment)
    db.session.commit()

    return jsonify({'message': 'Comment added successfully'}), 201

@app.route('/content/search', methods=['GET'])
def search_content():
    query = request.args.get('query', '')
    results = Content.search(query)
    return jsonify([{'id': c.id, 'title': c.title, 'slug': c.slug} for c in results]), 200

@app.route('/content', methods=['GET'])
def list_content():
    contents = Content.query.all()
    result = [{'id': c.id, 'title': c.title, 'slug': c.slug, 'views_count': c.views_count} for c in contents]

    return jsonify(result), 200

@app.route('/content', methods=['POST'])
@jwt_required()
def create_content():
    data = request.get_json()
    user_id = get_jwt_identity()
    title = data.get('title')
    slug = data.get('slug')
    content = data.get('content')
    category_id = data.get('category_id')

    new_content = Content(
        title=title,
        slug=slug,
        content=content,
        user_id=user_id,
        category_id=category_id,
        created_at=datetime.utcnow()
    )

    db.session.add(new_content)
    db.session.commit()

    return jsonify({'message': 'Content created successfully'}), 201

@auth_bp.route('/api/admin/users', methods=['POST'])
@jwt_required()
def create_user():
    if get_jwt_identity()['user_type'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    
    # Check if the user already exists
    existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
    if existing_user:
        return jsonify({"message": "Username or email already exists"}), 400

    # Hash the password before saving
    hashed_password = generate_password_hash(data['password'])
    
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password,
        user_type=data['user_type']
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User added successfully"}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Error adding user"}), 400

# Deactivate a user (Admin only)
@auth_bp.route('/api/admin/users/<int:id>/deactivate', methods=['PATCH'])
@jwt_required()
def deactivate_user(id):
    if get_jwt_identity()['user_type'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    
    user = User.query.get(id)
    if user:
        user.is_active = False
        db.session.commit()
        return jsonify({"message": "User deactivated"}), 200
    return jsonify({"message": "User not found"}), 404

# Delete flagged content (Admin only)
@auth_bp.route('/api/admin/content/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_content(id):
    if get_jwt_identity()['user_type'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    
    content = Content.query.get(id)
    if content:
        db.session.delete(content)
        db.session.commit()
        return jsonify({"message": "Content removed successfully"}), 200
    return jsonify({"message": "Content not found"}), 404


# Create a content category (Admin only)


# Tech Writer or Admin: Post Content

# Tech Writer or Admin: Edit Content by Tech Writer
@auth_bp.route('/api/tech-writer/content/<int:id>', methods=['PATCH'])
@jwt_required()
def edit_content_by_tech_writer(id):
    current_user = get_jwt_identity()  # Get the currently logged-in user's ID
    content_item = Content.query.get(id)
    
    if not content_item:
        return jsonify({"message": "Content not found"}), 404

    # Check if the content belongs to the logged-in user
    if content_item.user_id != current_user:
        return jsonify({"message": "You can only edit your own content"}), 403

    data = request.get_json()
    title = data.get('title', content_item.title)
    content = data.get('content', content_item.content)
    media_url = data.get('media_url', content_item.media_url)
    tags = data.get('tags', content_item.tags)

    try:
        content_item.title = title
        content_item.content = content
        content_item.media_url = media_url
        content_item.tags = ','.join(tags)
        db.session.commit()
        return jsonify({"message": "Content updated successfully"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

# Admin: Edit Any Content
@auth_bp.route('/api/content/<int:id>', methods=['PATCH'])
@jwt_required()
def edit_content_by_admin(id):
    user_identity = get_jwt_identity()
    
    content = Content.query.get(id)
    if not content:
        return jsonify({"message": "Content not found"}), 404
    
    if content.user_id != user_identity['id'] and user_identity['user_type'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    content.title = data.get('title', content.title)
    content.description = data.get('description', content.description)
    
    db.session.commit()
    return jsonify({"message": "Content updated successfully"}), 200

# Create a user profile
@user_bp.route('/api/user/profile', methods=['POST'])
@jwt_required()
def create_user_profile():
    user_identity = get_jwt_identity()
    data = request.get_json()
    
    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    user.username = data['username']
    user.bio = data['bio']
    user.profile_picture = data['profile_picture']
    
    db.session.commit()
    return jsonify({"message": "Profile created successfully"}), 201

# Get user preferences
@user_bp.route('/api/user/preferences', methods=['GET'])
@jwt_required()
def get_user_preferences():
    user_identity = get_jwt_identity()
    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    preferences = {
        "subscribed_categories": [category.name for category in user.subscribed_categories],
        "wishlist": [item.id for item in user.wishlist]
    }
    return jsonify({"preferences": preferences}), 200

# Update user preferences (subscribe/unsubscribe categories)
@user_bp.route('/api/user/preferences', methods=['POST'])
@jwt_required()
def update_user_preferences():
    user_identity = get_jwt_identity()
    data = request.get_json()
    
    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    # Update subscribed categories
    user.subscribed_categories = [Category.query.filter_by(name=cat).first() for cat in data['subscribed_categories']]
    
    db.session.commit()
    return jsonify({"message": "Preferences updated successfully"}), 200

@app.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user_id).all()
    result = [{'id': n.id, 'message': n.message, 'is_read': n.is_read} for n in notifications]

    return jsonify(result), 200

# AuditLog Routes
@app.route('/audit_logs', methods=['GET', 'POST'])
def manage_audit_logs():
    if request.method == 'POST':
        data = request.get_json()
        audit_log = AuditLog(
            action=data['action'],
            user_id=data['user_id'],
            content_id=data.get('content_id')
        )
        db.session.add(audit_log)
        db.session.commit()
        return jsonify({"message": "Audit log created"}), 201
    audit_logs = AuditLog.query.all()
    return jsonify([{"id": log.id, "action": log.action, "user_id": log.user_id} for log in audit_logs])

# UserSettings Routes
@app.route('/user_settings', methods=['GET', 'POST'])
def manage_user_settings():
    if request.method == 'POST':
        data = request.get_json()
        settings = UserSettings(
            user_id=data['user_id'],
            receive_notifications=data.get('receive_notifications', True),
            receive_email_updates=data.get('receive_email_updates', True),
            theme_preference=data.get('theme_preference', "light")
        )
        db.session.add(settings)
        db.session.commit()
        return jsonify({"message": "User settings created"}), 201
    user_settings = UserSettings.query.all()
    return jsonify([{"user_id": s.user_id, "receive_notifications": s.receive_notifications} for s in user_settings])

# ActivityFeed Routes
@app.route('/activity_feed', methods=['GET', 'POST'])
def manage_activity_feed():
    if request.method == 'POST':
        data = request.get_json()
        activity = ActivityFeed(
            user_id=data['user_id'],
            action=data['action'],
            content_id=data.get('content_id')
        )
        db.session.add(activity)
        db.session.commit()
        return jsonify({"message": "Activity recorded"}), 201
    activities = ActivityFeed.query.all()
    return jsonify([{"user_id": a.user_id, "action": a.action} for a in activities])

# ContentRating Routes
@app.route('/content_ratings', methods=['GET', 'POST'])
def manage_content_ratings():
    if request.method == 'POST':
        data = request.get_json()
        rating = ContentRating(
            user_id=data['user_id'],
            content_id=data['content_id'],
            rating=data['rating']
        )
        db.session.add(rating)
        db.session.commit()
        return jsonify({"message": "Content rating created"}), 201
    ratings = ContentRating.query.all()
    return jsonify([{"user_id": r.user_id, "content_id": r.content_id, "rating": r.rating} for r in ratings])

# Log Routes
@app.route('/logs', methods=['GET', 'POST'])
def manage_logs():
    if request.method == 'POST':
        data = request.get_json()
        log = Log(
            user_id=data.get('user_id'),
            action=data['action'],
            status=data['status'],
            message=data.get('message')
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Log created"}), 201
    logs = Log.query.all()
    return jsonify([{"id": l.id, "action": l.action, "status": l.status} for l in logs])

# Reply Routes
@app.route('/replies', methods=['GET', 'POST'])
def manage_replies():
    if request.method == 'POST':
        data = request.get_json()
        reply = Reply(
            reply_text=data['reply_text'],
            user_id=data['user_id'],
            comment_id=data['comment_id'],
            likes_count=data.get('likes_count', 0)
        )
        db.session.add(reply)
        db.session.commit()
        return jsonify({"message": "Reply created"}), 201
    replies = Reply.query.all()
    return jsonify([{"id": r.id, "reply_text": r.reply_text, "user_id": r.user_id} for r in replies])

# Role Routes
@app.route('/roles', methods=['GET', 'POST'])
def manage_roles():
    if request.method == 'POST':
        data = request.get_json()
        role = Role(
            name=data['name'],
            description=data.get('description'),
            permissions=data.get('permissions')
        )
        db.session.add(role)
        db.session.commit()
        return jsonify({"message": "Role created"}), 201
    roles = Role.query.all()
    return jsonify([{"id": role.id, "name": role.name, "description": role.description} for role in roles])

# User can post content
@user_bp.route('/api/user/content', methods=['POST'])
@jwt_required()
def post_user_content():
    user_identity = get_jwt_identity()
    data = request.get_json()

    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    category = Category.query.filter_by(name=data['category']).first()
    if not category:
        return jsonify({"message": "Invalid category"}), 400

    content = Content(
        title=data['title'],
        content=data['content'],
        category_id=category.id,
        media_url=data['media_url'],
        user_id=user.id
    )
    
    db.session.add(content)
    db.session.commit()
    return jsonify({"message": "Content posted successfully"}), 201

# Get content based on user preferences and subscriptions
@user_bp.route('/api/user/content', methods=['GET'])
@jwt_required()
def get_user_content():
    user_identity = get_jwt_identity()
    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    content_list = Content.query.filter(Content.category_id.in_([cat.id for cat in user.subscribed_categories])).all()

    content_data = []
    for content in content_list:
        content_data.append({
            "id": content.id,
            "title": content.title,
            "content": content.content,
            "category": content.category.name,
            "media_url": content.media_url,
            "tags": [tag.name for tag in content.tags]
        })

    return jsonify({"content": content_data}), 200

# Post a comment on a content item
@user_bp.route('/api/user/content/<int:id>/comment', methods=['POST'])
@jwt_required()
def post_comment(id):
    user_identity = get_jwt_identity()
    data = request.get_json()

    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    content = Content.query.get(id)
    if not content:
        return jsonify({"message": "Content not found"}), 404

    comment = Comment(
        content_id=id,
        user_id=user.id,
        comment_text=data['comment_text']
    )

    db.session.add(comment)
    db.session.commit()
    return jsonify({"message": "Comment posted successfully"}), 201

# Reply to a comment (similar to Reddit threads)
@user_bp.route('/api/user/content/<int:id>/reply', methods=['POST'])
@jwt_required()
def post_reply(id):
    user_identity = get_jwt_identity()
    data = request.get_json()

    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    comment = Comment.query.get(id)
    if not comment:
        return jsonify({"message": "Comment not found"}), 404

    reply = Reply(
        comment_id=id,
        user_id=user.id,
        reply_text=data['reply_text']
    )

    db.session.add(reply)
    db.session.commit()
    return jsonify({"message": "Reply posted successfully"}), 201

# Like a content item
@user_bp.route('/api/user/content/<int:id>/like', methods=['POST'])
@jwt_required()
def like_content(id):
    user_identity = get_jwt_identity()
    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    content = Content.query.get(id)
    if not content:
        return jsonify({"message": "Content not found"}), 404
    
    content.likes.append(user)
    db.session.commit()
    return jsonify({"message": "Content liked"}), 200

# Dislike a content item
@user_bp.route('/api/user/content/<int:id>/dislike', methods=['POST'])
@jwt_required()
def dislike_content(id):
    user_identity = get_jwt_identity()
    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    content = Content.query.get(id)
    if not content:
        return jsonify({"message": "Content not found"}), 404
    
    content.dislikes.append(user)
    db.session.commit()
    return jsonify({"message": "Content disliked"}), 200

# Add content to the user's wishlist
@user_bp.route('/api/user/content/<int:id>/wishlist', methods=['POST'])
@jwt_required()
def add_to_wishlist(id):
    user_identity = get_jwt_identity()
    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    content = Content.query.get(id)
    if not content:
        return jsonify({"message": "Content not found"}), 404
    
    user.wishlist.append(content)
    db.session.commit()
    return jsonify({"message": "Content added to wishlist"}), 200
# Tag routes
@app.route('/tags', methods=['GET', 'POST'])
def handle_tags():
    if request.method == 'POST':
        data = request.json
        tag = Tag(name=data['name'])
        db.session.add(tag)
        db.session.commit()
        return jsonify(tag), 201
    tags = Tag.query.all()
    return jsonify([str(tag) for tag in tags])

# Report routes
@app.route('/reports', methods=['GET', 'POST'])
def handle_reports():
    if request.method == 'POST':
        data = request.json
        report = Report(
            reporter_id=data['reporter_id'],
            reported_content_id=data.get('reported_content_id'),
            reported_user_id=data.get('reported_user_id'),
            reason=data['reason'],
            status=data.get('status', 'pending')
        )
        db.session.add(report)
        db.session.commit()
        return jsonify(report), 201
    reports = Report.query.all()
    return jsonify([str(report) for report in reports])

# UserFollow routes
@app.route('/user_follows', methods=['POST'])
def follow_user():
    data = request.json
    follow = UserFollow(follower_id=data['follower_id'], followee_id=data['followee_id'])
    db.session.add(follow)
    db.session.commit()
    return jsonify(follow), 201

@app.route('/user_follows/<int:follower_id>/<int:followee_id>', methods=['DELETE'])
def unfollow_user(follower_id, followee_id):
    follow = UserFollow.query.filter_by(follower_id=follower_id, followee_id=followee_id).first()
    if follow:
        db.session.delete(follow)
        db.session.commit()
        return '', 204
    return abort(404)

# ContentVersion routes
@app.route('/content_versions', methods=['GET', 'POST'])
def handle_content_versions():
    if request.method == 'POST':
        data = request.json
        version = ContentVersion(
            content_id=data['content_id'],
            version_number=data['version_number'],
            title=data['title'],
            body=data['body']
        )
        db.session.add(version)
        db.session.commit()
        return jsonify(version), 201
    versions = ContentVersion.query.all()
    return jsonify([str(version) for version in versions])
@app.route('/badges', methods=['GET', 'POST'])
def handle_badges():
    if request.method == 'POST':
        try:
            # Get data from the request body
            data = request.get_json()

            # Validate required fields
            if not data.get('name'):
                raise BadRequest("The 'name' field is required.")
            
            # Create a new badge
            badge = Badge(
                name=data['name'],
                description=data.get('description'),
                icon_url=data.get('icon_url')
            )

            # Add the badge to the session and commit
            db.session.add(badge)
            db.session.commit()

            # Return a response with the created badge
            return jsonify(badge.to_dict()), 201
        
        except BadRequest as e:
            return jsonify({"error": str(e)}), 400  # Bad request if validation fails
        except Exception as e:
            return jsonify({"error": "Internal server error", "message": str(e)}), 500  # Handle other exceptions
    
    elif request.method == 'GET':
        try:
            # Fetch all badges from the database
            badges = Badge.query.all()

            # Return the list of badges
            return jsonify([badge.to_dict() for badge in badges])

        except Exception as e:
            return jsonify({"error": "Internal server error", "message": str(e)}), 500


# Media routes
@app.route('/media', methods=['GET', 'POST'])
def handle_media():
    if request.method == 'POST':
        data = request.json
        media = Media(
            media_type=data['media_type'],
            url=data['url'],
            content_id=data.get('content_id')
        )
        db.session.add(media)
        db.session.commit()
        return jsonify(media), 201
    media_items = Media.query.all()
    return jsonify([str(media) for media in media_items])

# Many-to-many route example: content_tags
@app.route('/content_tags', methods=['POST'])
def add_content_tag():
    data = request.json
    content_id = data['content_id']
    tag_id = data['tag_id']
    stmt = content_tags.insert().values(content_id=content_id, tag_id=tag_id)
    db.session.execute(stmt)
    db.session.commit()
    return jsonify({'message': 'Tag added to content'}), 201

# More routes for other many-to-many tables can be created in a similar way

# Share content with other users
@user_bp.route('/api/user/content/<int:id>/share', methods=['POST'])
@jwt_required()
def share_content(id):
    user_identity = get_jwt_identity()
    user = User.query.get(user_identity['id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    content = Content.query.get(id)
    if not content:
        return jsonify({"message": "Content not found"}), 404
    
    # Logic for sharing content (e.g., via email or social media)
    return jsonify({"message": "Content shared successfully"}), 200

