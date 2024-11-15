from marshmallow import Schema, fields, post_load
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from marshmallow import ValidationError
from auth.models import User, TechWriterProfile, Badge, Content, Category, ContentReview, Comment, Role, ActivityFeed, Log, Reply, UserSettings, Report, Notification,Tag, AuditLog, ContentRating

# User Schema
class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True  # To include foreign keys in the schema

    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    user_type = fields.Str(required=True)
    is_active = fields.Bool()
    profile_picture = fields.Str()
    created_at = fields.DateTime()
    last_login = fields.DateTime()
    updated_at = fields.DateTime()
    profile_complete = fields.Bool()

    # Post load to create a User instance from the schema data
    @post_load
    def make_user(self, data, **kwargs):
        return User(**data)


# TechWriterProfile Schema
class TechWriterProfileSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = TechWriterProfile
        include_fk = True

    id = fields.Int(dump_only=True)
    user_id = fields.Int(required=True)
    bio = fields.Str()
    expertise = fields.Str()
    published_articles_count = fields.Int()

    @post_load
    def make_profile(self, data, **kwargs):
        return TechWriterProfile(**data)


# Badge Schema
class BadgeSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Badge

    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)
    description = fields.Str()
    icon_url = fields.Str()
    earned_at = fields.DateTime()

    @post_load
    def make_badge(self, data, **kwargs):
        return Badge(**data)


# Content Schema
class ContentSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Content
        include_fk = True

    id = fields.Int(dump_only=True)
    title = fields.Str(required=True)
    slug = fields.Str(required=True)
    content = fields.Str(required=True)
    category_id = fields.Int(required=True)
    media_url = fields.Str()
    tags = fields.Str()
    approved = fields.Bool()
    flagged = fields.Bool()
    user_id = fields.Int()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()
    draft = fields.Bool()
    views_count = fields.Int()

    @post_load
    def make_content(self, data, **kwargs):
        return Content(**data)


# ContentReview Schema
class ContentReviewSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ContentReview
        include_fk = True

    id = fields.Int(dump_only=True)
    content_id = fields.Int(required=True)
    user_id = fields.Int(required=True)
    rating = fields.Int()
    review_type = fields.Str(required=True)
    comment = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()

    @post_load
    def make_content_review(self, data, **kwargs):
        return ContentReview(**data)


# Category Schema
class CategorySchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Category

    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)
    description = fields.Str()

    @post_load
    def make_category(self, data, **kwargs):
        return Category(**data)


# Comment Schema
class CommentSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Comment
        include_fk = True

    id = fields.Int(dump_only=True)
    comment_text = fields.Str(required=True)
    user_id = fields.Int(required=True)
    content_id = fields.Int(required=True)
    created_at = fields.DateTime()
    updated_at = fields.DateTime()
    likes_count = fields.Int()

    @post_load
    def make_comment(self, data, **kwargs):
        return Comment(**data)


# Notification Schema
class NotificationSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Notification
        include_fk = True

    id = fields.Int(dump_only=True)
    user_id = fields.Int(required=True)
    message = fields.Str(required=True)
    notification_type = fields.Str(required=True)
    notification_url = fields.Str()
    is_read = fields.Bool()
    created_at = fields.DateTime()
    expiry_date = fields.DateTime()

    @post_load
    def make_notification(self, data, **kwargs):
        return Notification(**data)


# AuditLog Schema
class AuditLogSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = AuditLog
        include_fk = True

    id = fields.Int(dump_only=True)
    action = fields.Str(required=True)
    user_id = fields.Int(required=True)
    content_id = fields.Int()
    timestamp = fields.DateTime()

    @post_load
    def make_audit_log(self, data, **kwargs):
        return AuditLog(**data)


# UserSettings Schema
class UserSettingsSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = UserSettings
        include_fk = True

    id = fields.Int(dump_only=True)
    user_id = fields.Int(required=True)
    receive_notifications = fields.Bool()
    receive_email_updates = fields.Bool()
    theme_preference = fields.Str()

    @post_load
    def make_user_settings(self, data, **kwargs):
        return UserSettings(**data)


# ActivityFeed Schema
class ActivityFeedSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ActivityFeed
        include_fk = True

    id = fields.Int(dump_only=True)
    user_id = fields.Int(required=True)
    action = fields.Str(required=True)
    content_id = fields.Int()
    timestamp = fields.DateTime()

    @post_load
    def make_activity_feed(self, data, **kwargs):
        return ActivityFeed(**data)


# ContentRating Schema
class ContentRatingSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ContentRating
        include_fk = True

    id = fields.Int(dump_only=True)
    user_id = fields.Int(required=True)
    content_id = fields.Int(required=True)
    rating = fields.Int(required=True)

    @post_load
    def make_content_rating(self, data, **kwargs):
        return ContentRating(**data)


# Log Schema
class LogSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Log
        include_fk = True

    id = fields.Int(dump_only=True)
    user_id = fields.Int()
    action = fields.Str(required=True)
    status = fields.Str(required=True)
    message = fields.Str()
    timestamp = fields.DateTime()

    @post_load
    def make_log(self, data, **kwargs):
        return Log(**data)


# Reply Schema
class ReplySchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Reply
        include_fk = True

    id = fields.Int(dump_only=True)
    reply_text = fields.Str(required=True)
    user_id = fields.Int(required=True)
    comment_id = fields.Int(required=True)
    created_at = fields.DateTime()
    updated_at = fields.DateTime()
    likes_count = fields.Int()

    @post_load
    def make_reply(self, data, **kwargs):
        return Reply(**data)


# Role Schema
class RoleSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Role

    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)
    description = fields.Str()
    permissions = fields.Str()

    @post_load
    def make_role(self, data, **kwargs):
        return Role(**data)


# Tag Schema
class TagSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Tag

    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)

    @post_load
    def make_tag(self, data, **kwargs):
        return Tag(**data)


# Report Schema
class ReportSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Report
        include_fk = True

    id = fields.Int(dump_only=True)
    reporter_id = fields.Int(required=True)
    reported_content_id = fields.Int()
    reported_user_id = fields.Int()
    reason = fields.Str(required=True)
    status = fields.Str()
    timestamp = fields.DateTime()

    @post_load
    def make_report(self, data, **kwargs):
        return Report(**data)

