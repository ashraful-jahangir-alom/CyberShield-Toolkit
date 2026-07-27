from datetime import datetime
from . import db


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    module = db.Column(db.String(64), nullable=False)
    result = db.Column(db.Text, default='{}')
    risk = db.Column(db.String(16), default='LOW')
    duration = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='scans')
