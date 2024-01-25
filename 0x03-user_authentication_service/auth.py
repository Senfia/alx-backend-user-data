#!/usr/bin/env python3
"""Authentication module.
"""
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from uuid import uuid4

from db import DB
from user import User


class Auth:
    """Authentication class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize a new Auth instance."""
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hash a password."""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    def _generate_uuid(self) -> str:
        """Generate a UUID."""
        return str(uuid4())

    def register_user(self, email: str, password: str) -> User:
        """Add a new user to the database."""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, self._hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """Check if a user's login details are valid or not."""
        try:
            user = self._db.find_user_by(email=email)
            return user is not None and bcrypt.checkpw(
                password.encode("utf-8"),
                user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a new user session."""
        try:
            user = self._db.find_user_by(email=email)
            session_id = self._generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieve a user from a session ID."""
        if session_id is None:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy a user session."""
        if user_id is not None:
            self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generate a reset token for a user password."""
        try:
            user = self._db.find_user_by(email=email)
            reset_token = self._generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError()

    def update_password(self, reset_token: str, password: str) -> None:
        """Update a user's password."""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            new_password_hash = self._hash_password(password)
            self._db.update_user(
                user.id,
                hashed_password=new_password_hash,
                reset_token=None)
        except NoResultFound:
            raise ValueError()
