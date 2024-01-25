#!/usr/bin/env python3
""" A Flask app with user authentication.
"""
from flask import Flask, jsonify, request, abort, redirect

from auth import Auth

app = Flask(__name__)
AUTH = Auth()


# Routes
@app.route("/", methods=["GET"], strict_slashes=False)
def index():
    """GET /
    Returns the home page's content.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def create_user():
    """POST /users
    Returns the account creation content.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "User created"})
    except ValueError:
        return jsonify({"message": "Email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """POST /sessions
    Returns the account login content.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "Logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """DELETE /sessions
    Redirects to the home route.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def get_profile():
    """GET /profile
    Returns the user's profile information.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    return jsonify({"email": user.email})


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def request_reset_password_token():
    """POST /reset_password
    Returns the user's password reset content.
    """
    email = request.form.get("email")
    reset_token = None

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        reset_token = None

    if reset_token is None:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token})


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password():
    """PUT /reset_password
    Returns the user's password updated content.
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    is_password_changed = False

    try:
        AUTH.update_password(reset_token, new_password)
        is_password_changed = True
    except ValueError:
        is_password_changed = False

    if not is_password_changed:
        abort(403)

    return jsonify({"email": email, "message": "Password updated"})

# Run the app if executed directly


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
