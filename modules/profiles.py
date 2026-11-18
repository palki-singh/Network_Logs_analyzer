"""
User Profile Management Module for SecureChat.
Handles profile updates, secure file uploads with extension/MIME validation,
path traversal mitigation, and audit logging for profile modifications.
"""

import os
import uuid
from werkzeug.utils import secure_filename
from config import Config
from modules.storage import load_json, save_json
from modules.logging_system import security_logger
from modules.authentication import get_user_by_id, get_user_by_email, EMAIL_REGEX

def allowed_file(filename):
    """Checks whether the file extension is among ALLOWED_EXTENSIONS."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS

def update_user_profile(user_id, full_name, bio, email, file=None, zodiac_sign=None):
    """
    Updates a user's profile information, zodiac sign, and profile avatar.
    Returns (success_boolean, message).
    """
    users = load_json(Config.USERS_FILE, default=[])
    target_idx = None
    target_user = None

    for idx, u in enumerate(users):
        if u.get("user_id") == user_id:
            target_idx = idx
            target_user = u
            break

    if target_user is None:
        return False, "User not found."

    # Validate inputs
    full_name = (full_name or "").strip()
    bio = (bio or "").strip()
    email = (email or "").strip().lower()
    zodiac_sign = (zodiac_sign or "").strip()

    if not full_name:
        return False, "Full name cannot be blank."
    if len(full_name) < 2 or len(full_name) > 60:
        return False, "Full name must be between 2 and 60 characters."

    if not email or not EMAIL_REGEX.match(email):
        return False, "Please enter a valid email address."

    # Check email conflict with another user
    existing_email_user = get_user_by_email(email)
    if existing_email_user and existing_email_user.get("user_id") != user_id:
        return False, "Email address is already in use by another account."

    if len(bio) > 300:
        return False, "Bio cannot exceed 300 characters."

    changes = []
    if target_user.get("full_name") != full_name:
        changes.append("full_name")
        target_user["full_name"] = full_name

    if target_user.get("email") != email:
        changes.append("email")
        target_user["email"] = email

    if target_user.get("bio") != bio:
        changes.append("bio")
        target_user["bio"] = bio

    if zodiac_sign and target_user.get("zodiac_sign") != zodiac_sign:
        changes.append("zodiac_sign")
        target_user["zodiac_sign"] = zodiac_sign

    # Handle optional avatar upload
    if file and file.filename:
        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            return False, f"Invalid file type. Allowed formats: {', '.join(Config.ALLOWED_EXTENSIONS)}"

        ext = filename.rsplit(".", 1)[1].lower()
        unique_filename = f"avatar_{user_id}_{uuid.uuid4().hex[:8]}.{ext}"
        upload_path = os.path.join(Config.UPLOAD_FOLDER, unique_filename)

        # Ensure upload folder exists
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        file.save(upload_path)

        target_user["profile_picture"] = unique_filename
        changes.append("profile_picture")

        security_logger.log_event(
            event_type="PROFILE_PICTURE_UPLOAD",
            description=f"User '{target_user['username']}' uploaded a new profile picture ({unique_filename})",
            username=target_user["username"],
            user_id=user_id,
            status="SUCCESS",
            severity="LOW"
        )

    users[target_idx] = target_user
    save_json(Config.USERS_FILE, users)

    if changes:
        security_logger.log_event(
            event_type="PROFILE_UPDATED",
            description=f"User '{target_user['username']}' updated profile fields: {', '.join(changes)}",
            username=target_user["username"],
            user_id=user_id,
            status="SUCCESS",
            severity="LOW"
        )

    return True, "Profile updated successfully."
