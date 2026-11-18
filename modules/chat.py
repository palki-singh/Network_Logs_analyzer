"""
Chat and Messaging Module for SecureChat.
Manages private conversations between registered users, conversation threads,
unread counters, message sending with metadata-only security logging,
and strict access controls to prevent unauthorized conversation snooping.
"""

import uuid
from datetime import datetime, timezone
from config import Config
from modules.storage import load_json, save_json, append_json_item
from modules.logging_system import security_logger
from modules.authentication import get_user_by_id, get_all_users

def get_all_messages():
    """Load all messages from chats.json."""
    return load_json(Config.CHATS_FILE, default=[])

def get_conversation(user_a_id, user_b_id, mark_as_read_for_user=None):
    """
    Retrieves the private message history between two specific users.
    Optionally marks messages sent to `mark_as_read_for_user` as read.
    """
    all_msgs = get_all_messages()
    conversation = []
    updated = False

    for msg in all_msgs:
        sender = msg.get("sender_id")
        receiver = msg.get("receiver_id")

        if (sender == user_a_id and receiver == user_b_id) or (sender == user_b_id and receiver == user_a_id):
            if mark_as_read_for_user and receiver == mark_as_read_for_user and not msg.get("is_read"):
                msg["is_read"] = True
                updated = True
            conversation.append(msg)

    if updated:
        save_json(Config.CHATS_FILE, all_msgs)

    # Sort chronologically
    return sorted(conversation, key=lambda m: m.get("timestamp", ""))

def get_user_conversations_summary(user_id):
    """
    Retrieves a list of conversation partners for the current user,
    along with their profile, the last message, timestamp, and unread count.
    """
    all_msgs = get_all_messages()
    all_users_map = {u["user_id"]: u for u in get_all_users()}
    conversations = {}

    for msg in all_msgs:
        sender_id = msg.get("sender_id")
        receiver_id = msg.get("receiver_id")

        if sender_id != user_id and receiver_id != user_id:
            continue

        partner_id = receiver_id if sender_id == user_id else sender_id
        if partner_id not in all_users_map:
            continue

        if partner_id not in conversations:
            conversations[partner_id] = {
                "partner": all_users_map[partner_id],
                "last_message": msg.get("content", ""),
                "last_timestamp": msg.get("timestamp", ""),
                "unread_count": 0
            }
        else:
            if msg.get("timestamp", "") > conversations[partner_id]["last_timestamp"]:
                conversations[partner_id]["last_message"] = msg.get("content", "")
                conversations[partner_id]["last_timestamp"] = msg.get("timestamp", "")

        # Unread count
        if receiver_id == user_id and not msg.get("is_read"):
            conversations[partner_id]["unread_count"] += 1

    # Return list sorted by last activity
    summary_list = list(conversations.values())
    summary_list.sort(key=lambda x: x["last_timestamp"], reverse=True)
    return summary_list

def send_message(sender_user, receiver_user, content):
    """
    Sends a private message from sender to receiver.
    Validates message length, stores message in chats.json,
    and logs ONLY metadata (no message text) in security_logs.json.
    """
    content_clean = (content or "").strip()
    if not content_clean:
        return False, "Message cannot be empty."

    if len(content_clean) > 2000:
        return False, "Message exceeds 2000 character limit."

    msg_id = f"msg-{uuid.uuid4().hex[:10]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    message = {
        "message_id": msg_id,
        "sender_id": sender_user["user_id"],
        "sender_username": sender_user["username"],
        "receiver_id": receiver_user["user_id"],
        "receiver_username": receiver_user["username"],
        "content": content_clean,
        "timestamp": now_iso,
        "is_read": False
    }

    append_json_item(Config.CHATS_FILE, message)

    # Security requirement: Record METADATA ONLY, never message body!
    security_logger.log_event(
        event_type="MESSAGE_SENT",
        description=f"User '{sender_user['username']}' sent private message to '{receiver_user['username']}' (Length: {len(content_clean)} chars)",
        username=sender_user["username"],
        user_id=sender_user["user_id"],
        status="SUCCESS",
        severity="LOW"
    )

    return True, message

def search_users(current_user_id, query=""):
    """
    Discovers registered users, excluding the current user.
    Supports filtering by username or full name.
    """
    users = get_all_users()
    query_clean = (query or "").strip().lower()
    results = []

    for u in users:
        # Exclude self
        if u.get("user_id") == current_user_id:
            continue

        if query_clean:
            match_username = query_clean in u.get("username", "").lower()
            match_name = query_clean in u.get("full_name", "").lower()
            if not (match_username or match_name):
                continue

        # Sanitize sensitive fields before returning to frontend
        safe_user = {
            "user_id": u.get("user_id"),
            "username": u.get("username"),
            "full_name": u.get("full_name"),
            "bio": u.get("bio", "No bio provided."),
            "zodiac_sign": u.get("zodiac_sign", "✨ Cosmic Seeker"),
            "profile_picture": u.get("profile_picture", "default_avatar.png"),
            "created_at": u.get("created_at"),
            "role": u.get("role", "user")
        }
        results.append(safe_user)

    return results
