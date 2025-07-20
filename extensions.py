import re
from captcha.image import ImageCaptcha
import random
import string
import os
import html
from flask import request, abort
from bson import ObjectId, errors


# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
# from redis import Redis
#
# # Connect to Redis
# redis_store = Redis(host='localhost', port=6379)

# # Create Limiter with Redis storage
# limiter = Limiter(
#     key_func=get_remote_address,
#     storage_uri="redis://localhost:6379",
#     default_limits=["5 per minute", "1 per second"]
# )


# to avoid ImportError: cannot import name 'csrf' from partially initialized module 'app' (most likely due to a circular import) with aip.py
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager

csrf = CSRFProtect()  # CSRF protection
login_manager = LoginManager()  # Flask-Login manager





def sanitize_input(input_str):
    # Remove MongoDB query operators
    sanitized_str = re.sub(r'\$|\.', '', input_str)
    return sanitized_str


CAPTCHA_FOLDER = 'static/captcha_images'

if not os.path.exists(CAPTCHA_FOLDER):
    os.makedirs(CAPTCHA_FOLDER)

image = ImageCaptcha(width=280, height=90)


def generate_captcha():
    clear_old_captchas()  # Clear old captchas before generating a new one
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    captcha_path = os.path.join(CAPTCHA_FOLDER, 'captcha.png')
    image.write(captcha_text, captcha_path)
    return captcha_text, captcha_path


def clear_old_captchas():
    files = os.listdir(CAPTCHA_FOLDER)
    for file in files:
        os.remove(os.path.join(CAPTCHA_FOLDER, file))


# captcha_text, captcha_path = generate_captcha()



def sanitize_and_validate_input(value, *, allow_spaces=True, allow_html=False, max_length=100):
    """
    Cleans and validates user input to prevent:
    - SQL/NoSQL injection
    - XSS (stored/reflected)
    - Path traversal or command injection

    Args:
        value (str): The raw user input
        allow_spaces (bool): If False, collapses/removes spaces
        allow_html (bool): If True, allows basic HTML (use with care!)
        max_length (int): Maximum length for any input

    Returns:
        str: Safe, cleaned input

    Raises:
        ValueError: If input is unsafe or invalid
    """

    if not isinstance(value, str):
        raise ValueError("Input must be a string")

    # Trim whitespace
    value = value.strip()

    # Remove null bytes
    value = value.replace('\x00', '')

    # Length check
    if len(value) > max_length:
        raise ValueError("Input too long")

    # Optional HTML escaping
    if not allow_html:
        value = html.escape(value, quote=True)

    # Basic XSS prevention: remove script-ish stuff
    dangerous_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',           # e.g., onclick=
        r'document\.',
        r'window\.',
        r'eval\(',
        r'alert\('
    ]
    for pattern in dangerous_patterns:
        value = re.sub(pattern, '', value, flags=re.IGNORECASE)

    # Allow only certain characters
    allowed_pattern = r'^[\w,\- ]+$' if allow_spaces else r'^[\w,\-]+$'
    if not re.match(allowed_pattern, value):
        raise ValueError("Input contains invalid characters")

    # Collapse multiple spaces
    if allow_spaces:
        value = re.sub(r'\s+', ' ', value)

    if not value:
        raise ValueError("Input is empty or invalid")

    return value


def get_validated_object_id(field_name):
    raw_id = request.form.get(field_name)
    try:
        return ObjectId(str(raw_id))
    except (errors.InvalidId, TypeError):
        abort(400, f"Invalid ObjectId for field: {field_name}")