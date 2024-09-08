import re
from captcha.image import ImageCaptcha
import random
import string
import os

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

