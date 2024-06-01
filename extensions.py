import re
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
