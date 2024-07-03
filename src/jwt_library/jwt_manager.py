import logging
import jwt

class JWTManager:
    def __init__(self, validation_function=None, secret_key=None):
        self.validation_function = validation_function
        self.secret_key = secret_key

    def validate_token(self, token):
        if self.validation_function:
            return self.validation_function(token, self.secret_key)
        else:
            logging.warning("No validation function provided.")
            return False

def jwt_validation_function(token, secret_key):
    try:
        decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
        return decoded["name"]
    except jwt.ExpiredSignatureError:
        logging.error("Token has expired")
        return None
    except jwt.InvalidTokenError:
        logging.error("Invalid token")
        return None
