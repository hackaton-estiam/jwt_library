import unittest
from unittest.mock import patch
from jwt_library import JWTManager
import sqlite3
import requests
import jwt

SECRET_KEY = 'your-256-bit-secret'

class TestJWTManager(unittest.TestCase):

    def test_validate_token_with_function(self):
        manager = JWTManager(validation_function=lambda token, _: 'User' if token == 'valid_token' else None)
        self.assertEqual(manager.validate_token('valid_token'), 'User')
        self.assertIsNone(manager.validate_token('invalid_token'))

    def test_validate_token_with_no_function(self):
        manager = JWTManager()
        self.assertFalse(manager.validate_token('valid_token'))

    def test_db_validation_function(self):
        conn = sqlite3.connect(':memory:')
        conn.execute("CREATE TABLE users (name TEXT, token TEXT)")
        conn.execute("INSERT INTO users (name, token) VALUES ('Alice', 'token_alice')")
        conn.commit()

        def db_validation_function(token, _):
            query = "SELECT name FROM users WHERE token = ?"
            cursor = conn.execute(query, (token,))
            result = cursor.fetchone()
            return result[0] if result else None

        manager = JWTManager(validation_function=db_validation_function)
        self.assertEqual(manager.validate_token('token_alice'), 'Alice')
        self.assertIsNone(manager.validate_token('invalid_token'))

    @patch('requests.post')
    def test_api_validation_function(self, mock_post):
        mock_post.return_value.json.return_value = {'valid': True}

        def api_validation_function(token, _):
            response = requests.post('https://example.com/validate', json={'token': token})
            return 'API_User' if response.json().get('valid', False) else None

        manager = JWTManager(validation_function=api_validation_function)
        self.assertEqual(manager.validate_token('dummy_token'), 'API_User')

        mock_post.return_value.json.return_value = {'valid': False}
        self.assertIsNone(manager.validate_token('dummy_token'))

    def test_jwt_validation_function(self):
        encoded_jwt = jwt.encode({"name": "John Doe"}, SECRET_KEY, algorithm="HS256")

        def jwt_validation_function(token, secret_key):
            try:
                decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
                return decoded["name"]
            except jwt.ExpiredSignatureError:
                return None
            except jwt.InvalidTokenError:
                return None

        manager = JWTManager(validation_function=jwt_validation_function, secret_key=SECRET_KEY)
        self.assertEqual(manager.validate_token(encoded_jwt), 'John Doe')
        self.assertIsNone(manager.validate_token('invalid_token'))

if __name__ == '__main__':
    unittest.main()
