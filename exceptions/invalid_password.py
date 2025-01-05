from exceptions.invalid_input import InvalidInputException

class InvalidPasswordException(InvalidInputException):
    def __init__(self, message):
        super().__init__(message)