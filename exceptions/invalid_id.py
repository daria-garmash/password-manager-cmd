from exceptions.invalid_input import InvalidInputException

class InvalidIdException(InvalidInputException):
    def __init__(self, message):
        super().__init__(message)