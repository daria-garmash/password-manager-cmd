from exceptions.invalid_input import InvalidInputException

class InvalidLengthException(InvalidInputException):
    def __init__(self, message):
        super().__init__(message)