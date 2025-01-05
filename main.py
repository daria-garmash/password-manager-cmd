import random
import re
import string
import sys
from typing import List, Any
import pyfiglet
import maskpass
import pyperclip3
import sqlite3
import os
from argon2 import PasswordHasher, exceptions
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from exceptions.invalid_id import InvalidIdException
#custom exceptions
from exceptions.invalid_input import InvalidInputException
from exceptions.invalid_length import InvalidLengthException
from exceptions.invalid_password import InvalidPasswordException

# Create a PasswordHasher instance
ph = PasswordHasher()

def main():
    art = pyfiglet.figlet_format("T e r m i n a l  V a u l t", font = "slant", width = 500)
    print(art)

    #db
    sqlite_connection = sqlite3.connect('password_manager.db')
    cursor = sqlite_connection.cursor()
    print('DB Init')
    if not check_db_connection(cursor): print("Something's wrong with your db connection")

    db_setup(cursor)
    auth_result = auth(cursor, sqlite_connection)

    #encryption
    key = auth_result[0]
    salt = auth_result[1]
    cipher = Cipher(algorithms.AES(key), modes.CFB(salt))

    while True:
        print_options()
        option = input("Enter option number: ")
        match option:
            case "0": break
            case "1": add(sqlite_connection, cursor, cipher)
            case "2": get_all_creds(cursor)
            case "3": get_password_by_id( cursor, cipher)
            case "4":
                update_password_by_id(cursor, cipher)
                sqlite_connection.commit()
            case "5":
                delete_password_by_id(cursor)
                sqlite_connection.commit()
            case _: print("Unknown option")

    if sqlite_connection:
        sqlite_connection.commit()
        sqlite_connection.close()
        print('SQLite Connection closed')

def check_db_connection(cursor):
    try:
        query = 'select sqlite_version();'
        cursor.execute(query)
        result = cursor.fetchall()
        print('SQLite Version is {}'.format(result))
    except sqlite3.Error as error:
        print('Error occurred - ', error)
        return False
    return True

def db_setup(cursor):
    sql_file = "./sql-scripts/setup.sql"  # Path to your .sql file
    with open(sql_file, "r") as file:
        sql_script = file.read()
    try:
        cursor.executescript(sql_script)
        print("Tables created successfully!")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def print_options():
    print("Available options:")
    print("0 - Exit")
    print("1 - Add new password")
    print("2 - Get available credentials")
    print("3 - Copy password to clipboard")
    print("4 - Update password")
    print("5 - Delete password")

def auth(cursor, connection) -> list[bytes | Any]:
    #Check if local user exists
    with open("./sql-scripts/select-password-salt-from-users-by-name.sql", "r") as file:
       query = file.read()

    cursor.execute(query)
    output = cursor.fetchone()
    if output is None:
        print("\nLooks like you don't have a master password set up.")
        register_new_user(cursor, connection)
        cursor.execute(query)
        output = cursor.fetchone()

   # print(output)
    output_pass = output[0]
    output_salt = output[1]
    count = 0
    while True:
        if count > 5:
            print("You've reached the threshold of 5 incorrect attempts. The program will now terminate.")
            sys.exit()
        master_password = maskpass.askpass(prompt="\nEnter master password to the password manager: ", mask="*")
        try:
            ph.verify(output_pass, master_password)
            break
        except exceptions.VerifyMismatchError as e:
            print("Wrong password!")
            count = count + 1
    key = derive_key(master_password.encode(), output_salt)
    return [key, output_salt]

def add(connection, cursor, cipher):
    encryptor = cipher.encryptor()
    entry_name = input("Name for the new entry (short and easy to type): ")
    description = input("Description (optional): ")
    url = input("URL (optional): ")
    username = input("Username: ")
    option = input("To generate a secure random password string press 'G'. Press 'Enter' to continue with your custom passwords: " )
    if option.capitalize() == "G":
        password = ask_generate_password()
    else:
        password = maskpass.askpass(prompt="Password: ", mask="*")

    print("Please confirm save")
    option = input("1 - save and go back or 0 - go back without saving: ")
    if option == "0":
        return
    elif option == "1":
        cipher_pass = encryptor.update(password.encode()) + encryptor.finalize()

        with open("./sql-scripts/insert-entries.sql", "r") as file:
            query = file.read()
        cursor.execute(query, (entry_name, description, url, username, cipher_pass))
        connection.commit()

def get_all_creds(cursor):

    with open("./sql-scripts/select-entries-all.sql", "r") as file:
        query = file.read()
    cursor.execute(query)
    output = cursor.fetchall()
    print("--------------------------------------------------------")
    print("| ID | Name | Description | URL | Username")
    print("--------------------------------------------------------")
    for row in output:
        print(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} |")
    print("--------------------------------------------------------")

def register_new_user(cursor, connection):
    while True:
        master_password = maskpass.askpass(prompt="Create master password for your account: ", mask="*")
        master_password_confirm = maskpass.askpass(prompt="Confirm master password for your account: ",  mask="*")
        if master_password == master_password_confirm:
            break
        else:
            print("Passwords should match! Try again...")
    passw_hash = ph.hash(master_password)  #Adds random salt
    username = "local_user"
    salt = os.urandom(16)
    saltEncr = os.urandom(16) #separate salt for password encryption to be saved to db

    with open("./sql-scripts/insert-users.sql", "r") as file:
        query = file.read()
    cursor.execute(query, (username, passw_hash, saltEncr))
    print("Account was created successfully!")
    connection.commit()

    return derive_key(master_password.encode(), salt)

def derive_key(password, salt):
    key_length = 32
    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=2 ** 15,
        parallelism=4,
        hash_len=key_length,  #
        type=Type.ID
    )
    return key

def get_password_by_id(cursor, cipher):

    decryptor = cipher.decryptor()
    print("\nNote: if you are not sure about the ID check option 2 in the main menu")
    cred_id = input("Please enter id of the credentials or '0' to go back: ")
    if cred_id != '0':
        try:
            account_name = get_credentials_name(cursor, cred_id)
            with open("sql-scripts/select-password-from-entries-by-id.sql", "r") as file:
                query = file.read()
            cursor.execute(query, (cred_id,))
            db_password = cursor.fetchone()[0]
            password = decryptor.update(db_password) + decryptor.finalize()
            password = password.decode()
            pyperclip3.copy(password)
            print(f"Your {account_name} password was copied to clipboard!")
        except InvalidInputException as e:
            print(f"Invalid input: {e}")

def update_password_by_id(cursor, cipher):

    encryptor = cipher.encryptor()
    print("\nNote: if you are not sure about the id check option 2 in the main menu")
    cred_id = input("Please enter id of the credentials or '0' to go back: ")
    if cred_id != '0':
        try:
            account_name = get_credentials_name(cursor, cred_id)
            option = input("To generate a new secure random password string press 'G'. Press 'Enter' to continue with your custom password: ")
            if option.capitalize() == "G":
                new_password = ask_generate_password()
            else:
                new_password = maskpass.askpass(prompt=str.format("Create new password for {}: ", account_name), mask="*")
            cipher_pass = encryptor.update(new_password.encode()) + encryptor.finalize()
            with open("./sql-scripts/update-password-in-entries.sql", "r") as file:
                query = file.read()
            cursor.execute(query, (cipher_pass, cred_id))
            print(f"Your {account_name} password was updated successfully!")
        except InvalidInputException as e:
            print(f"Invalid input: {e}")


def delete_password_by_id(cursor):
    print("\nNote: if you are not sure about the id check option 2 in the main menu")
    cred_id = input("Please enter id of the credentials or '0' to go back: ")
    if cred_id != '0':
        try:
            account_name = get_credentials_name(cursor, cred_id)
            print(f"You are deleting your {account_name} password.")
            option = input("Please enter 'Y' to proceed or 'N' to go back: ")
            if option.capitalize() == "N":
                return
            elif option.capitalize() == "Y":
                with open("./sql-scripts/delete-entry-by-id.sql", "r") as file:
                    query = file.read()
                cursor.execute(query,(cred_id,))
                print("Your password was deleted successfully!")
        except InvalidInputException as e:
            print(f"Invalid input: {e}")

def get_credentials_name(cursor, cred_id):
    with open("./sql-scripts/select-account-name-by-id.sql", "r") as file:
        query = file.read()
    cursor.execute(query, (cred_id,))
    if cursor.rowcount <= 0:
        raise InvalidIdException(f"ID {cred_id} was not found. Please check option 2 to get the ID you need.")
    account_name = cursor.fetchone()[0]
    return account_name

def ask_generate_password():
    print("You opted to generate a secure random password.")
    while True:
        try:
            length = input("Enter the desired length of the password between 8 and 24 or leave blank for the default length of 11 characters: ")
            if length == "":
                length = 11
                break
            if all(char.isdigit() for char in length) and 8 <= int(length) <= 24:
                length = int(length)
                break
            else:
                raise InvalidLengthException("Length must be a number between 8 and 24")
        except InvalidInputException as e:
            print(f"Invalid input: {e}")
    return generate_password(length)

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''
    correct = 0
    while correct == 0:
        password = ''.join(random.choice(characters) for i in range(length))
        try :
            validate_password(password, length)
            correct = 1
        except InvalidInputException as e:
            correct = 0
    return password

def validate_password(password, length = 11):
    if len(password) < length :
        raise InvalidPasswordException(f"Password must be {length} characters long")
    if not any(char.isupper() for char in password):
        raise InvalidPasswordException("Password must contain at least one uppercase character")
    if not any(char.islower() for char in password):
        raise InvalidPasswordException("Password must contain at least one lowercase character")
    if not any(char.isdigit() for char in password):
        raise InvalidPasswordException("Password must contain at least one number")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise InvalidPasswordException("Password must contain at least one special character")


if __name__ == "__main__":
    main()