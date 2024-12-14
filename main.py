from typing import List, Any

import pyfiglet
import pyperclip3
import sqlite3
import os
from argon2 import PasswordHasher, exceptions
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Create a PasswordHasher instance
ph = PasswordHasher()

test_storage = []
local_creds = {}

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
    decryptor = cipher.decryptor()
    encryptor = cipher.encryptor()

    while True:
        print_options()
        option = input("Enter option number: ")
        match option:
            case "0": break
            case "3": add(sqlite_connection, cursor, encryptor)
            case "4": get_all_creds(cursor)
            case "5": get_password_by_name(cursor, decryptor)
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
    #print("1 - Authenticate")
    #print("2 - Get available options")
    print("3 - Add new password")
    print("4 - Get available credentials")
    print("5 - Copy password to clipboard")

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
    while True:
        master_password = input("\nEnter master password to the password manager: ")
        try:
            ph.verify(output_pass, master_password)
            break
        except exceptions.VerifyMismatchError as e:
            print("Wrong password!")
    key = derive_key(master_password.encode(), output_salt)
    return [key, output_salt]

def add(connection, cursor, encryptor):

    entry_name = input("Name for the new entry (short and easy to type): ")
    description = input("Description (optional): ")
    url = input("URL (optional): ")
    username = input("Username: ")
    password = input("Password: ")

    print("Please confirm save")
    option = input("1 - save and go back or 0 - go back without saving")
    if option == 0:
        return
    elif option == 1:
        cipher_pass = encryptor.update(password.encode()) + encryptor.finalize()

        with open("./sql-scripts/insert-entries.sql", "r") as file:
            query = file.read()
        cursor.execute(query, (entry_name, description, url, username, cipher_pass))
        connection.commit()
    #test_storage.append(entry)

def get_all_creds(cursor):
    #print(test_storage)
    with open("./sql-scripts/select-entries-all.sql", "r") as file:
        query = file.read()
    cursor.execute(query)
    output = cursor.fetchall()
    print("--------------------------------------------------------")
    print("| Name | Description | URL | Username")
    print("--------------------------------------------------------")
    for row in output:
        print(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]}")
    print("--------------------------------------------------------")

def register_new_user(cursor, connection):
    while True:
        master_password = input("Create master password for your account: ")
        master_password_confirm = input("Confirm master password for your account: ")
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

def get_password_by_name(cursor, decryptor):
    print("Note: if you are not sure about the name check option 4 in the main menu")
    name = input("Please enter name of the credentials or '0' to go back: ")
    if name != '0':
        #logic to get the entry by name
        with open("./sql-scripts/select-password-from-entries-by-name.sql", "r") as file:
            query = file.read()
        cursor.execute(query, (name,))
        db_password = cursor.fetchone()[0]
        password = decryptor.update(db_password) + decryptor.finalize()
        password = password.decode()
        pyperclip3.copy(password)
        print("Your password was copied to clipboard!")


if __name__ == "__main__":
    main()