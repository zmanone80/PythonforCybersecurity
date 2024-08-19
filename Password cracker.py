from passlib.hash import sha256_crypt

# Load our password attempts and our hashed values
shadow_file = 'new_shadow.txt'
password_list = 'new_password.txt'

# Create a function that will crack passwords
def crack_password(shadow_file, password_list):
    with open(shadow_file, 'r') as sf, open(password_list, 'r') as pl:
        shadow_lines = sf.readlines()
        passwords = pl.readlines()

        for shadow_line in shadow_lines:
            username, hashed_password = shadow_line.split(':')[0], shadow_line.split(':')[1].strip()
            print(f'Checking for user: {username}')
            for password in passwords:
                password = password.strip()  # Fix the variable name from passwords to password
                print(f"Trying password: {password}")
                if sha256_crypt.verify(password, hashed_password):  # Fix syntax from [] to ()
                    print(f"Password for {username} found: {password}")
                    break

# Call the function
crack_password(shadow_file, password_list)
          