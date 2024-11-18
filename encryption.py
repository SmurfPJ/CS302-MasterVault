from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64



SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000



def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + (chr(pad_len) * pad_len).encode()

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def derive_key(salt):
    passphrase = "mfyrrjSuP97KXU9vxtc7M2FdDbfqU9LZgzVHFPsxGqYZgJi4jgB8xURi56SV6AlE"
    return PBKDF2(passphrase, salt, dkLen=KEY_SIZE, count=ITERATIONS)


def encrypt(plaintext):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(salt)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode()))
    return base64.b64encode(salt + iv + ciphertext).decode('utf-8')

def decrypt(ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    salt = ciphertext[:SALT_SIZE]
    iv = ciphertext[SALT_SIZE:SALT_SIZE+16]
    encrypted_data = ciphertext[SALT_SIZE+16:]
    key = derive_key(salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(encrypted_data))
    return plaintext.decode('utf-8')


# from pymongo import MongoClient
# from bson.objectid import ObjectId


# client = MongoClient('mongodb+srv://Conor:M0ng0DB1@mastervaultdb1.g1a7o98.mongodb.net/')
# db = client.MasterVault
# userData = db["userData"]
# userPasswords = db["userPasswords"]
# familyData = db["familyData"]

# def main():

#     docID = '670c5affe8916d09773ebcb0'
    # familyData.update_one({"familyID": 1}, {"$set": {"member1": '66a6f5614607d5f3fae7b3fa'}})
    # print(familyData.find_one({"_id": ObjectId('670c5affe8916d09773ebcb0')}))

    # userPasswords.update_one({"_id": sessionID}, { "$unset": { "username1": "" }})

    print(userPasswords.find_one({"_id": ObjectId('6729665217c3489ff7992026')}))

    # plainText = input("Password: ")

    # encrypted = encrypt(plainText)
    # print("Encrypted: ", encrypted)

    # decrypted = decrypt(encrypted)
    # print("Decrypted: ", decrypted)

# main()