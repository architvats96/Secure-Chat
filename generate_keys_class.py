import json
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256, HMAC
import json


class generate_keys():
    def keys_for_exchange(self,pub_key,passwd):
        DHSK_encode = json.dumps(pub_key)
        DHSK = DHSK_encode.encode() # DH returns a fixed length shared secret of 32 byte
        user_secret = passwd # User secret selected from the dictionary
        hmac = HMAC.new(user_secret, DHSK, digestmod = SHA256)
        self.__enc_key = hmac.digest() #Note we use the bytes object not the hex value for the key.

        hash = SHA256.new()
        hash.update(self.__enc_key)
        self.__iv = hash.digest()[:16] # The IV is a fixed length of 16 bytes. This notation fetchs bytes 0-15 (16 in total)[List slicing]
        hash.update(self.__iv)
        self.__hmac_key = hash.digest()
        hash.update(self.__hmac_key)
        self.__chap_secret = hash.digest()

    def encryption_key(self):
        return self.__enc_key
    def iv_for_encryption(self):
        return self.__iv
    def hmac_key_encryption(self):
        return self.__hmac_key
    def chap_key(self):
        return self.__chap_secret


    def encryption_process(self,user_enc_key,iv_key,hmac_key,data):
        cipher = AES.new(user_enc_key, AES.MODE_CBC, iv_key)        # Create new cipher
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))        # Encrypt the data
        ct_HMAC = HMAC.new(hmac_key, ct_bytes, digestmod = SHA256)  # Create new HMAC. Here we pass in the data directly
        ct_hash = ct_HMAC.hexdigest()
        return ct_bytes,ct_hash
    

    def decryption_process(self,enc_key_passed,iv_passed,hmac_passed,encrypted_data,hash_of_data):
        decipher = AES.new(enc_key_passed, AES.MODE_CBC, iv_passed)             # Need a new decryption object
        pt = unpad(decipher.decrypt(encrypted_data), AES.block_size)            # Get the plain text                                  
        verify_HMAC = HMAC.new(hmac_passed, encrypted_data, digestmod = SHA256) # New HMAC object
        try:
            verify_HMAC.verify(hash_of_data)        # Verify excepts if there is an error. 
            return True,pt.decode()
        except Exception as e:
            return False
