import os
import sys
import hashlib

class DiffieHellman():
    def __init__(self):
        self.__prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.__gen = 2

        self.__priv_key = int.from_bytes(os.urandom(32), byteorder=sys.byteorder, signed=False) #passing random 32 bits integer
        self.__pub_key = pow(self.__gen, self.__priv_key, self.__prime)
        self.__shared_secret = 0

    def private_key(self):
        return self.__priv_key
    def public_key(self):
        return self.__pub_key
    def shared_secret(self):
        return self.__shared_secret

    def validate_pub_key(self, pub_key):
        if (pub_key == None):
            pub_key = self.public_key()
        if (2 <= pub_key and pub_key <= self.__prime - 2):
            if (pow(pub_key, (self.__prime - 1) // 2, self.__prime) == 1):
                return True
        return False

    def generate_shared_secret(self, public_key_of_sender):
        ''' Generates a shared secret with someone else '''
        if (self.validate_pub_key(public_key_of_sender)):
            shared_key = pow(public_key_of_sender, self.__priv_key, self.__prime)
            shared_key_length = shared_key.bit_length()            
            offset = shared_key_length % 8
            if (offset != 0):
                offset = 8 - offset
            shared_key_length += offset    
            shared_key_length = int(shared_key_length/8)
            ss_key_bytes = shared_key.to_bytes(int(shared_key_length), sys.byteorder)

            self.__shared_secret = hashlib.sha256(ss_key_bytes).digest()
            self.__shared_secret = int.from_bytes(self.__shared_secret,sys.byteorder)
            return self.__shared_secret
        else:
            raise Exception("Bad public key from the other party")
