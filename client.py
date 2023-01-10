import base64
import binascii
import os
import json
import time
import zlib
import datetime

from DeffieHellman_class import DeffieHellman
from generate_keys_class import generate_keys

# The below code will generate the deffiehellman public keys and private keys
client = DeffieHellman()                # key geneartion class which will be used for encryption
client_keys = generate_keys()           # public key and private key generation for sending public keys and geneartion shared secret
client_private_key = client.private_key()
client_public_key = client.public_key()
client_validate_public_key = client.validate_pub_key(client_public_key)



class client_class():    
    auth_user = ''
    auth_pass = ''
    opp_client = ''

    def client_f(self,socks,msg,user,passwd,other_user):    
        self.auth_user = user
        self.auth_pass = passwd                         #(-----------------------------Client Function-------------------------)#
        self.opp_client = other_user

        if(msg != ''):
            pdu = self.phase1() #--------------->function call
            json_serialize = json.dumps(pdu)
            send_pdu = self.crc_create(json_serialize)
            socks.send(send_pdu.encode())#--------------->sending the data to the other end
            
            data = socks.recv(2048)#---------------> Receiving the data from server
            data_received = data.decode('utf-8')
            data_recv = json.loads(data_received)   #--------------->loading the the serialize data as dict

            if(self.crc_check(data_recv) is True):#---------------> crc checking function returns True or False
                if(data_recv['header']['msg_type'] == 'dh2'):
                    server_public_key = data_recv['body']['key']
                    global shared_secret
                    shared_secret = client.generate_shared_secret(server_public_key)

                    client_keys.keys_for_exchange(shared_secret,(self.auth_pass).encode()) #---------------> generating keys with the help of shared secret and password
                    global enckey,ivkey,hmkey,chapkey
                    enckey = client_keys.encryption_key()   
                    ivkey = client_keys.iv_for_encryption()
                    hmkey = client_keys.hmac_key_encryption()
                    chapkey = client_keys.chap_key()

                    pdu_sending = self.phase2() #--------------->phase2 function call
                    socks.send(pdu_sending.encode())

                    data = socks.recv(2048)
                    if data:
                        decode_data = data.decode('utf-8')  #--------------->received data is decoded into strings
                        decode_dict = json.loads(decode_data)
                        new_dict_for_use = dict(decode_dict)

                        if(self.crc_check(decode_dict) is not True):    #--------------->CRC CHECK
                            send_this_nack_pdu = self.nack_pdu()
                            socks.send(send_this_nack_pdu.encode())
                        else:
                            if(new_dict_for_use['header']['msg_type'] == 'chall'):
                                self.create_challenge_response_client(new_dict_for_use,socks)   #--------------->function call
                                data = socks.recv(2048)
                                if data:
                                    decode_data = data.decode('utf-8')
                                    decode_dict = json.loads(decode_data)
                                    new_dict_for_use = dict(decode_dict)

                                    if(self.crc_check(decode_dict) is not True):
                                        send_this_nack_pdu = self.nack_pdu()
                                        socks.send(send_this_nack_pdu.encode())
                                    else:
                                        self.hello_challenge_client(socks)  #--------------->function call
                                        data = socks.recv(2048)
                                        if data:
                                            decode_data = data.decode('utf-8')
                                            decode_dict = json.loads(decode_data)
                                            new_dict_for_use = dict(decode_dict)
                                            
                                            if(self.crc_check(decode_dict) is not True):    #--------------->function call
                                                send_this_nack_pdu = self.nack_pdu()
                                                socks.send(send_this_nack_pdu.encode())
                                            else:
                                                send_pdu = self.response_ack_from_client(socks,new_dict_for_use)    #--------------->function call
                                                socks.send(send_pdu.encode())
                                                data = socks.recv(2048)
                                                
                                                if(data is None):
                                                    sending_pdu = self.create_pdu_for_message(msg)  #--------------->function call
                                                    socks.send(sending_pdu.encode())
                                                    
                                                    if(msg == 'close'):
                                                        print("\nConnection Terminated!!\n")
                                                        time.sleep(0.5)
                                                        socks.close()
                                                        exit()
                                                    data = socks.recv(2048)
                                                    if data:
                                                        decode_data = data.decode('utf-8')
                                                        decode_dict = json.loads(decode_data)
                                                        new_dict_for_use = dict(decode_dict)
                                                        
                                                        if(self.crc_check(decode_dict) is not True):
                                                            send_this_nack_pdu = self.nack_pdu()    #--------------->function call
                                                            socks.send(send_this_nack_pdu.encode())

                            else:
                                send_this_nack_pdu = self.nack_pdu()
                                socks.send(send_this_nack_pdu.encode())
                else:
                    send_this_nack_pdu = self.nack_pdu()
                    socks.send(send_this_nack_pdu.encode())

        if msg != '':                                      
            sending_pdu = self.create_pdu_for_message(msg)  #--------------->function call
            socks.send(sending_pdu.encode())
            
            if(msg == 'close'):
                print("\nConnection Terminated!!\n")
                time.sleep(0.5)
                socks.close()
                exit()
            data = socks.recv(2048)
            if data:
                decode_data = data.decode('utf-8')
                decode_dict = json.loads(decode_data)
                new_dict_for_use = dict(decode_dict)
                
                if(self.crc_check(decode_dict) is not True):    #--------------->function call
                    send_this_nack_pdu = self.nack_pdu()
                    socks.send(send_this_nack_pdu.encode())
    

    
    '''crc_create function  take a serialize dict and then ccalculates the crc of the recived dict and then store it in the dict and return the dict'''
    def crc_create(self,pdu_header):
        
        convert_to_dict = json.loads(pdu_header)
        crc_pdu = zlib.crc32(pdu_header.encode())
        convert_to_dict['header']['crc'] = crc_pdu
        sending_pdu_back = json.dumps(convert_to_dict)
        return sending_pdu_back

    
    '''crc_check function take dict and removes the crc heder after storing its value in a variable and then calculates the crc of the PDu and if security field is present in the dic then 
    performs the hmac verification and decryption of the conatinated value received from the other end and returns True or False'''
    def crc_check(self,pdu_received):
        
        global enc_hash
        pdu_crc_check = pdu_received['header']['crc']
        if('security' in pdu_received.keys()):
            hash_val = pdu_received['security']['hmac']['val']
            enc_data = hash_val[:-64]
            enc_hash = hash_val[-64:]
            enc_data_bytes = binascii.unhexlify(enc_data)
            enc_hash_bytes = binascii.unhexlify(enc_hash)
            hmac_value_check,plaintext = client_keys.decryption_process(enckey,ivkey,hmkey,enc_data_bytes,enc_hash_bytes)
            if(hmac_value_check is True):
                del pdu_received['security']
            else:
                send_this_nack_pdu = self.nack_pdu()
                return send_this_nack_pdu
        del pdu_received['header']['crc']
        converted = json.dumps(pdu_received)
        
        crc_chk = zlib.crc32(converted.encode())
        if(crc_chk == pdu_crc_check):
            return True
        else:
            return False        

    '''simple function, just creates the pdu and returs the pdu back'''
    def phase1(self):
        
        if(client_validate_public_key is True):
            
            pdu = {'header': {'msg_type' : 'dh1','timestamp':str(datetime.datetime.utcnow())},
                            'body': {'key':client_public_key,'username':(self.auth_user)}}
        return pdu
    '''phase2 sends an hello from client to server to get a challenge from the server'''
    def phase2(self):
        phase2_pdu = {'header': {'msg_type' : 'hello','timestamp':str(datetime.datetime.utcnow())},
                            'body': None}
        phase2_pdu_serial = json.dumps(phase2_pdu)
        crc_pdu = self.crc_create(phase2_pdu_serial)       #----->contains crc header and now we have to add security header
        
        phase2enc,phase2hash = client_keys.encryption_process(enckey,ivkey,hmkey,crc_pdu.encode())
        phase2enc_hex = binascii.hexlify(phase2enc)
        security_hash = phase2enc_hex.decode() + phase2hash
        security_dict = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
        phase2_dict = json.loads(crc_pdu)
        phase2_dict.update(security_dict)
        
        phase2_dict_serial = json.dumps(phase2_dict)
        
        return phase2_dict_serial
    
    '''create_challenge_response_client will get challenge and a socket which will then decrypt the data and take the 
    random 32 bytes data and concatenate it wiht the chap secret and sends back to the server'''
    def create_challenge_response_client(self,chall_dict_received,s):
        body_val = chall_dict_received['body']
        base64_bytes1 = str(body_val).encode("utf-8")
        sample_string_bytes = base64.b64decode(base64_bytes1)
        decode_string = sample_string_bytes.decode()
        enc_data_bytes = binascii.unhexlify(decode_string)
        enc_hash_bytes = binascii.unhexlify(enc_hash)
        hash_text,plain_text = client_keys.decryption_process(enckey,ivkey,hmkey,enc_data_bytes,enc_hash_bytes)
        chap_key_hex = binascii.hexlify(chapkey)
        concatenate_with_chap_secret = str(plain_text) + chap_key_hex.decode()

        

        resp_from_client_enc,resp_from_client_hash = client_keys.encryption_process(enckey,ivkey,hmkey,concatenate_with_chap_secret.encode())
        
        resp_from_client_enc_hex = binascii.hexlify(resp_from_client_enc)
        security_hash = resp_from_client_enc_hex.decode() + resp_from_client_hash
        base64_bytes = base64.b64encode(resp_from_client_enc_hex)

        serv_chall_pdu = {'header': {'msg_type' : 'resp','timestamp':str(datetime.datetime.utcnow())},'body': base64_bytes.decode()}
        serv_chall_pdu_dump = json.dumps(serv_chall_pdu)
        crc_pdu = self.crc_create(serv_chall_pdu_dump)
        
        security_dict = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
        resp_from_client__dict = json.loads(crc_pdu)
        resp_from_client__dict.update(security_dict)
        
        resp_from_client__dict_serial = json.dumps(resp_from_client__dict)
        
        s.send(resp_from_client__dict_serial.encode())

    '''function hello challenge client will generate a random 32 byes data for MUTUAL communication and send it to the server with an encrypted and base64encoded pdu'''
    def hello_challenge_client(self,s):
        random_number = os.urandom(32)
        random_number_hex = binascii.hexlify(random_number)
        
        phase2enc,phase2hash = client_keys.encryption_process(enckey,ivkey,hmkey,random_number_hex)
        phase2enc_hex = binascii.hexlify(phase2enc)
        security_hash = phase2enc_hex.decode() + phase2hash
        
        base64_bytes = base64.b64encode(phase2enc_hex)

        serv_chall_pdu = {'header': {'msg_type' : 'chall','timestamp':str(datetime.datetime.utcnow())},'body': base64_bytes.decode()}
        serv_chall_pdu_dump = json.dumps(serv_chall_pdu)
        crc_pdu = self.crc_create(serv_chall_pdu_dump)
        
        security_dict = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
        phase2_dict = json.loads(crc_pdu)
        phase2_dict.update(security_dict)
        phase2_dict_serial = json.dumps(phase2_dict)
        
        s.send(phase2_dict_serial.encode())
        

    '''response_ack_from_client function will receive response that will b64decode and decrypted and body will be sliced and checked with the clients chap key and the ack will be generated 
    based on the inputs and then the pdu will be sent securely'''
    def response_ack_from_client(self,s,dict):
        body_val = dict['body']
        base64_bytes1 = str(body_val).encode("utf-8")
        sample_string_bytes = base64.b64decode(base64_bytes1)
        decode_string = sample_string_bytes.decode()
        enc_data_bytes = binascii.unhexlify(decode_string)
        enc_hash_bytes = binascii.unhexlify(enc_hash)
        hash_text,plain_text = client_keys.decryption_process(enckey,ivkey,hmkey,enc_data_bytes,enc_hash_bytes)
        
        chapkey_hex = binascii.hexlify(chapkey)
        if(plain_text[64:] == chapkey_hex.decode()):
            phase2_pdu = {'header': {'msg_type' : 'ack','timestamp':str(datetime.datetime.utcnow())},
                            'body': None}
            phase2_pdu_serial = json.dumps(phase2_pdu)
            crc_pdu = self.crc_create(phase2_pdu_serial)       #----->contains crc header and now we have to add security header
            
            phase2enc,phase2hash = client_keys.encryption_process(enckey,ivkey,hmkey,crc_pdu.encode())
            phase2enc_hex = binascii.hexlify(phase2enc)
            security_hash = phase2enc_hex.decode() + phase2hash
            security_dict = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
            phase2_dict = json.loads(crc_pdu)
            phase2_dict.update(security_dict)
            phase2_dict_serial = json.dumps(phase2_dict)
            return phase2_dict_serial
        else:
            send_this_nack_pdu = self.nack_pdu()
            return send_this_nack_pdu

    '''function to create message pdu that will be sent to the other end securely and pdu is returned'''

    def create_pdu_for_message(self,msg):
        base64encode_str = base64.b64encode(str(msg).encode())
        
        phase2enc,phase2hash = client_keys.encryption_process(enckey,ivkey,hmkey,base64encode_str)
        phase2enc_hex = binascii.hexlify(phase2enc)
        security_hash = phase2enc_hex.decode() + phase2hash
        phase2_pdu = {'header': {'msg_type' : 'text','timestamp':str(datetime.datetime.utcnow())},
                            'body': phase2enc_hex.decode()}
        phase2_pdu_serial = json.dumps(phase2_pdu)
        crc_pdu = self.crc_create(phase2_pdu_serial)       #----->contains crc header and now we have to add security header
        sec_pdu = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
        crc_pdu_dict = json.loads(crc_pdu)
        crc_pdu_dict.update(sec_pdu)
        
        phase2_dict_serial = json.dumps(crc_pdu_dict)
        return phase2_dict_serial
    '''this function will send nack if any error are occurs'''
    def nack_pdu(self):
        nack_pdu = {'header': {'msg_type' : 'nack','timestamp':str(datetime.datetime.utcnow())},
                            'body': None}
        nack_pdu_serial = json.dumps(nack_pdu)
        crc_pdu = self.crc_create(nack_pdu_serial)
        crc_pdu_serial = json.loads(crc_pdu)
        nackpduenc,nackpduhash = client_keys.encryption_process(enckey,ivkey,hmkey,crc_pdu.encode())
        nackpdu_hex = nackpduenc
        nack_hmac = str(binascii.hexlify(nackpdu_hex).decode()) + str(nackpduhash)
        nack_hmac_b64 = base64.b64decode(nack_hmac)
        nack_dict = {'security':{'hmac':{'type':'SHA256','val':binascii.hexlify(nack_hmac_b64)}}}
        crc_pdu_serial.update(nack_dict)
        crc_pdu_send = json.dumps(crc_pdu_serial)
        return crc_pdu_send



