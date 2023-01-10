import binascii
import os
import json
import zlib
import base64
from generate_keys_class import generate_keys
from DeffieHellman_class import DeffieHellman
from logging_class import log_data
import datetime


# The below code will generate the deffiehellman public keys and private keys
server_keys = generate_keys()       # key geneartion class which will be used for encryption
server  = DeffieHellman()           # public key and private key generation for sending public keys and geneartion shared secret
server_public_key = server.public_key()
server_private_key = server.private_key()
server_public_key_verification = server.validate_pub_key(server_public_key)

logging_data = log_data() #format of calling log function log(filename,datetime,username,message)

class server_class():
    from_user = ''
    to_user = ''
    def server_f(self,s,in_user,out_user):                          #(-----------------------------Server Function-------------------------)#
        self.from_user = in_user
        self.to_user = out_user

        '''The below while statement will receive data, decode it in utf-8 foramt, load the data using json.loads 
        and then log the received data inside log. Then the json loaded data is sent for a CRC check. In crc check, HAMC check 
        is performed and displays the error accordingly. Then the data is sent to the type_check function which checks the type of message
        and then it will create a pdu and do the next process accordingly. The type_check function returns the pdu and sends it to the other end.'''
        while True:
            data = s.recv(4096)
            if not data: return None
            decode_data = data.decode('utf-8')
            new_decoded_data = decode_data.strip('\n\r')
            decode_dict = json.loads(new_decoded_data)
            new_dict_for_use = dict(decode_dict)
            
            logging_data.log(self.from_user,str(datetime.datetime.utcnow()),self.from_user,f'Received data from {self.to_user}: {new_dict_for_use}')

            if(self.crc_check(decode_dict) is not True):
                send_this_nack_pdu = self.nack_pdu()
                s.send(send_this_nack_pdu.encode())
                print("CRC Error!")
                exit()
            pdu = self.type_check(new_dict_for_use,s)
            
            logging_data.log(self.from_user,str(datetime.datetime.utcnow()),self.from_user,f'Sending data from {self.from_user} to {self.to_user}: {new_dict_for_use}')
            sending_data = json.dumps(pdu)
            s.send(sending_data.encode())
            if(decode_dict['body'] == 'close'):
                print("\nConnection terminated from client's side!!\n")
                s.close()
                exit()            

    '''This function will hava a parameter which will be a dictionary and  then it will calculates pdu's crc and append it 
    to the dictionary and return it'''
    def crc_create(self,pdu_header):
        convert_to_dict = json.loads(pdu_header)
        crc_pdu = zlib.crc32(pdu_header.encode())
        convert_to_dict['header']['crc'] = crc_pdu
        sending_back_pdu = json.dumps(convert_to_dict)
        return sending_back_pdu


    '''This function will check the crc32 and hmac values. receiving the dictionary it will del the crc field and the security field if present 
    and if security present the function will decrypt the and check for the HMAC value and then return the new dictionary after deletion back.'''
    def crc_check(self,pdu_received):
        pdu_crc_check = pdu_received['header']['crc']
        del pdu_received['header']['crc']
        if('security' in pdu_received.keys()):
            global enc_hash
            hash_val = pdu_received['security']['hmac']['val']
            enc_data = hash_val[:-64]
            enc_hash = hash_val[-64:]
            enc_data_bytes = binascii.unhexlify(enc_data)
            enc_hash_bytes = binascii.unhexlify(enc_hash)

            hmac_value_check,plaintext = server_keys.decryption_process(enckey,ivkey,hmkey,enc_data_bytes,enc_hash_bytes)
            if(hmac_value_check is True):
                del pdu_received['security']
            else:
                send_this_nack_pdu = self.nack_pdu()
                return send_this_nack_pdu
        converto_str = json.dumps(pdu_received)
        crc_chk = zlib.crc32(converto_str.encode())

        if(crc_chk == pdu_crc_check):
            return True
        else:
            return False

    '''This function will check for the type of the message and call a function or perform a process accordingly and return the PDU.'''
    def type_check(self,dict_received,s):
        global enckey,ivkey,hmkey,chapkey, shared_secret
        if(dict_received['header']['msg_type'] == 'dh1'):
            with open('server_file.txt') as f:
                data_list = f.readlines()
            new_list = []
            new_dict_for_user_and_pass = {}
            for i in range(len(data_list)):
                data_strip = data_list[i].strip('\n')
                new_json_loads = json.loads(data_strip)
                new_list.append(new_json_loads['username'])
                new_dict_for_user_and_pass[new_json_loads['username']] = new_json_loads['password']

            '''The below if is used to check if the username received from the client is present in the server side's directory. Then it will store the 
            username and password and if username is not matched then it will print the error and then it will verify the public key received from client
            and generate the keys for encryption and then return the PDU back.'''
            if(dict_received['body']['username'] in new_list):
                auth_user = dict_received['body']['username']
                global auth_pass
                auth_pass = new_dict_for_user_and_pass[auth_user]
                if(server_public_key_verification is True):
                    received_client_pub_key = dict_received['body']['key']
                    shared_secret = server.generate_shared_secret(received_client_pub_key)
                    create_pdu = {'header': {'msg_type' : 'dh2','timestamp':str(datetime.datetime.utcnow())},
                                'body': {'key':server_public_key}}
                    server_keys.keys_for_exchange(shared_secret,auth_pass.encode())
                    enckey = server_keys.encryption_key()   
                    ivkey = server_keys.iv_for_encryption()
                    hmkey = server_keys.hmac_key_encryption()
                    chapkey = server_keys.chap_key()
                    crc_of_pdu = self.crc_create(json.dumps(create_pdu))
                    loaded_crc_pdu = json.loads(crc_of_pdu)
                    return loaded_crc_pdu
                else:
                    send_this_nack_pdu = self.nack_pdu()
                    print('Verification Error')
                    return send_this_nack_pdu
            else:
                send_this_nack_pdu = self.nack_pdu()
                print('Username not available on server')
                return send_this_nack_pdu
        elif(dict_received['header']['msg_type'] == 'hello'):
            send_dict_chall = self.hello_challenge_server()
            return send_dict_chall
        elif(dict_received['header']['msg_type'] == 'resp'):
            send_dict_resp = self.response_ack_from_server(dict_received)
            return send_dict_resp
        elif(dict_received['header']['msg_type'] == 'chall'):
            send_dict_chall_resp = self.create_challenge_response_server(dict_received)
            return send_dict_chall_resp
        elif(dict_received['header']['msg_type'] == "ack"):
            return None
        elif(dict_received['header']['msg_type'] == 'text'):
            sending_ack_pdu = self.ack_pdu(dict_received,s)
            return sending_ack_pdu
        elif(dict_received['header']['msg_type'] == 'nack'):
            exit()
        else:
            send_this_nack_pdu = self.nack_pdu()
            print('Message type error')
            return send_this_nack_pdu

    ''''This function will perform the action for hello route from client to server and then create the challenge of random 32 bytes and then
    encrypt the data and bas64 encode it and store the value in the pdu and returns the pdu in serialize format'''
    def hello_challenge_server(self):
        random_number = os.urandom(32)
        random_number_hex = binascii.hexlify(random_number)
        phase2enc,phase2hash = server_keys.encryption_process(enckey,ivkey,hmkey,random_number_hex)
        phase2enc_hex = binascii.hexlify(phase2enc)
        security_hash = phase2enc_hex.decode() + phase2hash
        base64_bytes = base64.b64encode(phase2enc_hex)

        serv_chall_pdu = {'header': {'msg_type' : 'chall','timestamp':str(datetime.datetime.utcnow())},'body': base64_bytes.decode()}
        serv_chall_pdu_dump = json.dumps(serv_chall_pdu)
        crc_pdu = self.crc_create(serv_chall_pdu_dump)

        security_dict = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
        phase2_dict = json.loads(crc_pdu)
        phase2_dict.update(security_dict)
        
        return phase2_dict

    '''This function will create the response received from the client. it will base64 decode the body string and obtain the hmac value 
    after which the decryption part will run.The body data is extracted and hexlify using binascii.We slice the 64 bytes data and get the 
    ending 64 bytes which is our chap secret and then verify it with the server side chap secret.
    '''
    def response_ack_from_server(self,dict):
        body_val = dict['body']
        base64_bytes1 = str(body_val).encode("utf-8")
        sample_string_bytes = base64.b64decode(base64_bytes1)
        decode_string = sample_string_bytes.decode()
        enc_data_bytes = binascii.unhexlify(decode_string)
        enc_hash_bytes = binascii.unhexlify(enc_hash)
        hash_text,plain_text = server_keys.decryption_process(enckey,ivkey,hmkey,enc_data_bytes,enc_hash_bytes)
        
        chapkey_hex = binascii.hexlify(chapkey)
        if(plain_text[64:] == chapkey_hex.decode()):
            phase2_pdu = {'header': {'msg_type' : 'ack','timestamp':str(datetime.datetime.utcnow())},
                            'body': None}
            phase2_pdu_serial = json.dumps(phase2_pdu)
            crc_pdu = self.crc_create(phase2_pdu_serial)       #----->contains crc header and now we have to add security header
            
            phase2enc,phase2hash = server_keys.encryption_process(enckey,ivkey,hmkey,crc_pdu.encode())
            phase2enc_hex = binascii.hexlify(phase2enc)
            security_hash = phase2enc_hex.decode() + phase2hash
            security_dict = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
            phase2_dict = json.loads(crc_pdu)
            phase2_dict.update(security_dict)
            return phase2_dict
        else:
            send_this_nack_pdu = self.nack_pdu()
            return send_this_nack_pdu

    '''In this function we will deoced the body string and then decrypt it and concatinate it with the chap secret and perform encryption and bas64 encoding on it '''
    def create_challenge_response_server(self,dict):
        body_val = dict['body']
        base64_bytes1 = str(body_val).encode("utf-8")
        sample_string_bytes = base64.b64decode(base64_bytes1)
        decode_string = sample_string_bytes.decode()
        enc_data_bytes = binascii.unhexlify(decode_string)
        enc_hash_bytes = binascii.unhexlify(enc_hash)
        hash_text,plain_text = server_keys.decryption_process(enckey,ivkey,hmkey,enc_data_bytes,enc_hash_bytes)
        chap_key_hex = binascii.hexlify(chapkey)
        concatenate_with_chap_secret = str(plain_text) + chap_key_hex.decode()

        resp_from_client_enc,resp_from_client_hash = server_keys.encryption_process(enckey,ivkey,hmkey,concatenate_with_chap_secret.encode())
        
        resp_from_client_enc_hex = binascii.hexlify(resp_from_client_enc)
        security_hash = resp_from_client_enc_hex.decode() + resp_from_client_hash
        base64_bytes = base64.b64encode(resp_from_client_enc_hex)

        serv_chall_pdu = {'header': {'msg_type' : 'resp','timestamp':str(datetime.datetime.utcnow())},'body': base64_bytes.decode()}
        serv_chall_pdu_dump = json.dumps(serv_chall_pdu)
        crc_pdu = self.crc_create(serv_chall_pdu_dump)

        security_dict = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
        resp_from_client__dict = json.loads(crc_pdu)
        resp_from_client__dict.update(security_dict)
    
        return resp_from_client__dict

    '''This function will creat an ack pdu and will decrypt the data and base64 decode it. It will show the message and return PDU and 
    the PDU is sent in AES_256ecryption+base64 decoder'''
    def ack_pdu(self,dict,s):
        body_val = dict['body']
        enc_data_bytes = binascii.unhexlify(body_val)
        enc_hash_bytes = binascii.unhexlify(enc_hash)
        hash_text,plain_text = server_keys.decryption_process(enckey,ivkey,hmkey,enc_data_bytes,enc_hash_bytes)
        base64_bytes1 = str(plain_text).encode("utf-8")
        sample_string_bytes = base64.b64decode(base64_bytes1)
        decode_string = sample_string_bytes.decode()
        print(f"\n<- {self.to_user}: {decode_string}")
        if(decode_string == 'close'):
            print("\nConnection Terminated from client's side!!\n")
            s.close()
            exit()
        phase2_pdu = {'header': {'msg_type' : 'ack','timestamp':str(datetime.datetime.utcnow())},
                            'body': None}
        phase2_pdu_serial = json.dumps(phase2_pdu)
        crc_pdu = self.crc_create(phase2_pdu_serial)       #----->contains crc header and now we have to add security header

        phase2enc,phase2hash = server_keys.encryption_process(enckey,ivkey,hmkey,crc_pdu.encode())
        phase2enc_hex = binascii.hexlify(phase2enc)
        security_hash = phase2enc_hex.decode() + phase2hash
        security_dict = {'security':{'hmac':{'type':'SHA256','val':security_hash}}}
        phase2_dict = json.loads(crc_pdu)
        phase2_dict.update(security_dict)
        
        return phase2_dict
    '''This function will return the nack if any error occurs during the message transition and recturna an encrypted  and base63 encoded PDU'''
    def nack_pdu(self):
        nack_pdu = {'header': {'msg_type' : 'nack','timestamp':str(datetime.datetime.utcnow())},
                            'body': None}
        nack_pdu_serial = json.dumps(nack_pdu)
        crc_pdu = self.crc_create(nack_pdu_serial)
        crc_pdu_serial = json.loads(crc_pdu)
        nackpduenc,nackpduhash = server_keys.encryption_process(enckey,ivkey,hmkey,crc_pdu.encode())
        nackpdu_hex = nackpduenc
        nack_hmac = str(binascii.hexlify(nackpdu_hex).decode()) + str(nackpduhash)
        nack_hmac_b64 = base64.b64decode(nack_hmac)
        nack_dict = {'security':{'hmac':{'type':'SHA256','val':binascii.hexlify(nack_hmac_b64)}}}
        crc_pdu_serial.update(nack_dict)
        crc_pdu_send = json.dumps(crc_pdu_serial)
        return crc_pdu_send