# importin the necessary packages
import json
import select
import socket
import sys
from server import server_class
from client import client_class
import datetime
from logging_class import log_data

logging_data = log_data()                   #calling the logging file class object

date_time = str(datetime.datetime.utcnow()) #getting the current data, time and year

# user inputs the required data as lport, username and password
lport = int(input("Server PORT (e.g. 1234 or 4321): "))
username = input('\nEnter your username (e.g. user1 or user3): ')
password = input('Enter your Password (e.g. 123): ')

# Creating socket and binding it to the mentioned ip and lport and listening on it
socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = "127.0.0.1"
socks.bind((ip, lport))
socks.listen(1)
print(f'\nSocket listening on {ip} and port {lport}')

# logging the data
logging_data.log('main_file',str(datetime.datetime.utcnow()),username,f'Socket listening on {ip} and port {lport}')

inputs = [socks, sys.stdin]

# creating server class and client class objects
server_obj = server_class()
client_obj = client_class()

# opening the file name to show the user to which endpoint it wants to connect
with open('Credentials/client_file.txt') as f:
    dataread = f.readlines()

counter = 0
ip_lst = []
port_lst = []
other_lst = []
for i in range(len(dataread)):
    data = dataread[i].strip('\n')
    print('')
    data_serial = json.loads(data)
    data_serial['id'] = counter
    counter = counter + 1
    ip_lst.append(data_serial['ip'])
    port_lst.append(data_serial['port'])
    other_lst.append(data_serial['username'])
    print(data_serial)

# according to user_input the rport, username and password will be selected
user_in = input("\nEnter id of the user you want to connect: (e.g. 3 or 1): ")
user_data = int(user_in)

rport = port_lst[user_data]
rhost = ip_lst[user_data]
other_username = other_lst[user_data]

# logging the data
logging_data.log('main_file',str(datetime.datetime.utcnow()),username,f'Connected to {rhost} on {rport}')

'''Below code implements the select.select statement which sets the the program in a non-blocking state. 
Readable takes two inputs i.e. socket object and system input. If there is an system input 
the program will act as a client and send the incoming data to other user else it will act as a server and 
wait for the incoming data. The timeout parameter of the select.select will wait for that period of time and 
if data is not received then it will close the connection.'''

while True:
    print("\nNow in listening mode... press ENTER to input")
    readable, writable, exceptional = select.select(inputs, [], [],25)
    if socks in readable:
        conn, addr = socks.accept()
        server_obj.server_f(conn,username,other_username)
        conn.close()
    
    if sys.stdin in readable:
        input()
        message = input(f'-> {username}: ')
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((rhost,rport))
        client_obj.client_f(client,message,username,password,other_username)
        client.close()

    if not (readable or writable or exceptional):
        print('\nNo input from Client...closing connection!!\n')
        exit()
