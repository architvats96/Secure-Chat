Introduction
This is a chat application which is developed upon a peer to peer architecture. It uses Mutual Challenge Handshake Protocol (CHAP) for authenticating the user. Every message sent with this program is encrypted with a unique key ensuring its stringent security standard.

Requirements
1. Install pycryptodome with the following command. pip install pycryptodome
2. Install pycryptodomex with the following command. pip install pycryptodomex

Steps
1. run new_server_client.py on 2 terminals
2. enter server port 1234 on 1st terminal and username user1 and password 123
3. enter server port 4321 on 2nd terminal and username user3 and password 123
4. enter id 3 on 1st terminal and id 1 on 2nd terminal
5. press enter and start sending messages
6. all pdu's are logged with its username(user3.txt and user1.txt) as filename --->(only server logs the info)
7. all connection requests and socket info are logged in main_file_log.txt

Note: The program has been developed and tested on Linux only.
