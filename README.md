# Introduction
This is a chat application which is developed upon a peer to peer architecture. It uses Mutual Challenge Handshake Protocol (CHAP) for authenticating the user. Every message sent with this program is encrypted with a unique key ensuring its stringent security standard.

# Requirements
1. Install pycryptodome with the following command. pip install pycryptodome
2. Install pycryptodomex with the following command. pip install pycryptodomex

# Steps
1. Run new_server_client.py on two terminals
2. On terminal 1, connect to port 1234 and login with the credentials user1:123
3. On terminal 2, connect to port 4321 and login with the credentials user3:123
4. On terminal 1, connect to user3 by entering id as 3. Similarly, on terminal 2, connect to user1 by entering id as 1
5. Press enter and start sending messages
6. All PDU's are logged with its username(user3.txt and user1.txt) as filename --->(only server logs the info)
7. All connection requests and socket info are logged in Logs/main_file_log.txt

# Visual Demonstration
[Demonstration.webm](https://user-images.githubusercontent.com/43727792/211549176-c4b5a9e4-9f95-45f0-bf45-6b53ca248885.webm)


Note: The program has been developed and tested on Linux only.
