###############################################################################
# Name: ChatServer.py                                                         #
# Author: Kit Cischke (original), John Mortimore                              #
# Original: 02/12/2020                                                        #
# Modified: 02/15/2020                                                        #
#                                                                             #
# Socket based chat server that communicates with clients (ChatClient.py)     #
# using Electronic Code Book Encryption.                                      #
###############################################################################

import socket
import select
from Crypto.Cipher import AES
from base64 import b64decode
from base64 import b64encode

HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234
KEY = 'EE82E70D5C71E0D0C79F545FC85506E2'
BLOCK_SIZE = AES.block_size 

###############################################################################
# Func: encrypt_message                                                       #
# Desc: Encrypts a message to be send via socket.                             #
# Args: message - The message to encrypt.                                     #
# Retn: Base 64 encoded byte string of the encrypted message.                 #
###############################################################################
def encrypt_message(message):
	diff = BLOCK_SIZE - (len(message) % BLOCK_SIZE)
	message += ' ' * diff
	enc_message = cipher.encrypt(message)
	return b64encode(enc_message)


###############################################################################
# Func: receive_message                                                       #
# Desc: Handles message receiving.                                            #
# Args: client_socket - The socket to receive from.                           #
# Retn: Packet header and message.                                            #
###############################################################################
def receive_message(client_socket):
	try:
		# Receive the packet.
		enc_packet = client_socket.recv(2048)

		# If client gracefully closed a connection:
		if not len(enc_packet):
			return False

		# Decrypt the packet.
		packet = cipher.decrypt(b64decode(enc_packet))

		# Extrace the header and payload.
		packet_header = packet[0:HEADER_LENGTH]
		payload_length = int(packet_header.decode('utf-8').strip())
		payload = packet[HEADER_LENGTH:HEADER_LENGTH+payload_length]

		# Return an object of message header and message data.
		return {'header': packet_header, 'data': payload}

	except:
		# If client closed connection violently.
		return False

###############################################################################
cipher = AES.new(KEY, AES.MODE_ECB) # Create cipher.

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((IP, PORT))
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# List of connected clients - socket as a key, user header and name as data.
clients = {}

print(f'Listening for connections on {IP}:{PORT}...')

while True:

	read_sockets, _, exception_sockets = select.select(sockets_list, [],
		sockets_list)

	# Iterate over notified sockets:
	for notified_socket in read_sockets:
		# If notified socket is a server socket, accept new connection.
		if notified_socket == server_socket:

			# Accept new connection.
			client_socket, client_address = server_socket.accept()

			# Client should send his name right away, receive it.
			user = receive_message(client_socket)

			# If False - client disconnected before he sent his name.
			if user is False:
				continue

			# Add accepted socket to select.select() list.
			sockets_list.append(client_socket)

			# Also save username and username header.
			clients[client_socket] = user

			print('Accepted new connection from {}:{}, username: {}'
				.format(*client_address, user['data'].decode('utf-8')))

		# Else existing socket is sending a message:
		else:
			# Receive message.
			message = receive_message(notified_socket)

			# If False, client disconnected, cleanup.
			if message is False:
				print('Closed connection from: {}'
					.format(clients[notified_socket]['data'].decode('utf-8')))

				# Remove from list for socket.socket().
				sockets_list.remove(notified_socket)

				# Remove from list of users.
				del clients[notified_socket]

				continue

			# Get user by notified socket to know who sent the message.
			user = clients[notified_socket]

			print(f'Received message from'
				+ f' {user["data"].decode("utf-8")}:'
				+ f' {message["data"].decode("utf-8")}')

			# Iterate over connected clients and broadcast message:
			for client_socket in clients:

				# But don't sent it to sender.
				if client_socket != notified_socket:

					# Send user and message (both with headers).
					client_socket.send(encrypt_message(str(user['header']
						+ user['data'] + message['header']
						+ message['data'], 'utf-8')))

	# It's not really necessary to have this, but will handle some socket 
	# exceptions just in case.
	for notified_socket in exception_sockets:

		# Remove from list for socket.socket().
		sockets_list.remove(notified_socket)

		# Remove from our list of users.
		del clients[notified_socket]
