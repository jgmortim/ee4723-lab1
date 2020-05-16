###############################################################################
# Name: ChatClient.py                                                         #
# Author: Kit Cischke (original), John Mortimore                              #
# Original: 02/12/2020                                                        #
# Modified: 02/15/2020                                                        #
#                                                                             #
# Socket based chat client that communicates with a server (ChatServer.py)    #
# using Electronic Code Book Encryption.                                      #
###############################################################################

import socket
import select
import errno
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
my_username = input("Username: ")

cipher = AES.new(KEY, AES.MODE_ECB) # Create cipher.

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT))

# Set connection to non-blocking state, so .recv() call won't block, just
# return some exception that are handled.
client_socket.setblocking(False)

# Count number of bytes and prepare header of fixed size.
username_header = f"{len(my_username):<{HEADER_LENGTH}}"

# Send encrypted header and username to server.
client_socket.send(encrypt_message(username_header + my_username))

while True:
	# Wait for user to input a message.
	message = input(f'{my_username} > ')

	# If message is not empty, send it.
	if message:

		# Count number of bytes and prepare header of fixed size.
		message_header = f"{len(message):<{HEADER_LENGTH}}"

		# Send encrypted header and message to server.
		client_socket.send(encrypt_message(message_header + message))

	try:
		# Loop over received messages (May be more than one) and print them:
		while True:

			# Receive the packet.
			enc_packet = client_socket.recv(2048)

			# If server gracefully closed a connection:
			if not len(enc_packet):
				print('Connection closed by the server')
				sys.exit()

			# Decrypt the packet.
			packet = cipher.decrypt(b64decode(enc_packet))

			# Extract te username.
			user_header = packet[0:HEADER_LENGTH]
			user_length = int(user_header.decode('utf-8').strip())
			user_idx = HEADER_LENGTH
			username = packet[user_idx:user_idx+user_length].decode('utf-8')

			# Extract te message.
			msg_header_idx = user_idx+user_length
			msg_header = packet[msg_header_idx:HEADER_LENGTH+msg_header_idx]
			msg_length = int(msg_header.decode('utf-8').strip())
			msg_idx = msg_header_idx+HEADER_LENGTH
			message = packet[msg_idx:msg_idx+msg_length].decode('utf-8')

			# Print message
			print(f'{username} > {message}')

	except IOError as e:
		# This is normal on non blocking connections - when there are no 
		# incoming data error is going to be raised.
		# Some operating systems will indicate that using AGAIN, and some 
		# using WOULDBLOCK error code.
		# We are going to check for both - if one of them - that's expected, 
		# means no incoming data, continue as normal.
		# If we got different error code - something happened.
		if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
			print('Reading error: {}'.format(str(e)))
			sys.exit()

		# We just did not receive anything
		continue

	except Exception as e:
		# Any other exception - something happened, exit
		print('Reading error: '.format(str(e)))
		sys.exit()
