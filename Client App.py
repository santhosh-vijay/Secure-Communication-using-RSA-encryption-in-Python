from socket import socket, AF_INET, SOCK_STREAM
from Crypto.PublicKey import RSA
import os.path
import os
import pickle

s = socket(AF_INET, SOCK_STREAM)

saddr = ('192.168.112.136', 65432)
s.connect(saddr)


message = 'Connected with the server'
s.send(message.encode())
data = s.recv(4096)
print(data.decode())

key = s.recv(4096)
decode_key = key.decode()
pub_key_server = RSA.importKey(key)

print("Public key received")

f = open('rsapub1.pem', 'x')
with open('/home/santhoshvijay/python/rsapub1.pem', 'w') as file:
	file.write(decode_key)

priv_key_path =  '/home/santhoshvijay/python/rsakey.pem'
pub_key_path =  '/home/santhoshvijay/python/rsapub.pem'
	
if os.path.isfile(pub_key_path):
	if os.path.isfile(priv_key_path):
        #       with open(pub_key_path, 'rt') as file:
		pub = open(pub_key_path, 'rb')
		pubKey = pub.read()
		print("Public and Private key already exists")
		s.send(pubKey)
		print("Existing Public Key is sent")
		priv = open(priv_key_path, 'rb')
		privKey = priv.read()
		
		pub_key = RSA.importKey(pubKey)
		priv_key = RSA.importKey(privKey)

else:
		#Create Pem files
	f = open('rsakey.pem', 'x')
	g = open('rsapub.pem', 'x')

                #Generate and export RSA public/private KEY in PEM format  
	key = RSA.generate(2048)
	privKey = key.exportKey('PEM')
	pubKey =  key.publickey().exportKey('PEM')
	print("Public and Private key generated using RSA and sent")

	priv_key = RSA.importKey(privKey)
	pub_key = RSA.importKey(pubKey)

                #Save PEM key into the file  
	with open(priv_key_path, 'wb') as file:
		file.write(privKey)

	with open(pub_key_path, 'wb') as file:
			file.write(pubKey)
	s.send(pubKey)
	print("Public key generated and sent")

while True:
	print("(Waiting for reply...)")
	recv_message = s.recv(4096)
	unpickle = pickle.loads(recv_message)
	print(unpickle)
	decrypt_message = priv_key.decrypt(unpickle)
	decoded_message = decrypt_message.decode()
	print("Server:", decoded_message)
	if decoded_message == 'exit':
		os.remove('/home/santhoshvijay/python/rsapub1.pem')
		print("Chat terminated by Server!")
		break
	my_message = input("Client:")
	encrypt_message = pub_key_server.encrypt(my_message.encode(), '32')
	pickled = pickle.dumps(encrypt_message)
	s.send(pickled)
	if my_message == 'exit':
		os.remove('/home/santhoshvijay/python/rsapub1.pem')
		print("Chat terminated by Client!")
		break

s.close()
	
		
