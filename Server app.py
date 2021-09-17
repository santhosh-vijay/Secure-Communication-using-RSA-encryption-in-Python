from socket import socket, AF_INET, SOCK_STREAM
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from base64 import b64decode
import pickle
import os.path
import os

#IPv4 and TCP Connection
s = socket(AF_INET, SOCK_STREAM)

#Binding IP address and Port number
s.bind(('192.168.112.133', 65434))
print("using", s.getsockname())
s.listen(1)

sock, addr = s.accept()
data = sock.recv(1024)
print("Connection established with", addr)
sock.send(data.upper())

priv_key_path =  '/home/santhoshvijay/python/rsakey.pem'
pub_key_path =  '/home/santhoshvijay/python/rsapub.pem'

if os.path.isfile(pub_key_path):
        if os.path.isfile(priv_key_path):
        #       with open(pub_key_path, 'rt') as file:
                pub = open(pub_key_path, 'rb')
                pubKey = pub.read()
                print("Public and Private key already exists")
                sock.send(pubKey)
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

        #Save PEM key into the file  
        with open(priv_key_path, 'wb') as file:
                file.write(privKey)

        with open(pub_key_path, 'wb') as file:
                file.write(pubKey)

                #Send the public key
        sock.send(pubKey)
        print("Public key generated and sent")

        priv_key = RSA.importKey(privKey)
        pub_key = RSA.importKey(pubKey)

key = sock.recv(2048)
decode_key = key.decode()
print("Public key received")
pub_key_client = RSA.importKey(key)

h = open('rsapub1.pem', 'x')
with open('/home/santhoshvijay/python/rsapub1.pem', 'w') as file:
        file.write(decode_key)


while True:
        my_message = input("Server:")
        if my_message == 'exit':
                encrypt_message = pub_key_client.encrypt(my_message.encode(), 32)
                pickled = pickle.dumps(encrypt_message)
                sock.send(pickled)
                os.remove(
                break
        encrypt_message = pub_key_client.encrypt(my_message.encode(), 32)
        pickled = pickle.dumps(encrypt_message)
        sock.send(pickled)
        recv_message = sock.recv(2048)
        unpickle = pickle.loads(recv_message)
        print(unpickle)
        decrypt_message = priv_key.decrypt(unpickle)
        decoded_message = decrypt_message.decode()
        print("Client:", decoded_message)
        if decoded_message == 'exit':
                break

s.close()

