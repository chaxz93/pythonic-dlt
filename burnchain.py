from cryptography.hazmat.backends import default_backend                        #RSA Signatures with default backend
from cryptography.hazmat.primitives.asymmetric import rsa                       #Generates new RSA private key with provided backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_keys():
    priv_key = rsa.generate_private_key(                                        #RSA keys have complex internal structure with specific mathematical properties.
                                        public_exponent=65537,                  #65537 is the smallest public_exponent known to prevent Coppersmith's Attack for short unpadded messages, providing efficient signature verification
                                        key_size=4096,                          #key_size of 4096 bits provide most security
                                        backend=default_backend()               #implements RSABackend.
                                       )
    pub_key = priv_key.public_key()
    return priv_key, pub_key

def generate_signature(message, private_key):
    digital_signature = private_key.sign(
                                message,
                                padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH  #PSS is the recommended pseudorandom salt for padding new protocols
                                            ),
                                hashes.SHA256()                                 #RSA signatures require SHA256 hash
                                )
    return digital_signature

def verify(unsigned_msg, signed_msg, pub_key):
    return False

#runs tests for test-driven-development (TDD)

if __name__ == '__main__':
    privateTestKey, publicTestKey = generate_keys()
    print(privateTestKey)
    print(publicTestKey)
    originalMessage = b"Aguero is actually not blonde"
    digitalSignature = generate_signature(originalMessage, privateTestKey)
    print(digitalSignature)
    passedCorrectnessCheck = verify(originalMessage, digitalSignature, publicTestKey)
    if passedCorrectnessCheck:
        print("Digital Signature Valid!")
    else:
        print("Warning! Invalid Signature Detected!")

    print ("Python3 Detected!")
