from cryptography.hazmat.backends import default_backend                        #RSA Signatures with default backend
from cryptography.hazmat.primitives.asymmetric import rsa                       #Generates new RSA private key with provided backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

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
                                        padding.PSS(                            #PSS is the recommended pseudorandom salt for padding new protocols
                                                    mgf=padding.MGF1(hashes.SHA256()),
                                                    salt_length=padding.PSS.MAX_LENGTH
                                                    ),
                                        hashes.SHA256()                         #RSA signatures require SHA256 hash
                                        )
    return digital_signature

#If the signature does not match, verify() will raise an InvalidSignature exception.

#using the public key, original message, digital signature, and signing algorithm
#we can verify the non-repudiation of the private key used to sign

def verifiable_signtaure(message, signature, public_key):
    try:
        public_key.verify(
                         signature,
                         message,
                         padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                    ),
                         hashes.SHA256()
                         )
        return True
    except InvalidSignature:
        return False
    except:
        print("Signature Verification Failed!")
        return False

#runs tests for test-driven-development (TDD)

if __name__ == '__main__':
    privateTestKey, publicTestKey = generate_keys()
    print(privateTestKey)
    print(publicTestKey)
    originalMessage = b"Aguero is actually not blonde"
    digitalSignature = generate_signature(originalMessage, privateTestKey)
    print(digitalSignature)
    passedCorrectnessCheck = verifiable_signtaure(originalMessage, digitalSignature, publicTestKey)
    if passedCorrectnessCheck:
        print("Digital Signature Valid!")
    else:
        print("Warning! Invalid Signature Detected!")

    print ("Python3 Detected!")
    hackerPrivateKey, hackerPublicKey = generate_keys()
    forged_signature = generate_signature(originalMessage, hackerPrivateKey)
            b = "mystring".encode('utf-8')
            message += b
