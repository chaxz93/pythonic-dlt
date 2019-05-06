#RSA Signatures

def generate_keys():
    priv_key = 'aksjdlmqwaepqooew9ios30qpowadsw'
    pub_key = 'w9023qeujwd93oqlwqwd[qea;d]'
    return priv_key, pub_key

def digitally_sign(message, priv_key):
    digital_sig = '7y<dahsniew'
    return digital_sig

def verify(unsigned_msg, signed_msg, pub_key):
    return False

#runs tests for test-driven-development (TDD)

if __name__ == '__main__':
    privateTestKey, publicTestKey = generate_keys()
    originalMessage = b"Aguero is actually not blonde"
    signedMessage = digitally_sign(originalMessage, privateTestKey)
    passedCorrectnessCheck = verify(originalMessage, signedMessage, publicTestKey)
    if passedCorrectnessCheck:
        print("Digital Signature Valid!")
    else:
        print("Warning! Corrupt Signature Detected!")

    print ("Python3 Detected!")
