""" base58 encoding / decoding functions """
import unittest
import hashlib
import ctypes
import ctypes.util
import sys
import binascii

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base_count = len(alphabet)


'''
    Example:
        >>> import base58Encoder
        >>> base58Encoder.encodeKeyPairFromSecret('262db3bba012a6defe26888f53b442d67c9c9354dce9f8c32e67833cc9d0eef5','80')
        >>> Encoded base58Checksum SecretKey: 5J76oPfZf3UBD5Hh138Ue74GVkC7yQQSbqGv1UjsJtHbV2jnoq3
            Address: 19bimxJHW8ABuyCMyzmpU4GWiyGwcWtG1a
            
        >>> base58Encoder.decodeSecretKey('5J76oPfZf3UBD5Hh138Ue74GVkC7yQQSbqGv1UjsJtHbV2jnoq3')
            262db3bba012a6defe26888f53b442d67c9c9354dce9f8c32e67833cc9d0eef5
    
    '''





''' ##
        Hashing wrappers
                            ##'''

def doublehash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).hexdigest()

def addressHash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.hexdigest()

''' ##
        Keys Encoding
                        ##'''

''' version defalut is bitcoin encoding prefix '''
def encodeKeyPairFromSecret(secret,version='80', pubkeyVersion = '00'):
    secret_with_version =  binascii.unhexlify(version + secret)
    
    hashed_secret_with_version = doublehash(secret_with_version)
    checksum = (hashed_secret_with_version[:8])
    
    final = encodeHex(version + secret + checksum)
    print 'Encoded base58Checksum Secret Key: ' + final

    '''final = getAddressFromSecret(secret,pubkeyVersion)
    print 'Address: ' + final'''

def decodeSecretKey(secret):
    k =  '%x' % decode(secret)
    version, data, sheck = k[2], k[2:-8], k[-8:]
    
    print 'Version: ' + version
    
    result = data
    print 'secret Key: ' + result
    return result


''' ##
        Generic Encoding
                            ##'''

'''def getAddressFromSecret(secret,version='00'):
    k = KEY()
    k.generate(secret)
    k.set_compressed(False)
    pubkey = k.get_pubkey()
    hash160 = addressHash(pubkey)
    
    with_version = binascii.unhexlify(version + hash160)
    hashed_secret_with_version = doublehash(with_version)
    checksum = (hashed_secret_with_version[:8])
    
    final = encodeHex(version + hash160 + checksum)
    return final'''

def hexToNum(hex):
    result = int('0x' + hex, 16)
    print 'Hex to Num: ' + str(result)
    return result

def encodeHex(hex):
    return encode(hexToNum(hex))

def encode(n):
    """ encodes a number into an base68Checksum """
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(alphabet[r]))
    return ''.join(l)

def decodeHex(hex):
    return decode(hexToNum(hex))

def decode(s):
	""" Decodes the base58-encoded string s into an integer """
	decoded = 0
	multi = 1
	s = s[::-1]
	for char in s:
		decoded += multi * alphabet.index(char)
		multi = multi * base_count
    
	return decoded

''' ##
        Tests
                ##'''

class Base58Tests(unittest.TestCase):
    
    def test_alphabet_length(self):
        self.assertEqual(58, len(alphabet))
    
    def test_encode_10002343_returns_Tgmc(self):
        result = encode(10002343)
        self.assertEqual('Tgmc', result)
    
    def test_decode_Tgmc_returns_10002343(self):
        decoded = decode('Tgmc')
        self.assertEqual(10002343, decoded)
    
    def test_encode_1000_returns_if(self):
        result = encode(1000)
        self.assertEqual('if', result)
    
    def test_decode_if_returns_1000(self):
        decoded = decode('if')
        self.assertEqual(1000, decoded)
    
    def test_encode_zero_returns_empty_string(self):
        self.assertEqual('', encode(0))
    
    def test_encode_negative_number_returns_empty_string(self):
        self.assertEqual('', encode(-100))

if __name__ == '__main__':
    unittest.main()