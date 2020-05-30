import sys
from Crypto.Cipher import AES

if __name__ == '__main__':
	
	ciphertext_file = sys.argv[1]
	key_file = sys.argv[2]
	iv_file = sys.argv[3]
	output_file = sys.argv[4]

	with open(ciphertext_file) as f1:
		cipher = f1.read().strip().decode('hex')
		decode = ""
    	with open(key_file) as f2:
    		key = f2.read().strip().decode('hex')
    		with open(iv_file) as f3:
    			iv = f3.read().strip().decode('hex')
    			aes = AES.new(key, AES.MODE_CBC, iv)
    			decode = aes.decrypt(cipher)

        f = open(output_file, 'w')
        f.write(decode)

