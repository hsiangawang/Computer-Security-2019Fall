import sys

if __name__ == '__main__':
	
	ciphertext_file = sys.argv[1]
	key_file = sys.argv[2]
	output_file = sys.argv[3]

	with open(sys.argv[2]) as key_file:
		line = key_file.read().strip()
        decode_dict = {c: chr(ord('A') + i) for i, c in enumerate(line)}
	with open(ciphertext_file) as cipher_file: 
		line = cipher_file.read().strip()
		char_list = []
        for c in line:
            if c.isupper(): 
            	char_list.append(decode_dict[c])
            else: 
            	char_list.append(c)
        decoded = ''.join(char_list) 		
        f = open(output_file, 'w')
        f.write(decoded)



