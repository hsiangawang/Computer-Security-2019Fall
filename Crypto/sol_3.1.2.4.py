import sys

if __name__ == '__main__':
    
    ciphertext_file_name = sys.argv[1]
    key_file_name = sys.argv[2]
    modulo_file_name = sys.argv[3]
    output_file_name = sys.argv[4]

    with open(key_file_name) as pk_file:
        d = int(pk_file.read().strip(), 16)
    with open(modulo_file_name) as m_file:
        N = int(m_file.read().strip(), 16)
    with open(ciphertext_file_name) as cipher_file:
        c = int(cipher_file.read().strip(), 16)
    
    x = pow(c,d,N)
    with open(output_file_name, 'w') as output_file:
        output_file.write(hex(x)[2:-1])