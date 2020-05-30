import sys
import urllib2
from binascii import hexlify

def reverse(s): 
  str = "" 
  for i in s: 
    str = i + str
  return str

def get_status(u):
    req = urllib2.Request(u)
    try:
        f = urllib2.urlopen(req)
        return f.code
    except urllib2.HTTPError, e:
        return e.code

def pad(msg):
    n = len(msg) % 16
    return msg + ''.join(chr(i) for i in range(16, n, -1))

if __name__ == '__main__':
    
    cipher_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(cipher_file) as f1:
        cipher = f1.read().strip()

    blocks = []
    blocks_num = len(cipher)/32

    for i in range(blocks_num):
        blocks.append(cipher[i*32:i*32+32])
    print blocks
    #modified_block = blocks

    total_plaintext = ''
    #print "len(blocks): " 
    #print len(blocks)

    for b in range(1,len(blocks)):
        print "b: "
        print b
        prev_b = blocks[b-1]
        cur_b = blocks[b]
        print prev_b
        print cur_b
        prev_b_split = []
        cur_b_split = []
        for i in range(0,len(prev_b),2):
            prev_b_split.append(prev_b[i:i+2])
            cur_b_split.append(cur_b[i:i+2])
        print prev_b_split
        print cur_b_split

        plaintext = ''
        correct_text = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        prev_b_split_copy = []
        for i in range(len(prev_b_split)):
            prev_b_split_copy.append(prev_b_split[i])
        cur_b_str = ''.join(cur_b_split)

        for i in range(15,-1,-1):
            cipherbyte_modified = prev_b_split[i]
            #print 'cipherbyte_modified: ' + cipherbyte_modified

            for guess in range(256):
                prev_b_split[i] = hex(guess ^ 16 ^ int(cipherbyte_modified,16))[2:].zfill(2)
                #print prev_b_split
                prev_b_str = ''.join(prev_b_split)
                #modified_block[blocks_num-2] = prev_b_str
                #cipher_prime = ''.join(modified_block)
                attack_url = 'http://cs461-mp3.sprai.org:8081/mp3/chw6/?'+prev_b_str+cur_b_str
                #print attack_url
                status = get_status(attack_url)
                if status == 404:
                    print "get!"
                    print guess
                    print chr(guess)
                    correct_text [i] = guess
                    print correct_text
                    plaintext += chr(guess)
                    #ready to update new fake cipher
                
                    for k in range(16-i):
                    #print correct_text[15-k]
                    #print int(prev_b_split_copy[15-k],16)
                        IntVal = (correct_text[15-k] ^ int(prev_b_split_copy[15-k],16))
                    #print IntVal
                    #print i+k
                        prev_b_split[15-k] = hex(IntVal ^ (i+k))[2:].zfill(2)
                        test = int(prev_b_split[15-k],16) ^ IntVal
                        #print "test" 
                        #print test
                    break
                
                
                

        print 'plaintext: ' + reverse(plaintext)
        total_plaintext += reverse(plaintext)

print total_plaintext


"""
    prev_b = blocks[blocks_num-2]
    cur_b = blocks[blocks_num-1]
    print "prev_b: " + prev_b
    prev_b_split = []
    cur_b_split = []
    for i in range(0,len(prev_b),2):
        prev_b_split.append(prev_b[i:i+2])
        cur_b_split.append(cur_b[i:i+2])
    #print prev_b_split

    plaintext = ''
    correct_text = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    prev_b_split_copy = []
    for i in range(len(prev_b_split)):
        prev_b_split_copy.append(prev_b_split[i])
    cur_b_str = ''.join(cur_b_split)

    for i in range(15,-1,-1):
        cipherbyte_modified = prev_b_split[i]
        print 'cipherbyte_modified: ' + cipherbyte_modified

        for guess in range(256):
            prev_b_split[i] = hex(guess ^ 16 ^ int(cipherbyte_modified,16))[2:].zfill(2)
            #print prev_b_split
            prev_b_str = ''.join(prev_b_split)
            modified_block[blocks_num-2] = prev_b_str
            cipher_prime = ''.join(modified_block)
            attack_url = 'http://cs461-mp3.sprai.org:8081/mp3/chw6/?'+prev_b_str+cur_b_str
            #print attack_url
            status = get_status(attack_url)
            if status == 404:
                print "get!"
                print guess
                print chr(guess)
                correct_text [i] = guess
                print correct_text
                plaintext += chr(guess)
                #ready to update new fake cipher
                
                for k in range(16-i):
                    #print correct_text[15-k]
                    #print int(prev_b_split_copy[15-k],16)
                    IntVal = (correct_text[15-k] ^ int(prev_b_split_copy[15-k],16))
                    #print IntVal
                    #print i+k
                    prev_b_split[15-k] = hex(IntVal ^ (i+k))[2:].zfill(2)
                    test = int(prev_b_split[15-k],16) ^ IntVal
                    print "test" 
                    print test
                
                #print guess
                #print int(cipherbyte_modified,16)
                #print i
                #IntVal = (guess ^ int(cipherbyte_modified,16))
                #prev_b_split[i] = hex(IntVal ^ i)[2:].zfill(2)
                #print IntVal
                #test = int(prev_b_split[i],16) ^ IntVal
                #print "test" 
                #print test
                break

    print 'plaintext: ' + reverse(plaintext)
"""

    
   