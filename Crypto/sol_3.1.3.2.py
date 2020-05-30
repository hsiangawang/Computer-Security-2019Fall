import sys

def WHA(inStr):
    mask = 0x3FFFFFFF 
    outHash = 0
    for c in inStr:
        byte = ord(c)
        intermediate_value = ((byte ^ 0xCC) << 24) | ((byte ^ 0x33) << 16) | ((byte ^ 0xAA) << 8) | (byte ^ 0x55)
        outHash = (outHash & mask) + (intermediate_value & mask) 

    return outHash
	

if __name__ == '__main__':

	input_file = sys.argv[1]
	output_file = sys.argv[2]

	with open(input_file) as f1:
		inStr = f1.read().strip()
		encode = 0
		encode = WHA(inStr)
		encode = hex(encode)
		
	f = open(output_file, 'w')
	f.write(encode)
		
#0x2370e2c5

