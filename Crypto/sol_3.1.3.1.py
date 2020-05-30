import sys,hashlib

if __name__ == '__main__':
	
	input_string = sys.argv[1]
	perturbed_string = sys.argv[2]
	output_file = sys.argv[3]
	with open(input_string) as f1:
		input_str = f1.read().strip()
		input_str = hashlib.sha256(input_str).hexdigest()
		n1 = str(bin(int(input_str,16)))
	with open(perturbed_string) as f2:
		perturbed_str = f2.read().strip()
		perturbed_str = hashlib.sha256(perturbed_str).hexdigest()
		n2 = str(bin(int(perturbed_str,16)))

	l = len(n1)
	count = 0
	for i in range(l):
		if(n1[i]!=n2[i]):
			count+=1
	


	f = open(output_file, 'w')
	f.write(hex(count)[2:])

