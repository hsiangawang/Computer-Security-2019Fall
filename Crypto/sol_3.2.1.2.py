import sys
from pymd5 import md5, padding
from urllib import quote

if __name__ == '__main__':
    
    query_file = sys.argv[1]
    command_file = sys.argv[2]
    output_file = sys.argv[3]

    with open(query_file) as f1:
        query = f1.read().strip()
    with open(command_file) as f2:
        command3 = f2.read().strip()
    
    idx1 = query.find('=')
    idx2 = query.find('&')
    token = query[idx1+1:idx2]
    command = query[idx2+1:]

    PadNum = padding(8*8+len(command)*8)

    h = md5(state=token.decode('hex'), count=512)
    h.update(command3)

    Attacked_url = 'token=' + h.hexdigest() + '&' + command + quote(PadNum) + command3

    with open(output_file, 'w') as output_file:
        output_file.write(Attacked_url)
    
    