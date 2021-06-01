from re import compile ,S
pattern_pasv = compile(r'PASV(.*?)RETR(.*?)150', S)

str='(PASV)(RETR 1.ZIP)1456'

list=['1234','345']
if '1234' in list:
    print(1)