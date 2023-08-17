import sys

enc = sys.argv[1]
bins = [bin(ord(c)).replace('0b','') for c in enc]
bins = ['0'+b if len(b) < 15 else b for b in bins]
print(bins, [len(b) for b in bins])
print(''.join([chr(int(b[:7],2))+chr(int(b[8:],2)) for b in bins]))

