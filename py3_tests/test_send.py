from ledgerblue.comm import getDongle
from tx_pb2 import Transaction
import struct


input_1 = Transaction.Input(input_tx_hash=bytes.fromhex("ac3c7f1938e9bb4e04f296eb7b1d13758e904dcecf352bc5349eda43c84ebbc6"), input_index=0)
output_0 = Transaction.Output(dest_addr=bytes.fromhex("05c829a6b0ec3df93dac8c07d6b947ee99c4ff103d1b303894"), amount=79798)
message = "https://bit.ly/32hI7ly"

tx = Transaction(inputs=[input_1, input_1, input_1, input_1], outputs=[output_0, output_0, output_0, output_0, output_0], msg=message)

# prefix buffer with its size
request = struct.pack(">H", len(tx.SerializeToString())) + tx.SerializeToString()


dongle = getDongle(debug=True)

apdu = bytes.fromhex("e0020000")
chunkSize = 200

for chunk in [request[i:i + chunkSize] for i in range(0, len(request), chunkSize)]:
    capdu = apdu + struct.pack('B', len(chunk)) + chunk
    response = dongle.exchange(bytes(capdu))
    apdu = apdu[:2] + struct.pack('B', apdu[2] | 0x80) + apdu[3:]