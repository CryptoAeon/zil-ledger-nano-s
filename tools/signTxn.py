#!/usr/bin/env python3

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct

# Generated from Zilliqa-Js library:
# encodeTransactionProto({
#     "version": 65537,
#     "nonce": 13,
#     "toAddr": "8AD0357EBB5515F694DE597EDA6F3F6BDBAD0FD9",
#     "amount": new BN(100),
#     "pubKey": "0205273e54f262f8717a687250591dcfb5755b8ce4e3bd340c7abefd0de1276574",
# "gasPrice": new BN(1000000000),
#                 "gasLimit": Long.fromNumber(1),
# })
EncodedTxn = "08818004100d1a148ad0357ebb5515f694de597eda6f3f6bdbad0fd922230a210205273e54f262f8717a687250591dcfb5755b8ce4e3bd340c7abefd0de12765742a120a100000000000000000000000000000006432120a100000000000000000000000003b9aca003801"

def apduPrefix():
    # https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
    CLA = bytes.fromhex("E0")
    INS = b"\x04"
    P1 = b"\x00"
    P2 = b"\x00"

    return CLA + INS + P1 + P2


def main(args):
    STREAM_LEN = 16 # Stream in batches of STREAM_LEN bytes each.
    indexBytes = struct.pack("<I", args.index)
    txnBytes = bytearray.fromhex(EncodedTxn)

    print("txnBytes: " + txnBytes.hex())
    if len(txnBytes) > STREAM_LEN:
        txn1Bytes = txnBytes[0:STREAM_LEN]
        txnBytes = txnBytes[STREAM_LEN:]
    else:
        txn1Bytes = txnBytes
        txnBytes = bytearray(0)

    txn1SizeBytes = struct.pack("<I", len(txn1Bytes))
    hostBytesLeftBytes = struct.pack("<I", len(txnBytes))

    prefix = apduPrefix()
    # See signTxn.c:handleSignTxn() for sequence details of payload.
    # 1. 4 bytes for indexBytes.
    # 2. 4 bytes for hostBytesLeftBytes.
    # 3. 4 bytes for txn1SizeBytes (number of bytes being sent now).
    # 4. txn1Bytes of actual data.
    payload = indexBytes + hostBytesLeftBytes + txn1SizeBytes + txn1Bytes
    L_c = bytes([len(payload)])
    apdu = prefix + L_c + payload

    dongle = getDongle(True)
    result = dongle.exchange(apdu)

    # Keep streaming data into the device till we run out of it.
    # See signTxn.c:istream_callback() for how this is used.
    # Each time the bytes sent consists of:
    #  1. 4-bytes of hostBytesLeftBytes.
    #  2. 4-bytes of txnNSizeBytes (number of bytes being sent now).
    #  3. txnNBytes of actual data.
    while len(txnBytes) > 0:
        if len(txnBytes) > STREAM_LEN:
            txnNBytes = txnBytes[0:STREAM_LEN]
            txnBytes = txnBytes[STREAM_LEN:]
        else:
            txnNBytes = txnBytes
            txnBytes = bytearray(0)
        hostBytesLeftBytes = struct.pack("<I", len(txnBytes))
        txnNSizeBytes = struct.pack("<I", len(txnNBytes))
        apdu = hostBytesLeftBytes + txnNSizeBytes + txnNBytes
        result = dongle.exchange(apdu)

    print("Response: " + result.hex())
    print("Length: " + str(len(result)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #parser.add_argument('--txnJson', '-j', type=str, required=False)
    parser.add_argument('--index', '-i', type=int, required=True)
    args = parser.parse_args()
    main(args)
