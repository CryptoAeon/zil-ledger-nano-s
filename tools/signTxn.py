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
    INS = b"\x08"
    P1 = b"\x00"
    P2 = b"\x00"

    return CLA + INS + P1 + P2


def main(args):
    indexBytes = struct.pack("<I", args.index)

    txnBytes = bytearray.fromhex(EncodedTxn)
    txnSizeBytes = struct.pack("<I", len(txnBytes))

    prefix = apduPrefix()
    payload = indexBytes + txnSizeBytes + txnBytes
    L_c = bytes([len(payload)])
    apdu = prefix + L_c + payload

    dongle = getDongle(True)
    result = dongle.exchange(apdu)
    print("Response: " + result[0:72].hex())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #parser.add_argument('--txnJson', '-j', type=str, required=False)
    parser.add_argument('--index', '-i', type=int, required=True)
    args = parser.parse_args()
    main(args)
