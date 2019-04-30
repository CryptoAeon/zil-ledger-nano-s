#!/usr/bin/env python3

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct

def apduPrefix(args):
    # https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
    CLA = bytes.fromhex("E0")
    INS = b"\x02"
    P1 = b"\x00"
    P2 = b"\x01" if args.dispAddr else b"\x00"
    return CLA + INS + P1 + P2


def exchange(apdu):
    dongle = getDongle(True)
    return dongle.exchange(apdu)


def main(args):
    payload = struct.pack("<I", args.index)
    L_c = bytes([len(payload)])
    apdu = apduPrefix(args) + L_c + payload
    response = exchange(apdu)
    pubKey = response[0:65]
    pubAddr = response[65:]
    if args.dispAddr:
        print("Address:", pubAddr.hex())
        print("length: ", len(pubAddr.hex()))
    else:
        print("Public Key:", pubKey.hex())
        print("length: ", len(pubKey.hex()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--index', '-i', type=int, required=True)
    parser.add_argument('--dispAddr', '-a', type=bool, required=False)
    args = parser.parse_args()
    main(args)
