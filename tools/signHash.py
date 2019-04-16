#!/usr/bin/env python3

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct

def apduPrefix():
    # https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
    CLA = bytes.fromhex("E0")
    INS = b"\x04"
    P1 = b"\x00"
    P2 = b"\x00"
    return CLA + INS + P1 + P2

def main(args):
    indexBytes = struct.pack("<I", args.index)

    sig = args.signature
    if len(sig) > 64:
        sig = sig[:64]
    sigBytes = bytes(sig, "utf-8")

    prefix = apduPrefix()
    payload = indexBytes + sigBytes
    L_c = bytes([len(payload)])
    apdu = prefix + L_c + payload

    dongle = getDongle(True)
    result = dongle.exchange(apdu)

    print("Response: " + result[0:72].hex())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--signature', '-s', type=str, required=True)
    parser.add_argument('--index', '-i', type=int, required=True)
    args = parser.parse_args()
    main(args)
