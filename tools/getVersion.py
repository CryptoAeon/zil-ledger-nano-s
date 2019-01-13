#!/usr/bin/env python3

from ledgerblue.comm import getDongle

def apduPrefix():
    # https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
    CLA = bytes.fromhex("E0")
    INS = b"\x01"
    P1 = b"\x00"
    P2 = b"\x00"
    return CLA + INS + P1 + P2

def exchange(apdu):
    dongle = getDongle(True)
    return dongle.exchange(apdu)

def main():
    apdu = apduPrefix()
    response = exchange(apdu)
    if len(response) != 3:
        raise "Invalid response length: {}".format(len(response))
    print("v{}.{}.{}".format(response[0], response[1], response[2]))

if __name__ == "__main__":
    main()
