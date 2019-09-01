#!/usr/bin/python

import sys
import decimal

# https://stackoverflow.com/a/44702621/2128804
def floatToString(inputValue):
    return '{0:.12f}'.format(inputValue).rstrip('0').rstrip('.')

if len(sys.argv) != 2:
    print 'Usage: verifier.py Qa [length of Qa < 30 digits]'
    sys.exit(1)

qa = decimal.Decimal(sys.argv[1])
zil = (qa / decimal.Decimal(1000000000000))
print floatToString(zil)
