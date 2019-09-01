#!/usr/bin/python

import sys
import decimal

# https://stackoverflow.com/a/44702621/2128804
def floatToString(inputValue, shift):
    formatter = '{0:.' + shift + 'f}'
    return formatter.format(inputValue).rstrip('0').rstrip('.')

if len(sys.argv) == 2:
    qa = decimal.Decimal(sys.argv[1])
    shift = str(12)
elif len(sys.argv) == 4 and sys.argv[1] == "-shift":
    qa = decimal.Decimal(sys.argv[3])
    shift = sys.argv[2]
else:
    print 'Usage: verifier.py [-shift=12] Qa (length of Qa < 30 digits)'
    sys.exit(1)

shift_0s = pow(10, int(shift))
zil = (qa / decimal.Decimal(shift_0s))
print floatToString(zil, shift)
