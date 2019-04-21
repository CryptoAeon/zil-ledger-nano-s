# Zilliqa Nano S App 
  
Zilliqa wallet application for Nano S.

## Build
`make clean && make DBG=1 load`

The debug variable should be omitted for production builds.

## JavaScript Interface
Located [here](https://github.com/CryptoAeon/zil-ledger-js-interface)

## Node CLI App
Located [here](https://github.com/CryptoAeon/zil-ledger-node-app)

## Python Test Utils

Usage:
`python3 getPublicKey.py --index 0`

`python3 signHash.py --signature 02E681C8EB3602CDB9261F407E2C2EE6CB9BA996AAA895677E133C02BEFC1F8482 --index 0`