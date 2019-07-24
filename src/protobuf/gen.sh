# This script generates protobuf headers for txn.proto and copies
# it to the parent directory. It makes use of nanopb and hence
# requires it to be in path. You can download a binary release
# of nanopb here: https://jpa.kapsi.fi/nanopb/download/nanopb-0.3.9.3-linux-x86.tar.gz
# Note: Do not use the above downloaded nanopb runtime code in the
# app. This script only uses the generated txn.pb.h and txn.pb.c.
# Other files such as pb.h, pb_common.(h/), pb_(en/de)code.(c/h)
# are to be used from https://github.com/LedgerHQ/ledger-nanopb.

# Set this to the downloaded nanopb path (absolute path only).
NANOPB_PATH=""

if [[ $NANOPB_PATH = "" ]]
then
    echo "Error: NANOPB_PATH not set in script"
    exit 1
fi
    
# Compile the protobuf description
protoc -otxn.pb txn.proto

# Generate C sources and headers.
${NANOPB_PATH}/generator-bin/protoc --nanopb_out=. txn.proto
# python ${NANOPB_PATH}/generator/nanopb_generator.py txn.pb

# Move the files to our app source.
mv txn.pb.c txn.pb.h ../
rm txn.pb
