inputs=(
    1
    0
    00011
    1122110000000
    00000655546555666665555666
    111111111111
    1111111111111
    146545665456654565456
)

for item in ${inputs[*]}
do
    qatozil=`./qatozil $item`
    verifier=`./verifier.py $item`
    if [[ $qatozil != $verifier ]]
    then
        echo "Testing $item failed: $qatozil received vs $verifier expected"
        exit 1
    fi
done

echo "All tests completed successfully"
