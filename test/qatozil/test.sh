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

shifti=2
i=0
while [[ $i -le 10001 ]]
do
    qatozil=`./qatozil -shift $shifti $i`
    verifier=`./verifier.py -shift $shifti $i`
    echo -n "Testing \"qatozil -shift $shifti $i\" "
    if [[ $qatozil != $verifier ]]
    then
        echo "failed: $qatozil received vs $verifier expected"
        exit 1
    else
        echo "success"
    fi
    i=$(($i+1))
done

echo "All tests completed successfully"
