numberOfParty=$1
start=0
end=($1-1)
if [ $# -gt 1 ]
        then
                start=$2
                end=$3
fi

for id in $(seq 0 $((numberOfParty - 1)))
do

        (sleep $id && (echo $id) && (./online.out $id 0 $numberOfParty) && (echo "$id exits")) &
done
