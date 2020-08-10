#! /bin/sh

verbose_output=0

make
if [ $? -ne 0 ]
then
    echo "Make build failed. Terminating script"
    exit 1
fi

while getopts v option
do
case ${option} in
v )
    verbose_output=1
;;
esac
done

if [ $verbose_output -eq 0 ]
then
    exec 2>/dev/null
fi

./badssl
./socket_api_tests



echo "Completed all tests."
