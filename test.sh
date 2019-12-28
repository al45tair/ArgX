#!/bin/bash
#
#  Test ArgX
#

echo

work_dir=$(mktemp -d)
if [[ ! "$work_dir" || ! -d "$work_dir" ]]; then
    echo "Failed to create temporary directory"
    exit 1
fi

function cleanup {
    rm -rf "$work_dir"
}

trap cleanup EXIT

testndx=1
result=0

function check_logfile {
    logfile=$1
    oifs=$IFS
    IFS=
    tail -n +3 $logfile | while read -r line; do
        arg=$(echo "$line" | cut -d ' ' -f 5-)
	shift
	if [[ "$arg" != "$1" ]]; then
	    return 1
	fi
    done
    return 0
}

function test_not_argx {
    logfile="$work_dir/test$testndx.log"
    let testndx=testndx+1

    echo -n "$1... "
    shift

    "$@" > $logfile 2>&1 || { echo "failed"; cat $logfile; exit 1; }

    line=$(head -1 $logfile)
    if [[ "$line" != "Not using ArgX" ]]; then
	echo "failed"
	cat $logfile
	result=1
	return 1
    fi

    if ! check_logfile $logfile "$@"; then
	echo "failed"
	cat $logfile
	result=1
	return 1
    fi

    echo "ok"
    return 0
}

function test_argx {
    logfile="$work_dir/test$testndx.log"
    let testndx=testndx+1

    echo -n "$1... "
    shift

    "$@" > $logfile 2>&1 || { echo "failed"; cat $logfile; exit 1; }

    line=$(head -1 $logfile)
    if [[ "$line" != "Using ArgX" ]]; then
	echo "failed"
	cat $logfile
	result=1
	return 1
    fi

    if ! check_logfile $logfile "$@"; then
	echo "failed"
	cat $logfile
	result=1
	return 1
    fi

    echo "ok"
    return 0
}

echo "* Check ArgX doesn't trigger when not in use"
echo
test_not_argx "32-bit Unicode" build/x86/argxtestw.exe Foo Bar Baz
test_not_argx "64-bit Unicode" build/x64/argxtestw.exe Foo Bar Baz
test_not_argx "32-bit ANSI" build/x86/argxtesta.exe Foo Bar Baz
test_not_argx "64-bit ANSI" build/x64/argxtesta.exe Foo Bar Baz

echo
echo "* Check 32-bit ArgX"
echo
test_argx "Unicode to Unicode" build/x86/argxrunw build/x86/argxtestw.exe Foo Bar Baz
test_argx "Unicode to ANSI" build/x86/argxrunw build/x86/argxtesta.exe Foo Bar Baz
test_argx "ANSI to Unicode" build/x86/argxruna build/x86/argxtestw.exe Foo Bar Baz
test_argx "ANSI to ANSI" build/x86/argxruna build/x86/argxtesta.exe Foo Bar Baz

echo
echo "* Check 64-bit ArgX"
echo
test_argx "Unicode to Unicode" build/x64/argxrunw build/x64/argxtestw.exe Foo Bar Baz
test_argx "Unicode to ANSI" build/x64/argxrunw build/x64/argxtesta.exe Foo Bar Baz
test_argx "ANSI to Unicode" build/x64/argxruna build/x64/argxtestw.exe Foo Bar Baz
test_argx "ANSI to ANSI" build/x64/argxruna build/x64/argxtesta.exe Foo Bar Baz

echo
echo "* Check 64-bit to 32-bit ArgX"
echo
test_argx "Unicode to Unicode" build/x64/argxrunw build/x86/argxtestw.exe Foo Bar Baz
test_argx "Unicode to ANSI" build/x64/argxrunw build/x86/argxtesta.exe Foo Bar Baz
test_argx "ANSI to Unicode" build/x64/argxruna build/x86/argxtestw.exe Foo Bar Baz
test_argx "ANSI to ANSI" build/x64/argxruna build/x86/argxtesta.exe Foo Bar Baz

echo
echo "* Check 32-bit to 64-bit ArgX"
echo
test_argx "Unicode to Unicode" build/x86/argxrunw build/x64/argxtestw.exe Foo Bar Baz
test_argx "Unicode to ANSI" build/x86/argxrunw build/x64/argxtesta.exe Foo Bar Baz
test_argx "ANSI to Unicode" build/x86/argxruna build/x64/argxtestw.exe Foo Bar Baz
test_argx "ANSI to ANSI" build/x86/argxruna build/x64/argxtesta.exe Foo Bar Baz

exit $result
