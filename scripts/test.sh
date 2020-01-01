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

# Tests ArgxFindExecutable()
function test_findexe {
    echo -n "$1... "

    testexe=$(realpath $2.exe)

    # We don't do anything if there's already a path
    test0=$($testexe "C:\\foo\\bar\\baz")
    if [[ "$test0" != "C:\\foo\\bar\\baz" ]]; then
	echo "failed (0)"
	result=1
	return 1
    fi

    # 1. Directory from which the application was loaded
    loadpath=$(dirname $testexe | cygpath -w -f-)
    test1=$($testexe argxruna)
    if [[ "$test1" != "$loadpath\\argxruna.exe" ]]; then
	echo "failed (1)"
	result=1
	return 1
    fi

    # 2. Current directory
    pushd $work_dir > /dev/null
    touch frob.exe
    cygwork=$(realpath "$work_dir" | cygpath -w -f-)
    test2=$($testexe frob)
    popd > /dev/null
    if [[ "$test2" != "$cygwork\\frob.exe" ]]; then
	echo "failed (2)"
	result=1
	return 1
    fi

    # 3. The system directory
    test3=$($testexe subst)
    if [[ "$test3" != "C:\\WINDOWS\\system32\\subst.exe" ]]; then
	echo "failed (3)"
	result=1
	return 1
    fi

    # We skip the 16-bit Windows directory because it's empty on 64-bit installs

    # 5. The Windows directory
    test4=$($testexe winhlp32)
    if [[ "$test4" != "C:\\WINDOWS\\winhlp32.exe" ]]; then
	echo "failed (5)"
	result=1
	return 1
    fi

    # 6. Things in PATH (assumes Git is installed))
    test5=$($testexe bash)
    if [[ "$test5" != "C:\\Program Files\\Git\\usr\bin\\bash.exe" ]]; then
	echo "failed (6)"
	result=1
	return 1
    fi

    echo "ok"
}

# Tests ArgXIsSupportedByExecutable()
function test_supported {
    echo -n "$1... "

    testexe=$(realpath $2.exe)

    if ! $testexe build/x86/argxruna.exe | grep "does not support ArgX" > /dev/null; then
	echo "failed (1)"
	result=1
	return 1
    fi

    if ! $testexe build/x86/argxtesta.exe | grep "supports ArgX" > /dev/null; then
	echo "failed (2)"
	result=1
	return 1
    fi

    if ! $testexe build/x64/argxruna.exe | grep "does not support ArgX" > /dev/null; then
	echo "failed (3)"
	result=1
	return 1
    fi

    if ! $testexe build/x64/argxtesta.exe | grep "supports ArgX" > /dev/null; then
	echo "failed (4)"
	result=1
	return 1
    fi

    echo "ok"
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

echo
echo "* Check ArgxFindExecutable works"
echo
test_findexe "32-bit Unicode" build/x86/argxwhichw
test_findexe "32-bit ANSI" build/x86/argxwhicha
test_findexe "64-bit Unicode" build/x64/argxwhichw
test_findexe "64-bit ANSI" build/x64/argxwhicha

echo
echo "* Check ArgxIsSupportedByExecutable works"
echo
test_supported "32-bit Unicode" build/x86/argxsupportedw
test_supported "32-bit ANSI" build/x86/argxsupporteda
test_supported "64-bit Unicode" build/x64/argxsupportedw
test_supported "64-bit ANSI" build/x64/argxsupporteda

exit $result
